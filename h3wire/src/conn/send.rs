//! Per-stream send path: uni stream binding, the core-owned byte queues, HEADERS,
//! scatter/gather DATA, and the send phases ending in exactly one FIN.

use super::{Connection, Role};
use crate::error::UsageError;
use crate::event::{Action, DataFrame};
use crate::frame::{HEADERS, data_prefix, encode_header, grease_frame_type};
use crate::headers::{FieldRef, HeadersKind, ValidateCtx, validate_outgoing};
use crate::qpack::encoder::encode_field_section;
use crate::settings::encode_local;
use crate::stream::{InFlight, SendPhase, SendState, Stream, StreamId, TunnelState, UniKind};
use crate::varint;

impl Connection {
    /// Bind a stream opened for `Action::OpenUni(kind)`; queues its stream type
    /// (and, for the control stream, SETTINGS plus an optional GREASE frame).
    pub fn bind_uni(&mut self, kind: UniKind, stream: StreamId) -> Result<(), UsageError> {
        self.check_open().map_err(UsageError::Closed)?;
        if !stream.is_uni() || !self.is_local(stream) {
            return Err(UsageError::WrongStreamKind);
        }
        if self.local_uni[kind as usize].is_some() || self.streams.contains_key(&stream) {
            return Err(UsageError::WrongPhase);
        }
        let ty = match kind {
            UniKind::Control => 0x00,
            UniKind::QpackEncoder => 0x02,
            UniKind::QpackDecoder => 0x03,
        };
        let mut queue = Vec::new();
        varint::encode(ty, &mut queue);
        if kind == UniKind::Control {
            encode_local(&self.config, self.grease_seed, &mut queue);
            self.settings_left = queue.len();
            if self.config.grease {
                encode_header(grease_frame_type(self.grease_seed), 0, &mut queue);
            }
        }
        self.local_uni[kind as usize] = Some(stream);
        let send = SendState {
            queue,
            ..SendState::default()
        };
        self.streams.insert(
            stream,
            Stream {
                send,
                ..Stream::default()
            },
        );
        Ok(())
    }

    /// Streams with core-owned bytes pending and no DATA in flight, ascending id.
    pub fn sendable(&self) -> impl Iterator<Item = StreamId> + '_ {
        let open = self.check_open().is_ok();
        self.streams
            .iter()
            .filter(move |(_, st)| open && !st.send.pending().is_empty())
            .map(|(&id, _)| id)
    }

    pub fn poll_send(&self, s: StreamId) -> Option<&[u8]> {
        self.check_open().ok()?;
        let p = self.streams.get(&s)?.send.pending();
        (!p.is_empty()).then_some(p)
    }

    /// The transport accepted the first `n` bytes of `poll_send(s)`.
    pub fn sent(&mut self, s: StreamId, n: usize) -> Result<(), UsageError> {
        self.check_open().map_err(UsageError::Closed)?;
        let st = self.streams.get_mut(&s).ok_or(UsageError::UnknownStream)?;
        if n > st.send.pending().len() {
            return Err(UsageError::WrongPhase);
        }
        st.send.advance(n);
        if Some(s) == self.local_uni[UniKind::Control as usize] && !self.local_settings_sent {
            self.settings_left = self.settings_left.saturating_sub(n);
            self.local_settings_sent = self.settings_left == 0;
        }
        self.finish_if_drained(s);
        Ok(())
    }

    /// Queue a HEADERS frame: a new request (client), a response (server), or trailers.
    pub fn send_headers(
        &mut self,
        s: StreamId,
        fields: &[FieldRef],
        end: bool,
    ) -> Result<(), UsageError> {
        self.check_open().map_err(UsageError::Closed)?;
        if !s.is_request() || s.0 > varint::MAX || self.is_reaped(s) {
            return Err(UsageError::UnknownStream);
        }
        let role = self.role;
        let st = if role == Role::Client && !self.streams.contains_key(&s) {
            let st = self.new_request(fields)?;
            self.streams.entry(s).or_insert(st)
        } else {
            let st = self.streams.get_mut(&s).ok_or(UsageError::UnknownStream)?;
            st.send.phase = next_phase(role, st, fields, end)?;
            st
        };
        let mut block = Vec::new();
        encode_field_section(fields, &mut block);
        encode_header(HEADERS, block.len() as u64, &mut st.send.queue);
        st.send.queue.extend_from_slice(&block);
        if end {
            st.send.phase = SendPhase::Ending;
        }
        self.finish_if_drained(s);
        Ok(())
    }

    /// Start a DATA frame of `payload_len` bytes; the caller writes `prefix()` then the payload.
    pub fn send_data(
        &mut self,
        s: StreamId,
        payload_len: u64,
        end: bool,
    ) -> Result<DataFrame, UsageError> {
        self.check_open().map_err(UsageError::Closed)?;
        if payload_len > varint::MAX {
            return Err(UsageError::OutOfRange);
        }
        let st = &mut self
            .streams
            .get_mut(&s)
            .ok_or(UsageError::UnknownStream)?
            .send;
        let no_content = st.request_is_head || st.no_content_status;
        match st.phase {
            SendPhase::Tunnel => {}
            SendPhase::Body if payload_len == 0 || !no_content => {}
            _ => return Err(UsageError::WrongPhase),
        }
        if !st.drained() {
            return Err(UsageError::Blocked);
        }
        let frame = if payload_len == 0 && end {
            // FIN only: nothing to write.
            DataFrame {
                bytes: [0; 9],
                len: 0,
            }
        } else {
            let (bytes, len) = data_prefix(payload_len);
            st.in_flight = Some(InFlight {
                frame_len: u64::from(len) + payload_len,
                written: 0,
            });
            DataFrame { bytes, len }
        };
        if end {
            st.phase = SendPhase::Ending;
        }
        self.finish_if_drained(s);
        Ok(frame)
    }

    /// The transport accepted `n` more bytes of the in-flight DATA frame (prefix, then payload).
    pub fn data_written(&mut self, s: StreamId, n: usize) -> Result<(), UsageError> {
        self.check_open().map_err(UsageError::Closed)?;
        let st = &mut self
            .streams
            .get_mut(&s)
            .ok_or(UsageError::UnknownStream)?
            .send;
        let f = st.in_flight.as_mut().ok_or(UsageError::WrongPhase)?;
        let n = n as u64;
        if n > f.frame_len - f.written {
            return Err(UsageError::WrongPhase);
        }
        f.written += n;
        if f.written == f.frame_len {
            st.in_flight = None;
        }
        self.finish_if_drained(s);
        Ok(())
    }

    /// Validate a client's first HEADERS on a fresh request stream.
    fn new_request(&self, fields: &[FieldRef]) -> Result<Stream, UsageError> {
        if !self.may_start_request() {
            return Err(UsageError::GoingAway);
        }
        let enabled = self
            .peer_settings
            .as_ref()
            .is_some_and(|p| p.enable_connect_protocol);
        if !enabled && fields.iter().any(|f| f.name == b":protocol") {
            return Err(UsageError::NotNegotiated);
        }
        let m = validate_outgoing(
            fields,
            ValidateCtx::Request {
                connect_protocol_enabled: enabled,
            },
        )?;
        let mut st = Stream::default();
        st.send.phase = SendPhase::Body;
        st.recv.expects_no_content = m.method_is_head;
        if m.is_connect {
            st.recv.tunnel = TunnelState::ConnectPending;
        }
        Ok(st)
    }

    /// End latch: once an accepted `end` is fully written, request FIN exactly once.
    fn finish_if_drained(&mut self, s: StreamId) {
        let Some(st) = self.streams.get_mut(&s) else {
            return;
        };
        if st.send.phase == SendPhase::Ending && st.send.drained() {
            st.send.phase = SendPhase::Done;
            self.actions.push_back(Action::FinishStream(s));
            self.reap(s);
        }
    }
}

/// Phase after HEADERS on an existing request stream (response or trailers).
fn next_phase(
    role: Role,
    st: &mut Stream,
    fields: &[FieldRef],
    end: bool,
) -> Result<SendPhase, UsageError> {
    match st.send.phase {
        SendPhase::Idle | SendPhase::Headers if role == Role::Server => {
            let m = validate_outgoing(fields, ValidateCtx::Response)?;
            if m.kind == HeadersKind::Informational {
                return if end {
                    Err(UsageError::WrongPhase)
                } else {
                    Ok(SendPhase::Headers)
                };
            }
            st.send.no_content_status = matches!(m.status, Some(204 | 304));
            st.send.phase = SendPhase::Body;
            st.connect_final(m.status.is_some_and(|c| (200..300).contains(&c)));
            Ok(st.send.phase)
        }
        SendPhase::Body if end => {
            validate_outgoing(fields, ValidateCtx::Trailers)?;
            Ok(SendPhase::Trailers)
        }
        _ => Err(UsageError::WrongPhase),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;

    #[test]
    fn local_settings_sent_after_settings_fully_written() {
        let cfg = Config {
            grease: false,
            ..Config::default()
        };
        let mut c = Connection::new(Role::Client, cfg);
        c.bind_uni(UniKind::Control, StreamId(2)).unwrap(); // [0x00, 0x04, 0x00]
        c.sent(StreamId(2), 2).unwrap(); // stops inside SETTINGS
        assert!(!c.local_settings_sent);
        c.sent(StreamId(2), 1).unwrap();
        assert!(c.local_settings_sent);
    }

    fn status(code: &'static [u8]) -> [FieldRef<'static>; 1] {
        [FieldRef::new(b":status", code)]
    }

    /// A server with request stream 0 as Task 12 will create it on receive.
    fn server_with(recv_tunnel: TunnelState, request_is_head: bool) -> Connection {
        let mut c = Connection::new(Role::Server, Config::default());
        let mut st = Stream::default();
        st.recv.tunnel = recv_tunnel;
        st.send.request_is_head = request_is_head;
        c.streams.insert(StreamId(0), st);
        c
    }

    fn drain(c: &mut Connection) {
        let n = c.poll_send(StreamId(0)).map_or(0, <[u8]>::len);
        c.sent(StreamId(0), n).unwrap();
    }

    #[test]
    fn server_response_phases() {
        let s = StreamId(0);
        let mut c = server_with(TunnelState::Regular, false);
        assert_eq!(
            c.send_headers(s, &status(b"103"), true),
            Err(UsageError::WrongPhase)
        );
        c.send_headers(s, &status(b"103"), false).unwrap();
        assert_eq!(c.streams[&s].send.phase, SendPhase::Headers);
        assert_eq!(
            c.send_headers(s, &[FieldRef::new(b":method", b"GET")], false),
            Err(UsageError::InvalidField)
        );
        c.send_headers(s, &status(b"200"), false).unwrap();
        assert_eq!(c.streams[&s].send.phase, SendPhase::Body);
        drain(&mut c);
        c.send_data(s, 0, true).unwrap();
        assert!(c.actions.contains(&Action::FinishStream(s)));
    }

    #[test]
    fn server_no_content_responses() {
        let s = StreamId(0);
        for (code, head) in [(&b"204"[..], false), (b"304", false), (b"200", true)] {
            let mut c = server_with(TunnelState::Regular, head);
            c.send_headers(s, &status(code), false).unwrap();
            drain(&mut c);
            assert_eq!(c.send_data(s, 1, false), Err(UsageError::WrongPhase));
            c.send_headers(s, &[FieldRef::new(b"x-t", b"1")], true)
                .unwrap();
        }
    }

    #[test]
    fn server_connect_2xx_is_tunnel() {
        let s = StreamId(0);
        // 204 to CONNECT is a tunnel and carries DATA.
        for code in [&b"200"[..], b"204"] {
            let mut c = server_with(TunnelState::ConnectPending, false);
            c.send_headers(s, &status(b"100"), false).unwrap();
            c.send_headers(s, &status(code), false).unwrap();
            assert_eq!(c.streams[&s].send.phase, SendPhase::Tunnel);
            assert_eq!(c.streams[&s].recv.tunnel, TunnelState::Tunnel);
            drain(&mut c);
            c.send_data(s, 5, false).unwrap();
            c.data_written(s, 7).unwrap();
            assert_eq!(
                c.send_headers(s, &[FieldRef::new(b"x-t", b"1")], true),
                Err(UsageError::WrongPhase)
            );
        }
        let mut c = server_with(TunnelState::ConnectPending, false);
        c.send_headers(s, &status(b"404"), false).unwrap();
        assert_eq!(c.streams[&s].send.phase, SendPhase::Body);
        // The request body and trailers are a regular message again.
        assert_eq!(c.streams[&s].recv.tunnel, TunnelState::Regular);
    }

    #[test]
    fn client_head_and_connect_set_recv_state() {
        let mut c = Connection::new(Role::Client, Config::default());
        let head = [
            FieldRef::new(b":method", b"HEAD"),
            FieldRef::new(b":scheme", b"https"),
            FieldRef::new(b":authority", b"a"),
            FieldRef::new(b":path", b"/"),
        ];
        c.send_headers(StreamId(0), &head, true).unwrap();
        assert!(c.streams[&StreamId(0)].recv.expects_no_content);
        let connect = [
            FieldRef::new(b":method", b"CONNECT"),
            FieldRef::new(b":authority", b"a:443"),
        ];
        c.send_headers(StreamId(4), &connect, false).unwrap();
        let st = &c.streams[&StreamId(4)];
        assert_eq!(st.recv.tunnel, TunnelState::ConnectPending);
        assert!(!st.recv.expects_no_content);
    }
}
