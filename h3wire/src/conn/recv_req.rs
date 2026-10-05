//! Receive on request streams (RFC 9114 sections 4.1, 4.4, 7): the frame sequence,
//! header blocks with release backpressure, DATA, extension frames, and message
//! completeness at FIN.

use super::{Connection, Role};
use crate::config::{Config, Contexts};
use crate::error::{ConnectionError, H3Code};
use crate::event::{Event, Recv};
use crate::frame::{
    CANCEL_PUSH, DATA, FrameHeader, GOAWAY, H2_RESERVED, HEADERS, MAX_PUSH_ID, PUSH_PROMISE,
    SETTINGS,
};
use crate::headers::{HeadersKind, ValidateCtx, validate};
use crate::stream::{RecvPhase, RecvState, StreamId, TunnelState};
use crate::varint;

/// Why a call ended without a normal result.
enum Fail {
    Conn(H3Code, &'static str),
    Stream(H3Code),
    /// `may_deliver` rejected the stream (it is closed now), or the stream is gone.
    Discard,
}

impl Connection {
    /// Server: the first sight of a client bidi id (bytes, RESET_STREAM or STOP_SENDING)
    /// creates its stream, unless the id was reaped or is beyond the varint range.
    pub(super) fn first_sight(&mut self, s: StreamId) {
        if self.role == Role::Server && s.is_request() && s.0 <= varint::MAX && !self.is_reaped(s) {
            self.streams.entry(s).or_default();
        }
    }

    /// Server: see `first_sight`. Client: a stream it never opened (or one already
    /// reaped) is ignored.
    pub(super) fn recv_req(
        &mut self,
        s: StreamId,
        bytes: &[u8],
        fin: bool,
    ) -> Result<Recv, ConnectionError> {
        self.first_sight(s);
        if self.streams.get(&s).is_none_or(|st| st.recv.closed) {
            return Ok(Recv::Consumed(bytes.len()));
        }
        let r = match self.recv_frames(s, bytes, fin) {
            Ok(r) => Ok(r),
            Err(Fail::Conn(code, reason)) => Err(self.close_with(code, reason)),
            Err(Fail::Stream(code)) => {
                self.stream_error(s, code);
                Ok(Recv::Consumed(bytes.len()))
            }
            Err(Fail::Discard) => Ok(Recv::Consumed(bytes.len())),
        };
        self.reap(s);
        r
    }

    /// One call returns at most one app-visible item; it stops right after a decoded
    /// HEADERS block so the caller sees `Event::Headers` before what follows.
    fn recv_frames(&mut self, s: StreamId, bytes: &[u8], fin: bool) -> Result<Recv, Fail> {
        let mut pos = 0;
        let out = loop {
            let Some(st) = self.streams.get_mut(&s) else {
                return Err(Fail::Discard);
            };
            let Some((h, left)) = st.recv.cur else {
                if pos == bytes.len() {
                    break None;
                }
                let (n, h) = st.recv.parser.feed(&bytes[pos..]);
                pos += n;
                if let Some(h) = h {
                    check_frame(self.role, &self.config, &st.recv, h)?;
                    st.recv.cur = Some((h, h.len));
                }
                continue;
            };
            // A HEADERS payload waits until the previous block of this stream is released.
            if h.ty == HEADERS && left > 0 && pos < bytes.len() && st.recv.unreleased.is_some() {
                return Ok(if pos > 0 {
                    Recv::Consumed(pos)
                } else {
                    Recv::Paused
                });
            }
            // `take <= bytes.len() - pos`, so the cast is lossless.
            let take = left.min((bytes.len() - pos) as u64) as usize;
            if take == 0 && left > 0 {
                break None;
            }
            let piece = pos..pos + take;
            pos += take;
            let rest = left - take as u64;
            st.recv.cur = (rest > 0).then_some((h, rest));
            match h.ty {
                HEADERS => {
                    st.recv.headers_buf.extend_from_slice(&bytes[piece]);
                    if rest == 0 {
                        self.headers_done(s)?;
                        if pos < bytes.len() {
                            return Ok(Recv::Consumed(pos));
                        }
                    }
                }
                DATA if piece.is_empty() => {}
                DATA => {
                    let r = &mut st.recv;
                    r.data_received += take as u64;
                    if content_length_applies(r)
                        && r.content_length.is_some_and(|cl| r.data_received > cl)
                    {
                        return Err(Fail::Stream(H3Code::MESSAGE_ERROR));
                    }
                    break Some(Recv::Body {
                        consumed: pos,
                        range: piece,
                    });
                }
                ty if delivered_ext(self.role, &self.config, &st.recv, ty) => {
                    if !self.may_deliver(s) {
                        return Err(Fail::Discard);
                    }
                    self.mark_delivered(s);
                    break Some(Recv::Frame {
                        consumed: pos,
                        ty,
                        range: piece,
                        offset: h.len - left,
                        frame_len: h.len,
                    });
                }
                // Unknown or not registered for this context: skipped.
                _ => {}
            }
        };
        // `fin` counts only on a call that consumes all of `bytes`.
        if fin && pos == bytes.len() {
            self.recv_fin(s)?;
        }
        Ok(out.unwrap_or(Recv::Consumed(pos)))
    }

    /// A HEADERS payload is complete: decode, validate, update phases, emit the event.
    fn headers_done(&mut self, s: StreamId) -> Result<(), Fail> {
        let st = self.streams.get_mut(&s).ok_or(Fail::Discard)?;
        let id = self
            .blocks
            .insert_decoded(&st.recv.headers_buf)
            .map_err(|code| Fail::Conn(code, "QPACK field section decoding failed"))?;
        st.recv.headers_buf.clear();
        let ctx = match st.recv.phase {
            RecvPhase::Body | RecvPhase::AfterTrailers => ValidateCtx::Trailers,
            _ if self.role == Role::Server => ValidateCtx::Request {
                connect_protocol_enabled: self.config.enable_connect_protocol,
            },
            _ => ValidateCtx::Response,
        };
        if !self.may_deliver(s) {
            self.blocks.release(id);
            return Err(Fail::Discard);
        }
        // `get` builds `Pseudo` unvalidated: nothing is emitted before `validate` passes.
        let Some(m) = self
            .blocks
            .get(id)
            .ok()
            .and_then(|b| validate(&b, ctx).ok())
        else {
            self.blocks.release(id);
            return Err(Fail::Stream(H3Code::MESSAGE_ERROR));
        };
        let st = self.streams.get_mut(&s).ok_or(Fail::Discard)?;
        match m.kind {
            HeadersKind::Request => {
                st.send.request_is_head = m.method_is_head;
                if m.is_connect {
                    st.recv.tunnel = TunnelState::ConnectPending;
                }
                st.recv.content_length = m.content_length;
                st.recv.phase = RecvPhase::Body;
            }
            HeadersKind::Informational => st.recv.phase = RecvPhase::AfterInformational,
            HeadersKind::Response => {
                let status = m.status.unwrap_or_default();
                st.connect_final((200..300).contains(&status));
                st.recv.content_length = m.content_length;
                st.recv.expects_no_content |= matches!(status, 204 | 304);
                st.recv.phase = RecvPhase::Body;
            }
            // A trailers Content-Length never frames the message.
            HeadersKind::Trailers => st.recv.phase = RecvPhase::AfterTrailers,
        }
        st.recv.unreleased = Some(id);
        self.mark_delivered(s);
        self.block_stream.insert(id, s);
        self.events.push_back(Event::Headers {
            stream: s,
            block: id,
            kind: m.kind,
        });
        Ok(())
    }

    /// FIN at the end of a call that consumed everything (spec section 2.1).
    fn recv_fin(&mut self, s: StreamId) -> Result<(), Fail> {
        let st = self.streams.get_mut(&s).ok_or(Fail::Discard)?;
        if st.recv.cur.is_some() || st.recv.parser.mid_header() {
            return Err(Fail::Conn(H3Code::FRAME_ERROR, "FIN inside a frame"));
        }
        // The peer's direction is over: no STOP_SENDING for it on a stream error.
        st.recv.closed = true;
        let r = &st.recv;
        match r.phase {
            RecvPhase::AwaitHeaders | RecvPhase::AfterInformational => {
                Err(Fail::Stream(match self.role {
                    Role::Server => H3Code::REQUEST_INCOMPLETE,
                    Role::Client => H3Code::MESSAGE_ERROR,
                }))
            }
            _ if content_length_applies(r)
                && r.content_length.is_some_and(|cl| cl != r.data_received) =>
            {
                Err(Fail::Stream(H3Code::MESSAGE_ERROR))
            }
            _ => {
                if !std::mem::replace(&mut st.terminal_emitted, true) {
                    self.events.push_back(Event::Finished(s));
                }
                Ok(())
            }
        }
    }
}

/// Frame-header checks, before any payload byte is consumed.
fn check_frame(role: Role, cfg: &Config, r: &RecvState, h: FrameHeader) -> Result<(), Fail> {
    const UNEXPECTED: Fail = Fail::Conn(
        H3Code::FRAME_UNEXPECTED,
        "frame not allowed on a request stream",
    );
    let tunnel = r.tunnel == TunnelState::Tunnel;
    match h.ty {
        HEADERS if tunnel || r.phase == RecvPhase::AfterTrailers => Err(UNEXPECTED),
        HEADERS if h.len > cfg.max_encoded_field_section_size as u64 => Err(Fail::Conn(
            H3Code::EXCESSIVE_LOAD,
            "HEADERS exceeds max_encoded_field_section_size",
        )),
        DATA if r.phase != RecvPhase::Body => Err(UNEXPECTED),
        // RFC 9114 section 4.1.2: responses to HEAD and 204/304 carry no content.
        DATA if !tunnel && r.expects_no_content && h.len > 0 => {
            Err(Fail::Stream(H3Code::MESSAGE_ERROR))
        }
        HEADERS | DATA => Ok(()),
        PUSH_PROMISE if role == Role::Client => Err(Fail::Conn(
            H3Code::ID_ERROR,
            "PUSH_PROMISE without MAX_PUSH_ID",
        )),
        PUSH_PROMISE | SETTINGS | GOAWAY | MAX_PUSH_ID | CANCEL_PUSH => Err(UNEXPECTED),
        t if H2_RESERVED.contains(&t) => Err(UNEXPECTED),
        // RFC 9114 section 4.4: a known frame not permitted in the tunnel. A registered
        // extension type counts as known.
        t if tunnel && cfg.frames.iter().any(|f| f.ty == t) && !delivered_ext(role, cfg, r, t) => {
            Err(UNEXPECTED)
        }
        _ => Ok(()),
    }
}

/// Registered for the stream's current context: `TUNNEL` in a tunnel, else `REQUEST`
/// (server) or `RESPONSE` (client).
fn delivered_ext(role: Role, cfg: &Config, r: &RecvState, ty: u64) -> bool {
    let ctx = match (r.tunnel, role) {
        (TunnelState::Tunnel, _) => Contexts::TUNNEL,
        (_, Role::Server) => Contexts::REQUEST,
        (_, Role::Client) => Contexts::RESPONSE,
    };
    cfg.frames
        .iter()
        .any(|f| f.ty == ty && f.contexts.contains(ctx))
}

/// Content-Length frames the message (RFC 9114 section 4.1.2): not for a response without
/// content (to HEAD, 204, 304) nor in a tunnel. Received requests are always checked.
fn content_length_applies(r: &RecvState) -> bool {
    r.tunnel != TunnelState::Tunnel && !r.expects_no_content
}
