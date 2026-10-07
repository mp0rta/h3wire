// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 mp0rta
//! Connection close, stream termination (local abort, peer RESET_STREAM / STOP_SENDING,
//! stream errors) and reclamation of finished request streams.

use super::recv_uni::PeerUni;
use super::{Connection, Role};
use crate::error::{ConnectionError, H3Code, UsageError};
use crate::event::{AbortSource, Action, Event};
use crate::stream::{SendPhase, StreamId};
use crate::varint;
use std::ops::Range;

impl Connection {
    /// The single connection-error path: closes for good and queues the wire effect.
    pub(crate) fn close_with(&mut self, code: H3Code, reason: &'static str) -> ConnectionError {
        if let Some(c) = self.closed {
            return ConnectionError::Closed(c);
        }
        self.actions
            .push_back(Action::CloseConnection { code, reason });
        self.shut(code);
        ConnectionError::Closed(code)
    }

    /// The QUIC connection is gone: closed with `NO_ERROR` and no wire effect. A no-op
    /// once closed, so `Event::Closed` is emitted exactly once overall.
    pub fn transport_closed(&mut self) {
        if self.closed.is_none() {
            self.shut(H3Code::NO_ERROR);
        }
    }

    /// Enter `Closed` for good; `Event::Closed` stands in for every open stream's
    /// terminal event (spec section 2.1).
    fn shut(&mut self, code: H3Code) {
        self.closed = Some(code);
        self.events.push_back(Event::Closed { code });
        self.streams.clear();
        self.peer_uni.clear();
        self.blocks.clear();
        self.block_stream.clear();
    }

    /// `Err(code)` once the connection is closed; checked first by every public method.
    pub(crate) fn check_open(&self) -> Result<(), H3Code> {
        self.closed.map_or(Ok(()), Err)
    }

    /// Local cancellation of both directions of request stream `s`: queues
    /// `ResetStream` / `StopSending` with `code` for the directions still open and emits
    /// [`Event::StreamAborted`] with source `Local`.
    ///
    /// Aborting a stream already reaped is a no-op (this also covers a stream the peer
    /// reset, whatever the code). `Err(UnknownStream)` for a stream that is not a live
    /// request stream; `Err(ForbiddenCode)` for `H3_REQUEST_REJECTED` from a client or on
    /// a request the server already processed; `Err(OutOfRange)` beyond 2^62-1.
    pub fn abort(&mut self, s: StreamId, code: H3Code) -> Result<(), UsageError> {
        self.check_open().map_err(UsageError::Closed)?;
        if code.0 > varint::MAX {
            return Err(UsageError::OutOfRange);
        }
        if self.is_reaped(s) {
            return Ok(());
        }
        let st = self
            .streams
            .get(&s)
            .filter(|_| s.is_request())
            .ok_or(UsageError::UnknownStream)?;
        // RFC 9114 section 4.1.1: never for a processed request; a client never sends it.
        if code == H3Code::REQUEST_REJECTED && (self.role == Role::Client || st.recv.delivered) {
            return Err(UsageError::ForbiddenCode);
        }
        self.abort_stream(s, code, code, AbortSource::Local);
        Ok(())
    }

    /// A stream error detected locally (spec section 4).
    pub(crate) fn stream_error(&mut self, s: StreamId, code: H3Code) {
        self.abort_stream(s, code, code, AbortSource::Local);
    }

    /// The single per-stream abort path (spec section 4).
    ///
    /// `ResetStream { wire }` if our send side is not `Done`; `StopSending { wire }` unless
    /// the receive side is closed (a caller reacting to the peer's FIN or RESET_STREAM sets
    /// `recv.closed` first); queued bytes and in-flight DATA are dropped; both sides end up
    /// closed; `StreamAborted { event }` unless a terminal event was already emitted. Any
    /// unreleased header block stays for the application to `release`.
    pub(crate) fn abort_stream(
        &mut self,
        s: StreamId,
        wire: H3Code,
        event: H3Code,
        source: AbortSource,
    ) {
        let Some(st) = self.streams.get_mut(&s) else {
            return;
        };
        if st.send.phase != SendPhase::Done {
            self.actions.push_back(Action::ResetStream {
                stream: s,
                code: wire,
            });
        }
        if !st.recv.closed {
            self.actions.push_back(Action::StopSending {
                stream: s,
                code: wire,
            });
        }
        st.send.stop();
        st.recv.closed = true;
        if !std::mem::replace(&mut st.terminal_emitted, true) {
            self.events.push_back(Event::StreamAborted {
                stream: s,
                code: event,
                source,
            });
        }
        self.reap(s);
    }

    /// The code for a reset we send in reaction to the peer: `REQUEST_REJECTED` becomes
    /// `REQUEST_CANCELLED` where we may not send it (client always; server once the
    /// request is processed, RFC 9114 section 4.1.1).
    fn local_wire_code(&self, s: StreamId, code: H3Code) -> H3Code {
        let processed = self.streams.get(&s).is_some_and(|st| st.recv.delivered);
        if code == H3Code::REQUEST_REJECTED && (self.role == Role::Client || processed) {
            H3Code::REQUEST_CANCELLED
        } else {
            code
        }
    }

    /// The peer reset its send side of stream `s` (QUIC RESET_STREAM).
    ///
    /// A request stream is aborted ([`Event::StreamAborted`] with source `Peer`, and our
    /// own send side is reset too), even one never seen before. A critical stream closes
    /// the connection (`H3_CLOSED_CRITICAL_STREAM`); other uni streams are forgotten.
    pub fn stream_reset_received(
        &mut self,
        s: StreamId,
        code: H3Code,
    ) -> Result<(), ConnectionError> {
        self.check_open().map_err(ConnectionError::Closed)?;
        match self.peer_uni.get(&s) {
            Some(PeerUni::Control(_) | PeerUni::Encoder(_) | PeerUni::Decoder(_)) => {
                return Err(
                    self.close_with(H3Code::CLOSED_CRITICAL_STREAM, "critical stream reset")
                );
            }
            Some(_) => {
                self.peer_uni.remove(&s);
                return Ok(());
            }
            None => {}
        }
        if !s.is_request() || s.0 > varint::MAX {
            return Ok(());
        }
        // A reset before any byte arrived still opened the stream: our half gets reset too.
        self.first_sight(s);
        if let Some(st) = self.streams.get_mut(&s) {
            // The reset direction is over: no STOP_SENDING for it.
            st.recv.closed = true;
            let wire = self.local_wire_code(s, code);
            self.abort_stream(s, wire, code, AbortSource::Peer);
        }
        Ok(())
    }

    /// The peer asked us to stop sending on stream `s` (QUIC STOP_SENDING).
    ///
    /// On a request stream this ends only our send side: queued bytes are dropped, an
    /// [`Action::ResetStream`] with the peer's code is queued (`H3_REQUEST_REJECTED`
    /// becomes `H3_REQUEST_CANCELLED` where we may not send it) and
    /// [`Event::SendStopped`] is emitted, once, while the send side was still open;
    /// receiving goes on. On one of our critical streams it closes the connection
    /// (`H3_CLOSED_CRITICAL_STREAM`).
    pub fn stop_sending_received(
        &mut self,
        s: StreamId,
        code: H3Code,
    ) -> Result<(), ConnectionError> {
        self.check_open().map_err(ConnectionError::Closed)?;
        if self.local_uni.contains(&Some(s)) {
            return Err(self.close_with(H3Code::CLOSED_CRITICAL_STREAM, "critical stream stopped"));
        }
        self.first_sight(s);
        let wire = self.local_wire_code(s, code);
        let Some(st) = self.streams.get_mut(&s) else {
            return Ok(());
        };
        if st.send.phase == SendPhase::Done {
            return Ok(());
        }
        st.send.stop();
        self.actions.push_back(Action::ResetStream {
            stream: s,
            code: wire,
        });
        self.events
            .push_back(Event::SendStopped { stream: s, code });
        self.reap(s);
        Ok(())
    }

    /// Whether request stream `s` was reaped (its id is never a stream again).
    pub(super) fn is_reaped(&self, s: StreamId) -> bool {
        s.is_request() && contains_id(&self.closed_ids, s.0)
    }

    /// Remove request stream `s` once its send side is `Done`, its receive side closed
    /// and its terminal event emitted. An unreleased header block stays in the
    /// `BlockStore` until `release`.
    pub(super) fn reap(&mut self, s: StreamId) {
        let over = self.streams.get(&s).is_some_and(|st| {
            st.send.phase == SendPhase::Done && st.recv.closed && st.terminal_emitted
        });
        if over && s.is_request() {
            self.streams.remove(&s);
            insert_id(&mut self.closed_ids, s.0);
            self.peak_closed_ranges = self.peak_closed_ranges.max(self.closed_ids.len());
        }
    }
}

/// Add request id `id` (at most `varint::MAX`) to sorted, disjoint `ranges` of ids that
/// step by 4, merging with adjacent ranges. The range count stays bounded by how many
/// streams are open at once, not by how many completed.
fn insert_id(ranges: &mut Vec<Range<u64>>, id: u64) {
    let end = id.saturating_add(4);
    let i = ranges.partition_point(|r| r.start <= id);
    if i > 0 && ranges[i - 1].end > id {
        return;
    }
    let joins_next = ranges.get(i).is_some_and(|r| r.start == end);
    if i > 0 && ranges[i - 1].end == id {
        ranges[i - 1].end = if joins_next {
            ranges.remove(i).end
        } else {
            end
        };
    } else if joins_next {
        ranges[i].start = id;
    } else {
        ranges.insert(i, id..end);
    }
}

fn contains_id(ranges: &[Range<u64>], id: u64) -> bool {
    let i = ranges.partition_point(|r| r.start <= id);
    i > 0 && id < ranges[i - 1].end
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn closed_ids_merge_in_any_order() {
        let mut r = Vec::new();
        for id in [8, 0, 20, 4, 4, 16] {
            insert_id(&mut r, id);
        }
        assert_eq!(r, [0..12, 16..24]);
        insert_id(&mut r, 12);
        assert_eq!((r.len(), &r[0]), (1, &(0..24)));
        assert!(contains_id(&r, 0) && contains_id(&r, 20));
        assert!(!contains_id(&r, 24));
        insert_id(&mut r, varint::MAX - 3);
        assert!(contains_id(&r, varint::MAX - 3));
        assert!(!contains_id(&[], 0));
    }
}
