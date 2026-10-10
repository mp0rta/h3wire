// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 mp0rta
//! Writing (spec §3.3), per stream and in this order:
//! 1. core-owned bytes (HEADERS, trailers, control and QPACK streams): `poll_send`,
//!    copied, then `sent(n)`;
//! 2. DATA: `send_data(len)` for the head of the send queue, then `[prefix, payload]`
//!    with every accepted byte reported through `data_written(n)`. The payload leaves the
//!    queue only once the whole frame is accounted; zero-length payloads are skipped;
//! 3. the end: `send_data(0, true)` (FIN only) or trailers via `send_headers(.., true)`.
//!
//! FIN is written only on `Action::FinishStream`. Fairness: one transport write per
//! stream per turn; a stream that wrote re-queues its `Send` token behind the others, so
//! a bulk body never starves other streams' reads or writes.
//!
//! `poll_stopped` is polled on every send half the driver holds, also after FIN, until
//! it reports STOP_SENDING (`stop_sending_received`) or completion (`acked`).

use super::Driver;
use crate::quic::{self, SendStream, TransportError, WriteError};
use crate::state::{Dir, End, Inner};
use bytes::Bytes;
use h3wire::{H3Code, StreamId, UsageError};
use std::task::{Context, Poll};

/// What one write turn on a stream does.
enum Next {
    /// Write these; `true` for a DATA frame (`data_written`), `false` for core bytes.
    Write(Vec<Bytes>, bool),
    /// Nothing to write; `true` if the core state changed (a FIN-only end or an abort
    /// queued actions).
    Idle(bool),
}

impl<C: quic::Connection> Driver<C> {
    /// One write turn for every stream with core-owned bytes, except those waiting on
    /// the transport. DATA is driven by `Send` tokens.
    pub(super) fn write_sendable(&mut self, budget: &mut usize) -> Result<bool, TransportError> {
        let ids: Vec<StreamId> = self.shared.with(|i| i.conn.sendable().collect());
        let mut moved = false;
        for id in ids {
            if *budget == 0 {
                break;
            }
            if !self.write_blocked.contains(&id) {
                moved |= self.write_stream(id, budget)?;
            }
        }
        Ok(moved)
    }

    /// One write turn on `id`: at most one transport write. On progress the `Send` token
    /// is re-queued, so the rest goes out in later turns.
    pub(super) fn write_stream(
        &mut self,
        id: StreamId,
        budget: &mut usize,
    ) -> Result<bool, TransportError> {
        if *budget == 0 || !self.sends.contains_key(&id) {
            return Ok(false);
        }
        let frame = self.frames.remove(&id);
        let (mut bufs, data) = match self.shared.with(|i| next_write(i, id, frame)) {
            Next::Write(bufs, data) => (bufs, data),
            Next::Idle(moved) => return Ok(moved),
        };
        let waker = self.shared.ready_waker(id, Dir::Send);
        let s = self.sends.get_mut(&id).expect("checked above");
        let r = s.poll_write_chunks(&mut Context::from_waker(&waker), &mut bufs);
        let w = match r {
            Poll::Pending => {
                self.write_blocked.insert(id);
                if data {
                    self.frames.insert(id, bufs);
                }
                return Ok(false);
            }
            Poll::Ready(Err(e)) => {
                *budget -= 1;
                self.write_failed(id, e)?;
                return Ok(true);
            }
            Poll::Ready(Ok(w)) => w,
        };
        *budget -= 1;
        if w.bytes == 0 {
            // Breaks the `poll_write_chunks` contract (Ready accepts >= 1 byte): wait for
            // a wake instead of spinning.
            self.write_blocked.insert(id);
            if data {
                self.frames.insert(id, bufs);
            }
            return Ok(false);
        }
        let complete = w.chunks == bufs.len();
        let live = self.shared.with(|i| {
            let r = if data {
                i.conn.data_written(id, w.bytes)
            } else {
                i.conn.sent(id, w.bytes)
            };
            match r {
                Ok(()) => {}
                // The core is closed, or another thread aborted the stream after this
                // write was planned (the core reaped it): the stream's send side is over;
                // its `ResetStream` runs next round. Anything else is an accounting bug.
                Err(UsageError::Closed(_) | UsageError::UnknownStream) => return false,
                Err(e) => {
                    debug_assert!(false, "write accounting: {e:?}");
                    return false;
                }
            }
            if data && complete {
                // The frame is accounted: its payload leaves the queue.
                if let Some(st) = i.streams.get_mut(&id).filter(|s| !s.send.done) {
                    let b = st.send.queue.pop_front().expect("in-flight payload");
                    st.send.queued -= b.len();
                    i.pending_wakers.extend(st.send.waker.take());
                }
            }
            i.push_ready(id, Dir::Send);
            true
        });
        // A dead stream's frame is dropped, never written further.
        if live && data && !complete {
            bufs.drain(..w.chunks);
            self.frames.insert(id, bufs);
        }
        Ok(true)
    }

    /// Learn of a peer STOP_SENDING (or completion) on a send half we hold.
    pub(super) fn poll_stopped(
        &mut self,
        id: StreamId,
        budget: &mut usize,
    ) -> Result<bool, TransportError> {
        let Some(s) = self.sends.get_mut(&id) else {
            return Ok(false);
        };
        let waker = self.shared.ready_waker(id, Dir::Send);
        let Poll::Ready(r) = s.poll_stopped(&mut Context::from_waker(&waker)) else {
            return Ok(false);
        };
        *budget = budget.saturating_sub(1);
        match r? {
            Some(code) => self.stopped(id, code),
            None => {
                self.drop_send(id);
                self.shared.with(|i| {
                    if let Some(st) = i.streams.get_mut(&id) {
                        st.send.acked = true;
                    }
                });
            }
        }
        Ok(true)
    }

    fn write_failed(&mut self, id: StreamId, e: WriteError) -> Result<(), TransportError> {
        match e {
            WriteError::Stopped(code) => self.stopped(id, code),
            WriteError::Transport(e) => return Err(e),
            WriteError::Closed => self.drop_send(id),
        }
        Ok(())
    }

    /// The peer sent STOP_SENDING: the core resets our half (`Action::ResetStream` drops
    /// it), or closes the connection for a critical stream. A half that already finished
    /// gets no reset: drop it here.
    fn stopped(&mut self, id: StreamId, code: u64) {
        let _ = self
            .shared
            .with(|i| i.conn.stop_sending_received(id, H3Code(code)));
        if self.finished.contains(&id) {
            self.drop_send(id);
        }
    }

    /// Forget the send half of `id`.
    pub(super) fn drop_send(&mut self, id: StreamId) {
        self.sends.remove(&id);
        self.frames.remove(&id);
        self.write_blocked.remove(&id);
        self.finished.remove(&id);
    }
}

/// Plan one write turn on `id` under the lock; `frame` is the DATA frame in flight.
fn next_write(i: &mut Inner, id: StreamId, frame: Option<Vec<Bytes>>) -> Next {
    // A frame of a send side that ended since is dropped.
    if let Some(f) = frame.filter(|_| i.streams.get(&id).is_some_and(|s| !s.send.done)) {
        return Next::Write(f, true);
    }
    let mut moved = false;
    loop {
        if let Some(b) = i.conn.poll_send(id) {
            return Next::Write(vec![Bytes::copy_from_slice(b)], false);
        }
        // Uni streams have no `StreamState`: core bytes only.
        let Some(st) = i.streams.get_mut(&id).filter(|s| !s.send.done) else {
            return Next::Idle(moved);
        };
        let q = &mut st.send;
        while q.queue.front().is_some_and(Bytes::is_empty) {
            q.queue.pop_front();
        }
        let r = if let Some(b) = q.queue.front() {
            match i.conn.send_data(id, b.len() as u64, false) {
                Ok(f) => {
                    let prefix = Bytes::copy_from_slice(f.prefix());
                    return Next::Write(vec![prefix, b.clone()], true);
                }
                Err(e) => Err(e),
            }
        } else {
            match q.end.take() {
                None => return Next::Idle(moved),
                Some(End::Fin) => i.conn.send_data(id, 0, true).map(drop),
                Some(End::Trailers(f)) => i.conn.send_headers(id, &f.as_refs(), true),
            }
        };
        moved = true;
        match r {
            // FIN only: `FinishStream` is queued. Trailers: their HEADERS are core bytes.
            Ok(()) => {}
            Err(UsageError::Closed(_)) => return Next::Idle(true),
            // The core refused what the body produced (e.g. invalid trailers, DATA on a
            // no-content response): a body error.
            // (`Blocked` cannot happen: core bytes were drained above.)
            Err(_) => {
                i.abort_local(id, H3Code::INTERNAL_ERROR);
                return Next::Idle(true);
            }
        }
    }
}
