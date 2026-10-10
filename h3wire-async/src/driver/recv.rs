// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 mp0rta
//! Reading. Peer uni streams (control, QPACK, others) are read eagerly and without limit.
//! Request streams follow the receive tiers (spec §3.2):
//! 1. header discovery reads `discovery_len` until the request / final response HEADERS;
//! 2. speculative read-ahead: `min(read_ahead − queued, C − speculative)`;
//! 3. demand: with an empty queue, a waiting consumer and no reservation, take a
//!    reservation of `D` and read `D`.
//!
//! Whatever a read returns beyond what the core takes (end of discovery, `Recv::Paused`)
//! is `retained` with FIN, and fed again only within a tier's budget. While a stream has
//! retained bytes the transport is not read.

use super::{Driver, dispatch_events};
use crate::client::decode_head;
use crate::quic::{self, ReadError, RecvStream, TransportError};
use crate::state::{Dir, Inner, MIN_CHARGE, charge, own};
use bytes::Bytes;
use h3wire::{H3Code, Recv, Role, StreamId};
use std::task::{Context, Poll, Waker};

#[derive(Clone, Copy, PartialEq, Eq)]
enum Tier {
    Discovery,
    Speculative,
    Demand,
}

impl<C: quic::Connection> Driver<C> {
    /// One read (or one feed of retained bytes) on `id`; on progress the token is
    /// re-queued behind the other streams.
    pub(super) fn read_stream(
        &mut self,
        id: StreamId,
        budget: &mut usize,
    ) -> Result<bool, TransportError> {
        let plan = if id.is_uni() {
            Some((Tier::Discovery, usize::MAX))
        } else {
            self.shared.with(|i| self.plan(i, id))
        };
        let Some((tier, max_len)) = plan else {
            return Ok(false);
        };
        if let Some((raw, fin)) = self.shared.with(|i| i.retained.remove(&id)) {
            *budget = budget.saturating_sub(1);
            let n = raw.len().min(max_len);
            let stop = self.feed(id, &raw.slice(..n), fin && n == raw.len(), tier, max_len);
            let off = stop.unwrap_or(n);
            if stop.is_some() || off < raw.len() {
                self.shared
                    .with(|i| i.retained.insert(id, (raw.slice(off..), fin)));
            }
            let moved = stop != Some(0);
            if moved {
                self.shared.with(|i| i.push_ready(id, Dir::Recv));
            }
            return Ok(moved);
        }
        let Some(r) = self.recvs.get_mut(&id) else {
            return Ok(false);
        };
        // Capped so a paused remainder never exceeds the discovery read size.
        let max_len = if id.is_uni() {
            max_len
        } else {
            max_len.min(self.discovery_len)
        };
        let waker = self.shared.ready_waker(id, Dir::Recv);
        let Poll::Ready(res) = r.poll_read_chunk(&mut Context::from_waker(&waker), max_len) else {
            return Ok(false);
        };
        *budget -= 1;
        self.shared.with(|i| {
            if let Some(st) = i.streams.get_mut(&id) {
                st.seen = true;
            }
        });
        match res {
            Ok(Some(chunk)) => {
                if let Some(off) = self.feed(id, &chunk, false, tier, max_len) {
                    self.shared
                        .with(|i| i.retained.insert(id, (chunk.slice(off..), false)));
                }
                self.shared.with(|i| i.push_ready(id, Dir::Recv));
            }
            Ok(None) => {
                self.recvs.remove(&id);
                if self.feed(id, &Bytes::new(), true, tier, max_len).is_some() {
                    self.shared
                        .with(|i| i.retained.insert(id, (Bytes::new(), true)));
                }
            }
            Err(ReadError::Reset(code)) => {
                self.recvs.remove(&id);
                // An Err is a state notification only.
                let _ = self
                    .shared
                    .with(|i| i.conn.stream_reset_received(id, H3Code(code)));
            }
            Err(ReadError::Closed) => {
                self.recvs.remove(&id);
            }
            Err(ReadError::Transport(e)) => return Err(e),
        }
        Ok(true)
    }

    /// The transport failed. Before the handles fail, feed the core what the transport
    /// still holds on each request stream: a peer may close right after its last bytes
    /// were acknowledged, and quinn still returns them. Each stream is read until a read
    /// would block or fails, without the read-ahead limits: the bytes are in memory
    /// already. Client response heads are decoded on the way (the core drops its blocks
    /// on the close), which also lets the trailers behind them decode.
    pub(super) fn drain_after_loss(&mut self) {
        let mut cx = Context::from_waker(Waker::noop());
        let client = self.role == Role::Client;
        let ids: Vec<StreamId> = self.shared.with(|i| i.streams.keys().copied().collect());
        for id in ids {
            loop {
                if client {
                    self.shared.with(|i| decode_head(i, id));
                }
                let (chunk, fin) = match self.shared.with(|i| i.retained.remove(&id)) {
                    Some(r) => r,
                    None => {
                        let Some(r) = self.recvs.get_mut(&id) else {
                            break;
                        };
                        match r.poll_read_chunk(&mut cx, usize::MAX) {
                            Poll::Ready(Ok(Some(c))) => (c, false),
                            Poll::Ready(Ok(None)) => {
                                self.recvs.remove(&id);
                                (Bytes::new(), true)
                            }
                            Poll::Ready(Err(ReadError::Reset(code))) => {
                                self.recvs.remove(&id);
                                // An Err is a state notification only.
                                let _ = self
                                    .shared
                                    .with(|i| i.conn.stream_reset_received(id, H3Code(code)));
                                break;
                            }
                            // Nothing more held, or the stream is over.
                            _ => break,
                        }
                    }
                };
                if let Some(off) = self.feed(id, &chunk, fin, Tier::Speculative, usize::MAX) {
                    self.shared
                        .with(|i| i.retained.insert(id, (chunk.slice(off..), fin)));
                    if off == 0 {
                        break; // paused on a head nobody can take now
                    }
                }
            }
        }
    }

    /// The tier and `max_len` for the next read of request stream `id`, if any. Starting
    /// a demand read takes the reservation; a stream the cap holds back is recorded.
    fn plan(&self, i: &mut Inner, id: StreamId) -> Option<(Tier, usize)> {
        let cap_room = self.read_ahead_cap.saturating_sub(i.speculative);
        let st = i.streams.get_mut(&id)?;
        if st.discovering {
            return Some((Tier::Discovery, self.discovery_len));
        }
        let r = &mut st.recv;
        if r.eof || r.error.is_some() {
            return None;
        }
        if r.reservation.is_some() && r.queue.is_empty() {
            return Some((Tier::Demand, self.demand_chunk)); // in flight
        }
        // Below `MIN_CHARGE` of room no chunk fits: wait for consumption (or demand).
        let room = self.read_ahead.saturating_sub(r.queued);
        if room.min(cap_room) >= MIN_CHARGE {
            return Some((Tier::Speculative, room.min(cap_room)));
        }
        if r.queue.is_empty() && r.consumer_waiting && r.reservation.is_none() {
            r.reservation = Some(self.demand_chunk);
            return Some((Tier::Demand, self.demand_chunk));
        }
        if room >= MIN_CHARGE {
            i.cap_waiters.insert(id);
        }
        None
    }

    /// Feed `chunk` to the core, dispatching events after each call; body slices are
    /// queued under `tier` ([`own`]), charging at most `budget` in all (body tiers).
    /// `None`: everything (and `fin`) was fed. `Some(off)`: stopped at `off` (paused,
    /// discovery ended, or the budget is spent); the rest belongs in `retained`.
    fn feed(
        &self,
        id: StreamId,
        chunk: &Bytes,
        fin: bool,
        tier: Tier,
        budget: usize,
    ) -> Option<usize> {
        let budget = if tier == Tier::Discovery {
            usize::MAX
        } else {
            budget
        };
        let demand = tier == Tier::Demand;
        self.shared.with(|i| {
            if demand {
                // Counts the bytes this read queues; cleared below if it queued none.
                set_reservation(i, id, Some(0));
            }
            let stop = feed_core(i, id, chunk, fin, tier, budget);
            if demand
                && i.streams
                    .get(&id)
                    .is_some_and(|s| s.recv.reservation == Some(0))
            {
                set_reservation(i, id, None);
            }
            stop
        })
    }
}

fn set_reservation(i: &mut Inner, id: StreamId, r: Option<usize>) {
    if let Some(st) = i.streams.get_mut(&id) {
        st.recv.reservation = r;
    }
}

fn feed_core(
    i: &mut Inner,
    id: StreamId,
    chunk: &Bytes,
    fin: bool,
    tier: Tier,
    mut budget: usize,
) -> Option<usize> {
    let mut off = 0;
    loop {
        let rest = &chunk[off..];
        if rest.is_empty() && !fin {
            return None;
        }
        // A body slice is no longer than the input it came from and charges at least
        // `MIN_CHARGE`: with the input clipped to a budget of at least that, its charge
        // fits.
        if !rest.is_empty() && budget < MIN_CHARGE {
            return Some(off);
        }
        let bytes = &rest[..rest.len().min(budget)];
        let fin = fin && bytes.len() == rest.len();
        // An Err means the core is closed; its CloseConnection is queued.
        let Ok(r) = i.conn.recv(id, bytes, fin) else {
            return None;
        };
        off += match r {
            Recv::Paused => return Some(off),
            Recv::Body { consumed, range } => {
                let b = own(chunk, off + range.start..off + range.end);
                budget = budget.saturating_sub(charge(b.len()));
                i.queue_body(id, b, tier == Tier::Demand);
                consumed
            }
            Recv::Consumed(n) | Recv::Raw { consumed: n, .. } => n,
            Recv::Frame { consumed: n, .. } => n,
        };
        dispatch_events(i);
        if off == chunk.len() {
            return None;
        }
        if tier == Tier::Discovery
            && !id.is_uni()
            && !i.streams.get(&id).is_some_and(|s| s.discovering)
        {
            return Some(off);
        }
    }
}
