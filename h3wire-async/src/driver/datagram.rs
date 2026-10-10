// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 mp0rta
//! HTTP datagrams in the driver (spec §3.4): send what the handles queued, drain the
//! transport within the work budget, and route each datagram. Routing never waits on a
//! handle: every queue is bounded and drops its oldest entry.
//!
//! | `parse_datagram` | stream | action |
//! |---|---|---|
//! | `NotYetOpen` / `Drop` | | drop |
//! | `Deliver` | registered | the handle's queue (dropped once the handle is gone) |
//! | `Deliver` | not decided | the pending queue (per-stream and per-connection caps) |
//! | `Deliver` | decided, not registered | abort `H3_DATAGRAM_ERROR` |
//!
//! The decision point is registration, the final response being sent (server) or
//! received (client), or the request ending (its entry is reaped).

use super::Driver;
use crate::builder::Builder;
use crate::error::Error;
use crate::quic::{self, SendDatagramError, TransportError};
use crate::state::Inner;
use bytes::Bytes;
use h3wire::{Datagram, H3Code, StreamId};
use std::collections::VecDeque;
use std::task::{Context, Poll, Waker};

/// Datagram state of one request stream.
#[derive(Debug, Default)]
pub(crate) struct DgramState {
    /// Semantics registered (server: `DatagramSlot::register`; client:
    /// `RegisterDatagrams`): datagrams go to `queue`.
    pub registered: bool,
    /// The §3.4 decision point passed.
    pub decided: bool,
    /// The registered handle was dropped, or never taken: datagrams are discarded.
    pub gone: bool,
    /// Datagrams for the handle, oldest first (drop-oldest).
    pub queue: VecDeque<Bytes>,
    pub waker: Option<Waker>,
    /// How the receive side failed: `recv.error` is taken by its reader.
    pub error: Option<Error>,
}

/// Connection-level datagram queues and limits.
#[derive(Debug, Default)]
pub(crate) struct Dgrams {
    /// `H3_DATAGRAM` is advertised (the transport had datagrams when built).
    pub on: bool,
    /// The transport's `max_datagram_size` as of the driver's last pass.
    pub limit: Option<usize>,
    /// Datagrams of undecided streams, oldest first.
    pub pending: VecDeque<(StreamId, Bytes)>,
    pub pending_bytes: usize,
    /// Prefixed datagrams the handles queued for the transport (drop-oldest).
    pub out: VecDeque<Bytes>,
    /// Capacity of a registered queue, and of `out`.
    pub queue_cap: usize,
    /// Pending caps (count, bytes): per stream, per connection.
    pub stream_cap: (usize, usize),
    pub conn_cap: (usize, usize),
}

impl Dgrams {
    pub(crate) fn new(b: &Builder, on: bool) -> Self {
        Dgrams {
            on,
            queue_cap: b.datagram_queue,
            stream_cap: b.pending_dgrams_stream,
            conn_cap: b.pending_dgrams_conn,
            ..Dgrams::default()
        }
    }

    /// Keep `b` for undecided `id`, evicting the oldest past the caps.
    // ponytail: linear scans over `pending` (256 by default); index per stream if the
    // caps are raised far.
    fn pend(&mut self, id: StreamId, b: Bytes) {
        self.pending_bytes += b.len();
        self.pending.push_back((id, b));
        loop {
            let mine = self.pending.iter().filter(|(s, _)| *s == id);
            let (n, bytes) = mine.fold((0, 0), |(n, sz), (_, b)| (n + 1, sz + b.len()));
            if n <= self.stream_cap.0 && bytes <= self.stream_cap.1 {
                break;
            }
            let at = self.pending.iter().position(|(s, _)| *s == id);
            self.evict(at.expect("counted above"));
        }
        while self.pending.len() > self.conn_cap.0 || self.pending_bytes > self.conn_cap.1 {
            self.evict(0);
        }
    }

    fn evict(&mut self, at: usize) {
        if let Some((_, b)) = self.pending.remove(at) {
            self.pending_bytes -= b.len();
        }
    }

    /// Remove and return the pending datagrams of `id`, oldest first.
    pub(crate) fn take_pending(&mut self, id: StreamId) -> Vec<Bytes> {
        let (mine, rest) = std::mem::take(&mut self.pending)
            .into_iter()
            .partition::<VecDeque<_>, _>(|(s, _)| *s == id);
        self.pending = rest;
        let mine: Vec<Bytes> = mine.into_iter().map(|(_, b)| b).collect();
        self.pending_bytes -= mine.iter().map(Bytes::len).sum::<usize>();
        mine
    }
}

/// Push onto a drop-oldest queue of capacity `cap`.
pub(crate) fn push_bounded(q: &mut VecDeque<Bytes>, cap: usize, b: Bytes) {
    if cap == 0 {
        return;
    }
    if q.len() >= cap {
        q.pop_front();
    }
    q.push_back(b);
}

impl Inner {
    /// Register datagram semantics on `id` (a decision): pending datagrams move to the
    /// handle's queue.
    pub(crate) fn register_datagrams(&mut self, id: StreamId) {
        let pending = self.dgram.take_pending(id);
        let cap = self.dgram.queue_cap;
        let Some(d) = self.streams.get_mut(&id).map(|s| &mut s.dgram) else {
            return;
        };
        d.registered = true;
        d.decided = true;
        for b in pending {
            push_bounded(&mut d.queue, cap, b);
        }
    }

    /// The §3.4 decision point of `id` passed (final response sent or received): without
    /// registration, a datagram already pending aborts it with `H3_DATAGRAM_ERROR`, and
    /// so will any later one.
    pub(crate) fn decide_datagrams(&mut self, id: StreamId) {
        let Some(d) = self.streams.get_mut(&id).map(|s| &mut s.dgram) else {
            return;
        };
        if std::mem::replace(&mut d.decided, true) {
            return;
        }
        if !self.dgram.take_pending(id).is_empty() {
            self.abort_local(id, H3Code::DATAGRAM_ERROR);
        }
    }

    /// Route one received QUIC DATAGRAM payload.
    fn route(&mut self, payload: Bytes) {
        // Err: a malformed quarter stream id; the core closes the connection.
        let Ok(Datagram::Deliver(id, range)) = self.conn.parse_datagram(&payload) else {
            return; // NotYetOpen, Drop
        };
        let b = payload.slice(range);
        let cap = self.dgram.queue_cap;
        let Some(d) = self.streams.get_mut(&id).map(|s| &mut s.dgram) else {
            return;
        };
        if d.registered {
            if !d.gone {
                push_bounded(&mut d.queue, cap, b);
                self.pending_wakers.extend(d.waker.take());
            }
        } else if d.decided {
            self.abort_local(id, H3Code::DATAGRAM_ERROR);
        } else {
            self.dgram.pend(id, b);
        }
    }
}

impl<C: quic::Connection> Driver<C> {
    /// Refresh the limit, hand the queued datagrams to the transport, then receive and
    /// route datagrams while the budget lasts.
    pub(super) fn datagrams(
        &mut self,
        cx: &mut Context<'_>,
        budget: &mut usize,
    ) -> Result<bool, TransportError> {
        let limit = self.conn.max_datagram_size();
        let (on, out) = self.shared.with(|i| {
            i.dgram.limit = limit;
            (i.dgram.on, std::mem::take(&mut i.dgram.out))
        });
        let mut moved = !out.is_empty();
        for d in out {
            // TooLarge (the limit shrank since `send`) or Unsupported: lost, as a
            // datagram may be.
            if let Err(SendDatagramError::Transport(e)) = self.conn.send_datagram(d) {
                return Err(e);
            }
        }
        while on && *budget > 0 {
            let Poll::Ready(r) = self.conn.poll_recv_datagram(cx) else {
                break;
            };
            let d = r?;
            *budget -= 1;
            moved = true;
            self.shared.with(|i| i.route(d));
        }
        Ok(moved)
    }
}
