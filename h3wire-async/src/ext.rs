// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 mp0rta
//! Request/response extensions.

use crate::state::Shared;
#[cfg(test)]
use crate::state::charge;
use bytes::Bytes;
use h3wire::PeerSettings;
#[cfg(test)]
use h3wire::StreamId;
use std::future::poll_fn;
use std::task::Poll;

/// The Extended CONNECT `:protocol` value (RFC 9220); put it in a request's extensions.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Protocol(Bytes);

impl Protocol {
    /// From a static string.
    pub fn from_static(s: &'static str) -> Self {
        Self(Bytes::from_static(s.as_bytes()))
    }

    /// From arbitrary bytes; no validation.
    pub fn new(b: Bytes) -> Self {
        Self(b)
    }

    /// The raw value.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

/// One stream's buffers, from `ConnInfo::__debug_buffers` (tests).
#[cfg(test)]
#[derive(Clone, Debug)]
pub(crate) struct DebugStream {
    /// The stream.
    pub id: StreamId,
    /// Raw bytes read but not fed to the core.
    pub retained: usize,
    /// Bytes in the send queue.
    pub send_queued: usize,
    /// Sizes of the queued send chunks, oldest first.
    pub send_chunks: Vec<usize>,
    /// Datagrams in the registered handle's queue.
    pub dgram_queue: usize,
    /// Pending (undecided) datagrams: count and bytes (charged).
    pub pending_dgrams: (usize, usize),
}

/// Connection information; `Clone`, and usable after the connection has closed.
#[derive(Clone)]
pub struct ConnInfo {
    shared: Shared,
}

impl std::fmt::Debug for ConnInfo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ConnInfo").finish_non_exhaustive()
    }
}

impl ConnInfo {
    pub(crate) fn new(shared: Shared) -> Self {
        ConnInfo { shared }
    }

    /// The peer's SETTINGS, if they have arrived.
    pub fn peer_settings(&self) -> Option<PeerSettings> {
        self.shared.with(|i| i.conn.peer_settings().cloned())
    }

    /// Receive accounting for the bound oracle: (queued body bytes as charged, streams
    /// holding a demand reservation, retained raw bytes).
    #[cfg(test)]
    pub(crate) fn __debug_recv_accounting(&self) -> (usize, usize, usize) {
        self.shared.with(|i| {
            let r = i.streams.values().map(|s| &s.recv);
            (
                r.clone().map(|r| r.queued).sum(),
                r.filter(|r| r.reservation.is_some()).count(),
                i.retained.values().map(|(b, _)| b.len()).sum(),
            )
        })
    }

    /// Datagram accounting for the bound oracle: (datagrams in registered queues, pending
    /// datagrams, pending bytes).
    #[cfg(test)]
    pub(crate) fn __debug_datagram_accounting(&self) -> (usize, usize, usize) {
        self.shared.with(|i| {
            let queued = i.streams.values().map(|s| s.dgram.queue.len()).sum();
            (queued, i.dgram.pending.len(), i.dgram.pending_bytes)
        })
    }

    /// Per-stream buffers for the bound oracle, one entry per stream with any state, plus
    /// the datagrams queued for the transport.
    #[cfg(test)]
    pub(crate) fn __debug_buffers(&self) -> (Vec<DebugStream>, usize) {
        self.shared.with(|i| {
            let mut ids: Vec<StreamId> =
                i.streams.keys().chain(i.retained.keys()).copied().collect();
            ids.extend(i.dgram.pending.iter().map(|(s, _)| *s));
            ids.sort_by_key(|s| s.0);
            ids.dedup();
            let streams = ids
                .into_iter()
                .map(|id| {
                    let st = i.streams.get(&id);
                    let pending = i.dgram.pending.iter().filter(|(s, _)| *s == id);
                    DebugStream {
                        id,
                        retained: i.retained.get(&id).map_or(0, |(b, _)| b.len()),
                        send_queued: st.map_or(0, |s| s.send.queued),
                        send_chunks: st.map_or(Vec::new(), |s| {
                            s.send.queue.iter().map(Bytes::len).collect()
                        }),
                        dgram_queue: st.map_or(0, |s| s.dgram.queue.len()),
                        pending_dgrams: pending
                            .fold((0, 0), |(n, b), (_, d)| (n + 1, b + charge(d.len()))),
                    }
                })
                .collect();
            (streams, i.dgram.out.len())
        })
    }

    /// Wait for the peer's SETTINGS; `None` if the connection closes first.
    pub async fn settings(&self) -> Option<PeerSettings> {
        poll_fn(|cx| {
            self.shared.with(|i| {
                if let Some(s) = i.conn.peer_settings() {
                    return Poll::Ready(Some(s.clone()));
                }
                if i.close.is_some() {
                    return Poll::Ready(None);
                }
                i.wait_conn(cx.waker());
                Poll::Pending
            })
        })
        .await
    }
}
