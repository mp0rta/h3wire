// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 mp0rta
//! Reading. Peer uni streams (control, QPACK, others) are read eagerly and without limit.
//! Request streams are read only for header discovery here; Task 4 adds the body tiers
//! (read-ahead, demand reservations) and feeding `retained` under them.

use super::{Driver, dispatch_events};
use crate::quic::{self, ReadError, RecvStream, TransportError};
use crate::state::Dir;
use bytes::Bytes;
use h3wire::{H3Code, Recv, StreamId};
use std::task::{Context, Poll};

impl<C: quic::Connection> Driver<C> {
    /// One read on `id`; on progress the token is re-queued behind the other streams.
    pub(super) fn read_stream(
        &mut self,
        id: StreamId,
        budget: &mut usize,
    ) -> Result<bool, TransportError> {
        let max_len = if id.is_uni() {
            usize::MAX
        } else if !self.retained.contains_key(&id) && self.discovering(id) {
            self.discovery_len
        } else {
            return Ok(false);
        };
        let Some(r) = self.recvs.get_mut(&id) else {
            return Ok(false);
        };
        let waker = self.shared.ready_waker(id, Dir::Recv);
        let Poll::Ready(res) = r.poll_read_chunk(&mut Context::from_waker(&waker), max_len) else {
            return Ok(false);
        };
        *budget -= 1;
        match res {
            Ok(Some(chunk)) => {
                self.feed(id, chunk, false);
                self.shared.with(|i| i.push_ready(id, Dir::Recv));
            }
            Ok(None) => {
                self.recvs.remove(&id);
                self.feed(id, Bytes::new(), true);
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

    fn discovering(&self, id: StreamId) -> bool {
        self.shared
            .with(|i| i.streams.get(&id).is_some_and(|s| s.discovering))
    }

    /// Feed `chunk` to the core, dispatching events after each call. A request stream
    /// stops at the end of discovery (or at `Recv::Paused`); the rest is retained.
    fn feed(&mut self, id: StreamId, chunk: Bytes, fin: bool) {
        let rest = self.shared.with(|i| {
            let mut off = 0;
            loop {
                let bytes = &chunk[off..];
                if bytes.is_empty() && !fin {
                    return None;
                }
                // An Err means the core is closed; its CloseConnection is queued.
                let Ok(r) = i.conn.recv(id, bytes, fin) else {
                    return None;
                };
                off += match r {
                    Recv::Paused => return Some(off),
                    Recv::Consumed(n) | Recv::Raw { consumed: n, .. } => n,
                    Recv::Frame { consumed: n, .. } => n,
                    Recv::Body { .. } => {
                        unreachable!("request bodies are read after discovery (Task 4)")
                    }
                };
                dispatch_events(i);
                if off == chunk.len() {
                    return None;
                }
                if !id.is_uni() && !i.streams.get(&id).is_some_and(|s| s.discovering) {
                    return Some(off);
                }
            }
        });
        if let Some(off) = rest {
            self.retained.insert(id, (chunk.slice(off..), fin));
        }
    }
}
