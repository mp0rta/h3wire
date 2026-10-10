// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 mp0rta
//! HTTP datagrams (RFC 9297, spec §3.4).
//!
//! - **Server:** while `H3_DATAGRAM` is advertised, every request carries a
//!   [`DatagramSlot`]. [`DatagramSlot::register`] registers datagram semantics for the
//!   request and returns its [`Datagrams`]. Datagrams that arrive before the decision are
//!   kept (bounded, oldest evicted). If the final response is sent without registration,
//!   any datagram already received, or arriving later, aborts the request with
//!   `H3_DATAGRAM_ERROR`. Dropping every clone of the slot without registering does not
//!   decide by itself.
//! - **Client:** put [`RegisterDatagrams`] in a request's extensions to register at
//!   send; its response, whatever the status, carries a [`DatagramSlot`] whose first
//!   `register` returns the handle. A handle never taken discards the datagrams. Without
//!   it, a datagram for that request (pending at the response, or later) aborts it with
//!   `H3_DATAGRAM_ERROR`.
//!
//! `H3_DATAGRAM` is advertised iff the transport has datagrams when the connection is
//! built.

use crate::driver::datagram::push_bounded;
use crate::error::{DatagramError, Error};
use crate::slot::OnceSlot;
use crate::state::{Inner, Shared};
use bytes::{Bytes, BytesMut};
use h3wire::{StreamId, UsageError};
use std::future::poll_fn;
use std::task::Poll;

/// Client: register HTTP datagram semantics for this request (put it in the request's
/// extensions before sending).
#[derive(Clone, Copy, Debug, Default)]
pub struct RegisterDatagrams;

/// The datagram registration of a request (server) or response (client), in its
/// extensions. Clones share it: the first [`register`](Self::register) of any of them
/// gets the handle.
#[derive(Clone)]
pub struct DatagramSlot(OnceSlot<Datagrams>);

impl std::fmt::Debug for DatagramSlot {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DatagramSlot").finish_non_exhaustive()
    }
}

impl DatagramSlot {
    /// The caller counted the handle's user.
    pub(crate) fn new(shared: Shared, id: StreamId) -> Self {
        DatagramSlot(OnceSlot::new(Datagrams { shared, id }))
    }

    /// Server: register datagram semantics and return the handle (the datagrams that
    /// arrived so far come first). Client: return the handle (semantics were registered
    /// at send). `None` after the first call.
    pub fn register(&self) -> Option<Datagrams> {
        let d = self.0.take()?;
        d.shared.with(|i| i.register_datagrams(d.id));
        Some(d)
    }
}

/// The HTTP datagrams of one request. Dropping it discards later datagrams.
pub struct Datagrams {
    shared: Shared,
    id: StreamId,
}

impl std::fmt::Debug for Datagrams {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Datagrams")
            .field("stream", &self.id)
            .finish_non_exhaustive()
    }
}

/// The quarter stream id prefix of `id`, or why no datagram can be sent on it.
fn prefix(i: &Inner, id: StreamId, buf: &mut [u8; 8]) -> Result<usize, DatagramError> {
    match i.conn.datagram_prefix(id, buf) {
        Ok(n) => Ok(n),
        Err(UsageError::NotNegotiated) => {
            let off = i.conn.peer_settings().is_some_and(|s| !s.h3_datagram);
            Err(if off || !i.dgram.on {
                DatagramError::Unsupported
            } else {
                DatagramError::NotNegotiated
            })
        }
        // Closed, or the request's send side is over.
        Err(_) => Err(DatagramError::Closed),
    }
}

impl Datagrams {
    /// Queue `data` as one datagram (drop-oldest); `Ok` means accepted locally, not
    /// delivered. Fails with `NotNegotiated` until the peer's SETTINGS confirm
    /// `H3_DATAGRAM`, `Unsupported` if the peer (or the transport) has no datagrams,
    /// `TooLarge` over [`max_payload`](Self::max_payload), and `Closed` once the
    /// request's send side or the connection is over.
    ///
    /// The limit is the transport's as of the driver's last pass; a datagram the
    /// transport then refuses because its limit shrank is lost, as a datagram may be.
    pub fn send(&self, data: Bytes) -> Result<(), DatagramError> {
        self.shared.with(|i| {
            let mut p = [0; 8];
            let n = prefix(i, self.id, &mut p)?;
            let limit = i.dgram.limit.ok_or(DatagramError::Unsupported)?;
            if n + data.len() > limit {
                return Err(DatagramError::TooLarge);
            }
            let mut b = BytesMut::with_capacity(n + data.len());
            b.extend_from_slice(&p[..n]);
            b.extend_from_slice(&data);
            let cap = i.dgram.queue_cap;
            push_bounded(&mut i.dgram.out, cap, b.freeze());
            i.wake_driver();
            Ok(())
        })
    }

    /// The next datagram. `Ok(None)` once the request ended normally (no datagram can
    /// arrive after its receive side ended); an abort or the connection's close fails it.
    pub async fn recv(&mut self) -> Result<Option<Bytes>, Error> {
        let id = self.id;
        poll_fn(|cx| {
            self.shared.with(|i| {
                let close = i.close.as_ref().map(|c| c.to_error());
                let Some(st) = i.streams.get_mut(&id) else {
                    return Poll::Ready(close.map_or(Ok(None), Err));
                };
                if let Some(b) = st.dgram.queue.pop_front() {
                    return Poll::Ready(Ok(Some(b)));
                }
                if let Some(e) = &st.dgram.error {
                    return Poll::Ready(Err(e.clone()));
                }
                if st.recv.eof {
                    return Poll::Ready(Ok(None));
                }
                if let Some(e) = close {
                    return Poll::Ready(Err(e));
                }
                st.dgram.waker = Some(cx.waker().clone());
                Poll::Pending
            })
        })
        .await
    }

    /// The largest payload [`send`](Self::send) accepts now: the transport's limit minus
    /// this request's quarter stream id length. `None` until negotiation completes, or
    /// when datagrams cannot be sent.
    pub fn max_payload(&self) -> Option<usize> {
        self.shared.with(|i| {
            let n = prefix(i, self.id, &mut [0; 8]).ok()?;
            i.dgram.limit?.checked_sub(n)
        })
    }
}

impl Drop for Datagrams {
    fn drop(&mut self) {
        let id = self.id;
        self.shared.with(|i| {
            if let Some(d) = i.streams.get_mut(&id).map(|s| &mut s.dgram) {
                if d.registered {
                    d.gone = true;
                    d.queue.clear();
                    d.waker = None;
                }
            }
            i.release_user(id);
        });
    }
}
