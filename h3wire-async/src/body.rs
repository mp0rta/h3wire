// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 mp0rta
//! Message bodies: [`RecvBody`], the receive half.

use crate::error::Error;
use crate::state::{Dir, Shared};
use bytes::Bytes;
use h3wire::{H3Code, StreamId};
use http_body::{Body, Frame};
use std::pin::Pin;
use std::task::{Context, Poll};

/// A received request or response body: DATA, then optional trailers.
///
/// Dropping it before the end aborts the stream with `H3_REQUEST_CANCELLED` in both
/// directions: the core has no receive-only abort.
pub struct RecvBody {
    shared: Shared,
    id: StreamId,
}

impl std::fmt::Debug for RecvBody {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RecvBody")
            .field("stream", &self.id)
            .finish_non_exhaustive()
    }
}

impl RecvBody {
    #[allow(dead_code)] // the client and server hand it out (Tasks 6–7)
    pub(crate) fn new(shared: Shared, id: StreamId) -> Self {
        RecvBody { shared, id }
    }
}

impl Body for RecvBody {
    type Data = Bytes;
    type Error = Error;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, Error>>> {
        let id = self.id;
        self.shared.with(|i| {
            let close = i.close.as_ref().map(|c| c.to_error());
            let Some(r) = i.streams.get_mut(&id).map(|s| &mut s.recv) else {
                return Poll::Ready(close.map(Err));
            };
            if r.detached {
                return Poll::Ready(None);
            }
            if !r.queue.is_empty() {
                r.consumer_waiting = false;
                let b = i.pop_body(id).expect("queue is not empty");
                i.mark_ready(id, Dir::Recv); // room to read on
                return Poll::Ready(Some(Ok(Frame::data(b))));
            }
            if let Some(t) = r.trailers.take() {
                r.consumer_waiting = false;
                return Poll::Ready(Some(Ok(Frame::trailers(t))));
            }
            if let Some(e) = r.error.take() {
                r.eof = true;
                return Poll::Ready(Some(Err(e)));
            }
            if r.eof {
                return Poll::Ready(None);
            }
            // After close the core emits nothing more for this stream.
            if let Some(e) = close {
                return Poll::Ready(Some(Err(e)));
            }
            r.waker = Some(cx.waker().clone());
            if !std::mem::replace(&mut r.consumer_waiting, true) {
                i.mark_ready(id, Dir::Recv); // demand
            }
            Poll::Pending
        })
    }

    fn is_end_stream(&self) -> bool {
        self.shared.with(|i| {
            i.streams.get(&self.id).is_some_and(|s| {
                let r = &s.recv;
                r.detached
                    || (r.eof && r.queue.is_empty() && r.trailers.is_none() && r.error.is_none())
            })
        })
    }
}

impl Drop for RecvBody {
    fn drop(&mut self) {
        let id = self.id;
        self.shared.with(|i| {
            let closed = i.close.is_some();
            let Some(r) = i.streams.get_mut(&id).map(|s| &mut s.recv) else {
                return;
            };
            if r.detached {
                return;
            }
            r.waker = None;
            r.consumer_waiting = false;
            if r.eof || r.error.is_some() || closed {
                i.discard_body(id);
            } else if r.task_owned {
                r.abandoned = true;
                return;
            } else {
                // Err: not a live request stream any more; nothing to abort.
                let _ = i.conn.abort(id, H3Code::REQUEST_CANCELLED);
            }
            i.wake_driver();
        });
    }
}
