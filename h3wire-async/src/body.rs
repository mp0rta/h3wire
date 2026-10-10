// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 mp0rta
//! Message bodies: [`RecvBody`], the receive half, and the body pipe that feeds an
//! outgoing body into a stream's send queue.

use crate::error::{BoxError, Error};
use crate::http_map::trailer_fields;
use crate::rt::{BoxTask, Cancelable, Executor, Owns};
use crate::state::{Dir, End, Inner, Shared, assert_unlocked};
use bytes::{Buf, Bytes};
use h3wire::{FieldRef, H3Code, StreamId};
use http_body::{Body, Frame};
use std::future::poll_fn;
use std::pin::{Pin, pin};
use std::task::{Context, Poll};

/// A received request or response body: DATA, then optional trailers.
///
/// Dropping it before the end aborts the stream with `H3_REQUEST_CANCELLED` in both
/// directions: the core has no receive-only abort. Once a tunnel owns the stream
/// ([`upgrade`](crate::upgrade)) it is detached: an ended body whose drop does nothing.
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
    /// Takes over one of the entry's `users`, counted by the caller.
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
            continue_100(i, id);
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
                i.fire_cancels(id); // the last of a finished body: see `recv_consumed`
                return Poll::Ready(Some(Ok(Frame::data(b))));
            }
            if let Some(t) = r.trailers.take() {
                r.consumer_waiting = false;
                i.fire_cancels(id);
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
            i.streams.get(&self.id).is_none_or(|s| {
                let r = &s.recv;
                r.detached
                    || (r.eof && r.queue.is_empty() && r.trailers.is_none() && r.error.is_none())
            })
        })
    }
}

/// Server: answer `expect: 100-continue` with `:status 100`, once, unless a response was
/// already sent (spec §4.2).
fn continue_100(i: &mut Inner, id: StreamId) {
    let Some(st) = i.streams.get_mut(&id) else {
        return;
    };
    if std::mem::take(&mut st.expect_continue) && !st.final_sent && !st.send.done {
        // Err: the stream or connection is already over.
        let _ = i
            .conn
            .send_headers(id, &[FieldRef::new(b":status", b"100")], false);
        i.mark_ready(id, Dir::Send);
    }
}

impl Drop for RecvBody {
    fn drop(&mut self) {
        let id = self.id;
        self.shared.with(|i| {
            // A detached body is not the reader: its drop does nothing.
            if i.streams.get(&id).is_some_and(|s| !s.recv.detached) {
                i.drop_reader(id);
            }
            i.release_user(id);
        });
    }
}

/// Feed `body` into the send queue of `id`, polling it only while the stream is admitted
/// (spec §3.3). Runs on an executor task, never under the lock.
///
/// A data frame becomes `Bytes` via `copy_to_bytes(remaining)`: zero-copy when the `Buf`
/// already is `Bytes`, one copy otherwise. `Ok` once the body ended, or once the send
/// side ended or the connection closed first; `Err` with the body's error, for the
/// caller to act on (client: abort; server, Task 7: `task_failed`).
pub(crate) async fn pipe_body<B>(shared: &Shared, id: StreamId, body: B) -> Result<(), BoxError>
where
    B: Body,
    B::Error: Into<BoxError>,
{
    let mut body = pin!(body);
    poll_fn(|cx| {
        loop {
            let go = shared.with(|i| {
                let live = i.close.is_none() && i.streams.get(&id).is_some_and(|s| !s.send.done);
                if !live {
                    return None;
                }
                if i.admit(id) {
                    return Some(true);
                }
                i.streams.get_mut(&id)?.send.waker = Some(cx.waker().clone());
                Some(false)
            });
            match go {
                None => return Poll::Ready(Ok(())),
                Some(false) => return Poll::Pending,
                Some(true) => {}
            }
            assert_unlocked();
            let frame = match body.as_mut().poll_frame(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Some(Err(e))) => return Poll::Ready(Err(e.into())),
                Poll::Ready(None) => {
                    end(shared, id, End::Fin);
                    return Poll::Ready(Ok(()));
                }
                Poll::Ready(Some(Ok(f))) => f,
            };
            match frame.into_data() {
                Ok(mut d) => {
                    let b = d.copy_to_bytes(d.remaining());
                    shared.with(|i| {
                        if let Some(st) = i.streams.get_mut(&id).filter(|s| !s.send.done) {
                            st.send.queued += b.len();
                            st.send.queue.push_back(b);
                            i.mark_ready(id, Dir::Send);
                        }
                    });
                }
                Err(f) => {
                    if let Ok(t) = f.into_trailers() {
                        end(shared, id, End::Trailers(trailer_fields(&t)));
                        return Poll::Ready(Ok(()));
                    }
                }
            }
        }
    })
    .await
}

fn end(shared: &Shared, id: StreamId, e: End) {
    shared.with(|i| {
        if let Some(st) = i.streams.get_mut(&id).filter(|s| !s.send.done) {
            st.send.end = Some(e);
            i.mark_ready(id, Dir::Send);
        }
    });
}

/// Spawn the client request-body pipe for `id`, wrapped in [`Cancelable`]. A body error
/// aborts the stream with `H3_INTERNAL_ERROR` (spec §4.4).
pub(crate) fn spawn_body_pipe<B, E>(shared: Shared, id: StreamId, body: B, exec: &E, owns: Owns)
where
    B: Body + Send + 'static,
    B::Data: Send,
    B::Error: Into<BoxError>,
    E: Executor<BoxTask>,
{
    let token = shared.with(|i| i.cancel_token(id, owns));
    let task = async move {
        if pipe_body(&shared, id, body).await.is_err() {
            shared.with(|i| {
                i.abort_local(id, H3Code::INTERNAL_ERROR);
            });
        }
    };
    exec.execute(Box::pin(Cancelable::new(Box::pin(task), token)));
}
