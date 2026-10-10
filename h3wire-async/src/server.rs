// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 mp0rta
//! The server (spec §4.2): [`Builder::serve_connection`] and [`ServerConnection`].

use crate::body::{RecvBody, pipe_body};
use crate::builder::Builder;
use crate::driver::Driver;
use crate::error::{BoxError, Error};
use crate::ext::ConnInfo;
use crate::http_map::{request_from_block, response_fields};
use crate::quic;
use crate::rt::{BoxTask, CancelToken, Cancelable, Executor, Owns};
use crate::state::{Dir, Inner, Shared, assert_unlocked};
use bytes::Buf;
use h3wire::{H3Code, Role, StreamId};
use http::header::EXPECT;
use http::{Method, Request, Response, StatusCode};
use http_body::Body;
use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};
use tower_service::Service;

impl Builder {
    /// Serve HTTP/3 on `conn`: the returned [`ServerConnection`] drives the connection
    /// and dispatches each request to `service`, whose future and response body run on
    /// a task spawned on `exec`.
    ///
    /// HTTP datagrams are advertised iff `conn` has datagrams.
    pub fn serve_connection<C, S, B, E>(
        &self,
        conn: C,
        service: S,
        exec: E,
    ) -> ServerConnection<C, S, E>
    where
        C: quic::Connection,
        S: Service<Request<RecvBody>, Response = Response<B>> + Clone + Send + 'static,
        S::Future: Send + 'static,
        S::Error: Into<BoxError>,
        B: Body + Send + 'static,
        B::Data: Buf + Send,
        B::Error: Into<BoxError>,
        E: Executor<BoxTask>,
    {
        ServerConnection {
            driver: Driver::new(conn, Role::Server, self),
            service,
            exec,
            shutdown: false,
        }
    }
}

/// A server connection: a future that drives the connection and dispatches requests.
///
/// - New streams are accepted only while the Service's `poll_ready` is ready, so QUIC
///   stream credit provides backpressure (spec §3.1). `poll_ready` and `call` run inside
///   this future.
/// - Each request runs on its own task: the Service future, then the response HEADERS,
///   then the response body. A Service that panics, fails or drops its future without a
///   response, or a response body that fails, aborts that stream with
///   `H3_INTERNAL_ERROR`. `100 Continue` is sent when a request carrying
///   `expect: 100-continue` has its body polled before any response.
/// - It resolves `Ok` on a clean close (graceful shutdown, or the peer closing with
///   `H3_NO_ERROR`). Dropping it closes the connection with `H3_NO_ERROR`.
pub struct ServerConnection<C: quic::Connection, S, E> {
    pub(crate) driver: Driver<C>,
    service: S,
    exec: E,
    shutdown: bool,
}

// No field is structurally pinned.
impl<C: quic::Connection, S, E> Unpin for ServerConnection<C, S, E> {}

impl<C: quic::Connection, S, E> std::fmt::Debug for ServerConnection<C, S, E> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ServerConnection").finish_non_exhaustive()
    }
}

impl<C: quic::Connection, S, E> ServerConnection<C, S, E> {
    /// Start a graceful shutdown (spec §4.2):
    /// 1. GOAWAY(2^62-4); streams are still accepted;
    /// 2. after the next full pass, the final GOAWAY cutoff: requests at or above it are
    ///    rejected with `H3_REQUEST_REJECTED`, those below it are still served;
    /// 3. wait until every existing request stream ended in both directions;
    /// 4. wait until every response is acknowledged by the transport (or reset);
    /// 5. close with `H3_NO_ERROR`.
    ///
    /// There is no time limit: wrap the connection in your own timeout and drop it.
    /// Responses are acknowledged at the QUIC layer; their receipt by the peer
    /// application is not guaranteed.
    pub fn graceful_shutdown(mut self: Pin<&mut Self>) {
        self.shutdown = true;
        self.driver.shared().with(|i| {
            // Err: already closed.
            let _ = i.conn.start_shutdown();
            i.graceful = true;
            i.wake_driver();
        });
    }

    /// See `ConnInfo::__debug_recv_accounting`. Not public API.
    #[doc(hidden)]
    pub fn __debug_recv_accounting(&self) -> (usize, usize, usize) {
        ConnInfo::new(self.driver.shared()).__debug_recv_accounting()
    }
}

impl<C, S, B, E> ServerConnection<C, S, E>
where
    C: quic::Connection,
    S: Service<Request<RecvBody>, Response = Response<B>> + Clone + Send + 'static,
    S::Future: Send + 'static,
    S::Error: Into<BoxError>,
    B: Body + Send + 'static,
    B::Data: Buf + Send,
    B::Error: Into<BoxError>,
    E: Executor<BoxTask>,
{
    /// Dispatch delivered requests while the Service is ready (outside the lock).
    /// `Some(ready)`, or `None` if `poll_ready` failed and the connection was closed.
    fn dispatch(&mut self, cx: &mut Context<'_>) -> Option<bool> {
        let shared = self.driver.shared();
        loop {
            assert_unlocked();
            match self.service.poll_ready(cx) {
                Poll::Pending => return Some(false),
                Poll::Ready(Err(_)) => {
                    self.driver.close(H3Code::INTERNAL_ERROR);
                    return None;
                }
                Poll::Ready(Ok(())) => {}
            }
            let Some((id, req, token)) = shared.with(next_request) else {
                return Some(true);
            };
            // Built first: if `call` panics, its drop still commits the abort.
            let mut task = Commit {
                fut: None,
                shared: shared.clone(),
                id,
            };
            let mut req = req.map(|()| RecvBody::new(shared.clone(), id));
            req.extensions_mut().insert(ConnInfo::new(shared.clone()));
            // Further request extensions go here (Task 8: upgrade; Task 9: datagrams).
            let head = req.method() == Method::HEAD;
            let fut = self.service.call(req);
            task.fut = Some(Box::pin(respond(shared.clone(), id, head, fut)));
            self.exec
                .execute(Box::pin(Cancelable::new(Box::pin(task), token)));
        }
    }
}

/// The next delivered request: its head is released, and its entry gains two users (the
/// `RecvBody` and the task), the task's ownership and its cancel token.
fn next_request(i: &mut Inner) -> Option<(StreamId, Request<()>, CancelToken)> {
    while let Some(id) = i.incoming.pop_front() {
        // None: aborted (and reaped) before dispatch.
        let Some(b) = i.streams.get_mut(&id).and_then(|s| s.head.take()) else {
            continue;
        };
        let r = i.conn.headers(b).map(|h| request_from_block(&h));
        i.conn.release(b);
        i.mark_ready(id, Dir::Recv); // a stream paused on its next HEADERS feeds again
        let req = match r {
            Ok(Ok(req)) => req,
            Ok(Err(code)) => {
                // Err: the stream or connection is already over.
                let _ = i.conn.abort(id, code);
                continue;
            }
            // The core dropped its blocks: the connection closed.
            Err(_) => continue,
        };
        let st = i.streams.get_mut(&id).expect("checked above");
        st.users += 2;
        st.recv.task_owned = true;
        st.expect_continue = req
            .headers()
            .get(EXPECT)
            .is_some_and(|v| v.as_bytes().eq_ignore_ascii_case(b"100-continue"));
        let token = i.cancel_token(id, Owns::Both);
        return Some((id, req, token));
    }
    None
}

/// The per-request task body: the Service future, the response HEADERS, the body pipe.
/// Failures are only recorded here (`final_sent` stays false, or `task_failed`); `Commit`
/// turns them into the abort.
async fn respond<F, B, Er>(shared: Shared, id: StreamId, head: bool, fut: F)
where
    F: Future<Output = Result<Response<B>, Er>>,
    B: Body,
    B::Error: Into<BoxError>,
{
    let Ok(resp) = fut.await else {
        return;
    };
    let (parts, body) = resp.into_parts();
    let fields = response_fields(&parts);
    // HEAD, 204 and 304 carry no content: the body is dropped unpolled (the core would
    // refuse its DATA).
    let no_content = head
        || matches!(
            parts.status,
            StatusCode::NO_CONTENT | StatusCode::NOT_MODIFIED
        );
    let end = no_content || body.is_end_stream();
    let pipe = shared.with(|i| {
        let Some(st) = i.streams.get_mut(&id) else {
            return false;
        };
        if st.send.done {
            // The peer stopped the response (or the stream ended): nothing to send.
            st.final_sent = true;
            return false;
        }
        // Err (an invalid response): `final_sent` stays false.
        if i.conn.send_headers(id, &fields.as_refs(), end).is_err() {
            return false;
        }
        if let Some(st) = i.streams.get_mut(&id) {
            st.final_sent = true;
        }
        i.mark_ready(id, Dir::Send);
        !end
    });
    if pipe && pipe_body(&shared, id, body).await.is_err() {
        set_failed(&shared, id);
    }
}

fn set_failed(shared: &Shared, id: StreamId) {
    shared.with(|i| {
        if let Some(st) = i.streams.get_mut(&id) {
            st.task_failed = true;
        }
    });
}

/// Wraps the per-request task (inside its [`Cancelable`]) and commits the stream abort
/// for anything that went wrong inside it, exactly once: when the task completes, or
/// when it is dropped (cancelled, or unwinding). The user future is dropped first, so a
/// `RecvBody` it owns has recorded `abandoned` by then: the result does not depend on
/// destructor order.
struct Commit {
    fut: Option<BoxTask>,
    shared: Shared,
    id: StreamId,
}

impl Future for Commit {
    type Output = ();

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
        let this = &mut *self;
        let Some(f) = this.fut.as_mut() else {
            return Poll::Ready(());
        };
        let unwinding = Unwinding(&this.shared, this.id);
        let r = f.as_mut().poll(cx);
        drop(unwinding);
        if r.is_ready() {
            this.fut = None;
            this.commit();
        }
        r
    }
}

impl Drop for Commit {
    fn drop(&mut self) {
        if self.fut.take().is_some() {
            self.commit();
        }
    }
}

impl Commit {
    /// The task is over: release its ownership and abort with the code its outcome
    /// calls for (spec §4.6, plan "Abort codes inside the task"):
    /// 1. `H3_INTERNAL_ERROR` if it failed: no final response, or the body pipe failed;
    /// 2. else `H3_REQUEST_CANCELLED` if its `RecvBody` was dropped before the end.
    ///
    /// A cancelled task's stream is already over in both directions: no-op there.
    fn commit(&self) {
        let id = self.id;
        self.shared.with(|i| {
            let Some(st) = i.streams.get_mut(&id) else {
                return;
            };
            st.recv.task_owned = false;
            let code = if st.task_failed || !st.final_sent {
                Some(H3Code::INTERNAL_ERROR)
            } else if st.recv.abandoned && !st.recv_terminal() {
                Some(H3Code::REQUEST_CANCELLED)
            } else {
                None
            };
            if let Some(code) = code {
                // Err: the stream or connection is already over.
                let _ = i.conn.abort(id, code);
                i.wake_driver();
            }
            i.release_user(id);
        });
    }
}

/// Marks the task failed if the task panics while it is polled (a panic in the body
/// pipe, after the final response was sent).
struct Unwinding<'a>(&'a Shared, StreamId);

impl Drop for Unwinding<'_> {
    fn drop(&mut self) {
        if std::thread::panicking() {
            set_failed(self.0, self.1);
        }
    }
}

impl<C, S, B, E> Future for ServerConnection<C, S, E>
where
    C: quic::Connection,
    S: Service<Request<RecvBody>, Response = Response<B>> + Clone + Send + 'static,
    S::Future: Send + 'static,
    S::Error: Into<BoxError>,
    B: Body + Send + 'static,
    B::Data: Buf + Send,
    B::Error: Into<BoxError>,
    E: Executor<BoxTask>,
{
    type Output = Result<(), Error>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = &mut *self;
        let Some(ready) = this.dispatch(cx) else {
            return Pin::new(&mut this.driver).poll(cx);
        };
        // During shutdown acceptance never stops: the core rejects late requests.
        this.driver.accept_bidi = ready || this.shutdown;
        let r = Pin::new(&mut this.driver).poll(cx);
        // Requests this pass delivered; releasing their heads wakes the driver.
        if r.is_pending() && this.dispatch(cx).is_none() {
            return Pin::new(&mut this.driver).poll(cx);
        }
        r
    }
}
