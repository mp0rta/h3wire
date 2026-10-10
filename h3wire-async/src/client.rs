// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 mp0rta
//! The client (spec §4.3): [`Builder::handshake`], [`SendRequest`] and
//! [`ClientConnection`].

use crate::body::{RecvBody, spawn_body_pipe};
use crate::builder::Builder;
use crate::driver::Driver;
use crate::error::{BoxError, Error, ErrorKind};
use crate::ext::{ConnInfo, Protocol};
use crate::http_map::{Fields, request_fields, response_from_block};
use crate::quic;
use crate::rt::{BoxTask, Executor, Owns};
use crate::state::{Dir, Inner, OnOpen, Open, Shared};
use bytes::Buf;
use h3wire::{AbortSource, H3Code, PeerSettings, Role, StreamId, UsageError};
use http::{Method, Request, Response};
use http_body::Body;
use std::future::{Future, poll_fn};
use std::marker::PhantomData;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

impl Builder {
    /// Start a client connection over `conn`. Spawn the returned [`ClientConnection`]
    /// (the driver) on `exec`; request bodies are piped by tasks spawned on `exec`.
    ///
    /// HTTP datagrams are advertised iff `conn` has datagrams.
    pub async fn handshake<C, B, E>(
        &self,
        conn: C,
        exec: E,
    ) -> Result<(SendRequest<B>, ClientConnection<C>), Error>
    where
        C: quic::Connection,
        B: Body + Send + 'static,
        B::Data: Buf + Send,
        B::Error: Into<BoxError>,
        E: Executor<BoxTask>,
    {
        let driver = Driver::new(conn, Role::Client, self);
        let send = SendRequest {
            shared: driver.shared(),
            exec: BoxExec(Arc::new(move |t| exec.execute(t))),
            _body: PhantomData,
        };
        Ok((send, ClientConnection { driver }))
    }
}

/// The application's executor, type-erased.
#[derive(Clone)]
struct BoxExec(Arc<dyn Fn(BoxTask) + Send + Sync>);

impl Executor<BoxTask> for BoxExec {
    fn execute(&self, fut: BoxTask) {
        (self.0)(fut)
    }
}

/// Sends requests on a client connection; `Clone`.
pub struct SendRequest<B> {
    pub(crate) shared: Shared,
    exec: BoxExec,
    _body: PhantomData<fn(B)>,
}

impl<B> Clone for SendRequest<B> {
    fn clone(&self) -> Self {
        SendRequest {
            shared: self.shared.clone(),
            exec: self.exec.clone(),
            _body: PhantomData,
        }
    }
}

impl<B> std::fmt::Debug for SendRequest<B> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SendRequest").finish_non_exhaustive()
    }
}

/// Why no new request may start, if so.
fn refused(i: &Inner) -> Option<Error> {
    if let Some(c) = &i.close {
        return Some(c.to_error());
    }
    if i.peer_goaway {
        return Some(ErrorKind::Usage(UsageError::GoingAway).into());
    }
    i.graceful.then(|| {
        ErrorKind::Closed {
            code: H3Code::NO_ERROR,
            by_peer: false,
        }
        .into()
    })
}

fn usage(e: UsageError) -> Error {
    ErrorKind::Usage(e).into()
}

impl<B> SendRequest<B>
where
    B: Body + Send + 'static,
    B::Data: Send,
    B::Error: Into<BoxError>,
{
    /// `Ok` while new requests may start; fails after the peer's GOAWAY, a graceful
    /// shutdown, or the connection's close.
    pub async fn ready(&mut self) -> Result<(), Error> {
        self.shared.with(|i| refused(i)).map_or(Ok(()), Err)
    }

    /// Send `req`; the returned future resolves at the final response HEADERS (1xx
    /// responses are ignored).
    ///
    /// - The request is queued by this call, not by the first poll. Its body is piped by
    ///   an executor task spawned once the stream opens, whether or not the returned
    ///   future is ever polled. Dropping that future before it resolves cancels the
    ///   request (`H3_REQUEST_CANCELLED`).
    /// - Without a URI authority, `Host` supplies `:authority`; with neither, or for a
    ///   CONNECT whose body is not empty ([`Body::is_end_stream`]), the future fails with
    ///   [`ErrorKind::Usage`] and nothing is sent.
    /// - With a [`Protocol`] extension (Extended CONNECT) the future first waits for the
    ///   peer's SETTINGS (only then is the request queued), and fails with
    ///   `Usage(NotNegotiated)` unless the peer enabled it.
    pub fn send_request(
        &mut self,
        req: Request<B>,
    ) -> impl Future<Output = Result<Response<RecvBody>, Error>> + Send + use<B> {
        let shared = self.shared.clone();
        let start = self.start(req);
        async move {
            let mut f = match start? {
                Ok(f) => f,
                Err(req) => {
                    let s = ConnInfo::new(shared.clone()).settings().await;
                    let Some(s) = s else {
                        return Err(shared.with(|i| i.close.as_ref().expect("closed").to_error()));
                    };
                    if !s.enable_connect_protocol {
                        return Err(usage(UsageError::NotNegotiated));
                    }
                    enqueue(&shared, req)?
                }
            };
            poll_fn(|cx| f.poll(cx)).await
        }
    }

    /// Validate `req` and queue it; an Extended CONNECT comes back unqueued, to be queued
    /// once the peer's SETTINGS allow it.
    fn start(&self, req: Request<B>) -> Result<Result<InFlight, Queued>, Error> {
        let (parts, body) = req.into_parts();
        let fields = request_fields(&parts).map_err(usage)?;
        let connect = parts.method == Method::CONNECT;
        if connect && !body.is_end_stream() {
            return Err(usage(UsageError::WrongPhase));
        }
        // CONNECT goes without FIN and without a pipe (Task 8 takes it from there).
        let end = !connect && body.is_end_stream();
        let on_open = (!connect && !end).then(|| {
            let (sh, exec) = (self.shared.clone(), self.exec.clone());
            Box::new(move |id| spawn_body_pipe(sh, id, body, &exec, Owns::Send)) as OnOpen
        });
        let req = (fields, end, on_open);
        if parts.extensions.get::<Protocol>().is_some() {
            return Ok(Err(req));
        }
        enqueue(&self.shared, req).map(Ok)
    }

    /// The peer's SETTINGS, if they have arrived.
    pub fn peer_settings(&self) -> Option<PeerSettings> {
        ConnInfo::new(self.shared.clone()).peer_settings()
    }

    /// Wait for the peer's SETTINGS; `None` if the connection closes first.
    pub async fn settings(&self) -> Option<PeerSettings> {
        ConnInfo::new(self.shared.clone()).settings().await
    }

    /// See `ConnInfo::__debug_recv_accounting`. Not public API.
    #[doc(hidden)]
    pub fn __debug_recv_accounting(&self) -> (usize, usize, usize) {
        ConnInfo::new(self.shared.clone()).__debug_recv_accounting()
    }
}

/// A request's HEADERS, whether they end the stream, and its body pipe.
type Queued = (Fields, bool, Option<OnOpen>);

/// Queue `req` for the driver to open its stream, unless new requests are refused.
fn enqueue(shared: &Shared, req: Queued) -> Result<InFlight, Error> {
    let mut req = Some(req);
    // On refusal `req` (it may own the body) is dropped after the lock.
    let ticket = shared.with(|i| {
        if let Some(e) = refused(i) {
            return Err(e);
        }
        let t = i.next_open;
        i.next_open += 1;
        let o = Open {
            req: req.take(),
            done: None,
            waker: None,
        };
        i.opens.insert(t, o);
        i.wake_driver();
        Ok(t)
    })?;
    Ok(InFlight {
        shared: shared.clone(),
        ticket,
        id: None,
        over: false,
    })
}

/// A request from its submission to its final response. Dropped before that, it cancels
/// the request.
struct InFlight {
    shared: Shared,
    ticket: u64,
    /// The stream, once the driver opened it.
    id: Option<StreamId>,
    /// Resolved: nothing to cancel.
    over: bool,
}

impl InFlight {
    fn poll(&mut self, cx: &mut Context<'_>) -> Poll<Result<Response<RecvBody>, Error>> {
        let shared = self.shared.clone();
        let (r, gone) = shared.with(|i| self.poll_locked(i, cx));
        drop(gone); // may own the user's body: dropped after the lock
        let r = match r {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(r) => r,
        };
        self.over = true;
        let id = self.id;
        Poll::Ready(r.map(|resp| resp.map(|()| RecvBody::new(shared, id.expect("opened")))))
    }

    /// Also returns the removed queue entry, to be dropped outside the lock.
    fn poll_locked(
        &mut self,
        i: &mut Inner,
        cx: &mut Context<'_>,
    ) -> (Poll<Result<Response<()>, Error>>, Option<Open>) {
        let mut gone = None;
        if self.id.is_none() {
            let o = i.opens.get_mut(&self.ticket).expect("removed only here");
            let Some(done) = o.done.take() else {
                o.waker = Some(cx.waker().clone());
                return (Poll::Pending, None);
            };
            gone = i.opens.remove(&self.ticket);
            match done {
                Ok(id) => self.id = Some(id),
                Err(e) => return (Poll::Ready(Err(e)), gone),
            }
        }
        let id = self.id.expect("set above");
        let r = response(i, id, cx);
        // Ok: our user passes to the `RecvBody`.
        if let Poll::Ready(Err(_)) = r {
            i.release_user(id);
        }
        (r, gone)
    }
}

/// The final response of `id` once its head arrived; the head is released.
fn response(
    i: &mut Inner,
    id: StreamId,
    cx: &mut Context<'_>,
) -> Poll<Result<Response<()>, Error>> {
    let close = i.close.as_ref().map(|c| c.to_error());
    let Some(st) = i.streams.get_mut(&id) else {
        return Poll::Ready(Err(close.expect("streams outlive the connection")));
    };
    if let Some(b) = st.head.take() {
        let r = i.conn.headers(b).map(|h| response_from_block(&h));
        i.conn.release(b);
        i.mark_ready(id, Dir::Recv); // a stream paused on its next HEADERS feeds again
        return Poll::Ready(match r {
            Ok(Ok(resp)) => Ok(resp),
            Ok(Err(code)) => {
                let _ = i.conn.abort(id, code);
                Err(ErrorKind::StreamAborted {
                    code,
                    source: AbortSource::Local,
                    retryable: false,
                }
                .into())
            }
            // The core dropped its blocks: the connection closed.
            Err(e) => Err(close.unwrap_or_else(|| usage(e))),
        });
    }
    if let Some(e) = st.recv.error.take() {
        st.recv.eof = true;
        return Poll::Ready(Err(e));
    }
    if let Some(e) = close {
        return Poll::Ready(Err(e));
    }
    st.recv.waker = Some(cx.waker().clone());
    Poll::Pending
}

impl Drop for InFlight {
    fn drop(&mut self) {
        if self.over {
            return;
        }
        let gone = self.shared.with(|i| {
            let mut gone = None;
            if self.id.is_none() {
                gone = i.opens.remove(&self.ticket);
                if let Some(Open {
                    done: Some(Ok(id)), ..
                }) = &gone
                {
                    self.id = Some(*id);
                }
            }
            if let Some(id) = self.id {
                // Nobody resumes a stream that is being aborted: no `mark_ready`.
                if let Some(b) = i.streams.get_mut(&id).and_then(|s| s.head.take()) {
                    i.conn.release(b);
                }
                // Err: the stream or connection is already over.
                let _ = i.conn.abort(id, H3Code::REQUEST_CANCELLED);
                i.release_user(id);
            }
            i.wake_driver();
            gone
        });
        drop(gone);
    }
}

/// The client connection's driver: a future to spawn on the executor. It resolves `Ok`
/// on a clean close (graceful shutdown, or the peer closing with `H3_NO_ERROR`).
/// Dropping it closes the connection with `H3_NO_ERROR`.
pub struct ClientConnection<C: quic::Connection> {
    driver: Driver<C>,
}

impl<C: quic::Connection> std::fmt::Debug for ClientConnection<C> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ClientConnection").finish_non_exhaustive()
    }
}

impl<C: quic::Connection> ClientConnection<C> {
    /// Refuse new requests, wait for those in flight (their responses taken, both
    /// directions ended and our side acknowledged), then close with `H3_NO_ERROR`.
    ///
    /// There is no time limit: wrap the connection in your own timeout and drop it.
    pub fn graceful_shutdown(self: Pin<&mut Self>) {
        self.driver.shared().with(|i| {
            i.graceful = true;
            i.wake_driver();
        });
    }
}

impl<C: quic::Connection> Future for ClientConnection<C> {
    type Output = Result<(), Error>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        Pin::new(&mut self.driver).poll(cx)
    }
}
