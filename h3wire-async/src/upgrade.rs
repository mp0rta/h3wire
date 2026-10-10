// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 mp0rta
//! Upgrades and tunnels: CONNECT and Extended CONNECT (spec §4.5).
//!
//! - **Server:** [`on`] on a CONNECT request claims its stream at once: the request's
//!   [`RecvBody`] becomes an ended body (EOF, a no-op on drop) and every byte queued so
//!   far stays for the tunnel. Answer with a 2xx whose body is empty
//!   ([`Body::is_end_stream`](http_body::Body::is_end_stream)) and the [`OnUpgrade`]
//!   resolves to the [`Tunnel`]; a non-2xx resolves it to [`ErrorKind::NotUpgraded`]. A
//!   2xx with a non-empty body aborts the stream with `H3_INTERNAL_ERROR` (the
//!   `OnUpgrade` sees `Usage`). A 2xx to a CONNECT nobody claimed, or whose `OnUpgrade`
//!   was dropped, aborts it with `H3_REQUEST_CANCELLED` right after the HEADERS.
//! - **Client:** a 2xx response to a CONNECT carries a pending upgrade; [`on`] resolves
//!   at once. Dropping the response with the upgrade still inside, or an untaken
//!   `OnUpgrade`, aborts with `H3_REQUEST_CANCELLED`. A non-2xx finishes the request.
//!
//! Dropping a [`TunnelRecv`] before EOF, or a [`TunnelSend`] before
//! [`finish`](TunnelSend::finish) (and without an abort), aborts the whole request with
//! `H3_REQUEST_CANCELLED`: the core has no receive-only abort. Dropping a half whose
//! direction already ended does nothing. A [`Tunnel`] is both halves.

use crate::body::RecvBody;
use crate::driver::dispatch_events;
use crate::error::{Error, ErrorKind};
use crate::slot::OnceSlot;
use crate::state::{Dir, End, Inner, Shared, Up};
use bytes::Bytes;
use h3wire::{H3Code, StreamId, UsageError};
use http::{Request, Response};
use std::future::{Future, poll_fn};
use std::pin::Pin;
use std::task::{Context, Poll};

/// Tunnel ownership of a CONNECT stream; counts one of the entry's `users`. Dropping it
/// runs the §4.5 cancellation for wherever the upgrade stands.
pub(crate) struct Claim {
    shared: Shared,
    id: StreamId,
}

impl Claim {
    /// The caller counted the user.
    pub(crate) fn new(shared: Shared, id: StreamId) -> Self {
        Claim { shared, id }
    }
}

impl Drop for Claim {
    fn drop(&mut self) {
        let id = self.id;
        self.shared.with(|i| {
            if let Some(st) = i.streams.get_mut(&id) {
                match std::mem::take(&mut st.up) {
                    // Released before the final response: no reader remains.
                    Up::Claimed => i.drop_reader(id),
                    // Activated, but the tunnel was never taken.
                    Up::Active => {
                        // Err: the stream or connection is already over.
                        let _ = i.conn.abort(id, H3Code::REQUEST_CANCELLED);
                        i.wake_driver();
                    }
                    _ => {}
                }
            }
            i.release_user(id);
        });
    }
}

/// Server: the claim of a CONNECT request, in its extensions.
#[derive(Clone)]
pub(crate) struct UpgradeCell(pub(crate) OnceSlot<Claim>);

/// Client: the claim of a 2xx CONNECT response, in its extensions.
#[derive(Clone)]
pub(crate) struct PendingUpgrade(pub(crate) OnceSlot<Claim>);

mod sealed {
    pub trait Sealed {
        fn on_upgrade(&mut self) -> super::OnUpgrade;
    }
}

/// A message [`on`] accepts: a server's `Request<RecvBody>` or a client's
/// `Response<RecvBody>`.
pub trait Upgradable: sealed::Sealed {}

impl Upgradable for Request<RecvBody> {}
impl Upgradable for Response<RecvBody> {}

impl sealed::Sealed for Request<RecvBody> {
    /// Claims now: detaches the body, keeping its queue for the tunnel.
    fn on_upgrade(&mut self) -> OnUpgrade {
        let claim = self
            .extensions()
            .get::<UpgradeCell>()
            .and_then(|c| c.0.take());
        if let Some(c) = &claim {
            c.shared.with(|i| {
                let Some(st) = i.streams.get_mut(&c.id) else {
                    return;
                };
                if matches!(st.up, Up::None) && !st.final_sent {
                    st.up = Up::Claimed;
                    st.recv.detached = true;
                    st.recv.consumer_waiting = false;
                    i.pending_wakers.extend(st.recv.waker.take());
                }
            });
        }
        OnUpgrade { claim }
    }
}

impl sealed::Sealed for Response<RecvBody> {
    fn on_upgrade(&mut self) -> OnUpgrade {
        let claim = self
            .extensions()
            .get::<PendingUpgrade>()
            .and_then(|c| c.0.take());
        OnUpgrade { claim }
    }
}

/// Take the upgrade of `msg` (spec §4.5). Only the first call gets it; later ones, and
/// messages without one, resolve to [`ErrorKind::NotUpgraded`].
pub fn on<T: Upgradable>(msg: &mut T) -> OnUpgrade {
    msg.on_upgrade()
}

/// Resolves to the [`Tunnel`] once a 2xx went out (server) or at once (client).
pub struct OnUpgrade {
    claim: Option<Claim>,
}

impl std::fmt::Debug for OnUpgrade {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OnUpgrade").finish_non_exhaustive()
    }
}

impl Future for OnUpgrade {
    type Output = Result<Tunnel, Error>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let Some(c) = &self.claim else {
            return Poll::Ready(Err(ErrorKind::NotUpgraded.into()));
        };
        let (shared, id) = (c.shared.clone(), c.id);
        let r = shared.with(|i| poll_claim(i, id, cx));
        if r.is_ready() {
            self.claim = None; // its drop takes the lock
        }
        r.map(|r| {
            r.map(|()| Tunnel {
                send: TunnelSend {
                    shared: shared.clone(),
                    id,
                    finished: false,
                },
                recv: TunnelRecv { shared, id },
            })
        })
    }
}

/// `Ok` once the tunnel is taken: both halves are counted as users.
fn poll_claim(i: &mut Inner, id: StreamId, cx: &mut Context<'_>) -> Poll<Result<(), Error>> {
    let close = i.close.as_ref().map(|c| c.to_error());
    let Some(st) = i.streams.get_mut(&id) else {
        return Poll::Ready(Err(close.unwrap_or_else(|| ErrorKind::NotUpgraded.into())));
    };
    match &st.up {
        Up::Claimed => {
            if let Some(e) = close.or_else(|| st.recv.error.clone()) {
                return Poll::Ready(Err(e));
            }
            st.recv.waker = Some(cx.waker().clone());
            Poll::Pending
        }
        Up::Active => {
            if let Some(e) = close {
                return Poll::Ready(Err(e));
            }
            st.up = Up::Tunnel;
            st.users += 2;
            Poll::Ready(Ok(()))
        }
        Up::Failed(e) => Poll::Ready(Err(e.clone())),
        _ => Poll::Ready(Err(ErrorKind::NotUpgraded.into())),
    }
}

/// Server: the final response of a CONNECT went out (`Ok`: a 2xx), or will not (`Err`:
/// what its `OnUpgrade` resolves to). A 2xx nobody holds the claim for is aborted with
/// `H3_REQUEST_CANCELLED`.
pub(crate) fn settle(i: &mut Inner, id: StreamId, sent: Result<(), Error>) {
    let Some(st) = i.streams.get_mut(&id) else {
        return;
    };
    let claimed = matches!(st.up, Up::Claimed);
    if claimed {
        i.pending_wakers.extend(st.recv.waker.take());
    }
    let unclaimed_2xx = !claimed && sent.is_ok();
    st.up = match sent {
        Ok(()) if claimed => Up::Active,
        Err(e) if claimed => Up::Failed(e),
        _ => Up::None,
    };
    if unclaimed_2xx {
        // Err: the stream or connection is already over.
        let _ = i.conn.abort(id, H3Code::REQUEST_CANCELLED);
        i.wake_driver();
    }
}

/// Client: the final response of CONNECT `id` arrived. A 2xx hands the receive side to
/// the pending upgrade (counted as a user here); anything else finishes the empty
/// request with FIN only, so a server still reading it does not wait forever.
pub(crate) fn connect_response(i: &mut Inner, id: StreamId, success: bool) {
    let Some(st) = i.streams.get_mut(&id) else {
        return;
    };
    if success {
        st.recv.detached = true;
        st.up = Up::Active;
        st.users += 1;
    } else {
        // Err: the stream or connection is already over.
        let _ = i.conn.send_data(id, 0, true);
        i.mark_ready(id, Dir::Send);
    }
}

/// A CONNECT stream after the upgrade: a byte stream in both directions (DATA frames).
/// [`split`](Tunnel::split) gives independent halves.
#[derive(Debug)]
pub struct Tunnel {
    send: TunnelSend,
    recv: TunnelRecv,
}

impl Tunnel {
    /// The two halves.
    pub fn split(self) -> (TunnelSend, TunnelRecv) {
        (self.send, self.recv)
    }

    /// See [`TunnelRecv::recv`].
    pub async fn recv(&mut self) -> Result<Option<Bytes>, Error> {
        self.recv.recv().await
    }

    /// See [`TunnelSend::send`].
    pub async fn send(&mut self, data: Bytes) -> Result<(), Error> {
        self.send.send(data).await
    }

    /// See [`TunnelSend::finish`].
    pub fn finish(&mut self) -> Result<(), Error> {
        self.send.finish()
    }

    /// See [`TunnelSend::abort`].
    pub fn abort(&self, code: H3Code) {
        self.send.abort(code)
    }
}

/// Abort the whole request with `code`; idempotent. The core's event is dispatched at
/// once, so the other half sees `StreamAborted { code, source: Local }` immediately.
fn abort(shared: &Shared, id: StreamId, code: H3Code) {
    shared.with(|i| {
        // Err: already over, or an invalid code.
        if i.conn.abort(id, code).is_ok() {
            dispatch_events(i);
        }
        i.wake_driver();
    });
}

/// The sending half of a [`Tunnel`].
pub struct TunnelSend {
    shared: Shared,
    id: StreamId,
    /// `finish` was called.
    finished: bool,
}

impl std::fmt::Debug for TunnelSend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TunnelSend")
            .field("stream", &self.id)
            .finish_non_exhaustive()
    }
}

/// Why nothing more can be sent on `id`, if so.
fn send_refused(i: &Inner, id: StreamId, finished: bool) -> Option<Error> {
    if let Some(c) = &i.close {
        return Some(c.to_error());
    }
    let wrong = || ErrorKind::Usage(UsageError::WrongPhase).into();
    match i.streams.get(&id) {
        Some(st) if st.send.done => Some(st.send.error.clone().unwrap_or_else(wrong)),
        Some(_) if !finished => None,
        _ => Some(wrong()),
    }
}

impl TunnelSend {
    /// Queue `data`, waiting until the stream is admitted (spec §3.3). Cancel-safe: the
    /// bytes are queued whole the moment this returns `Ready`, so a dropped pending call
    /// queued nothing. Fails with `SendStopped` after a peer STOP_SENDING, with
    /// `StreamAborted` after an abort, and with `Usage` after [`finish`](Self::finish).
    pub async fn send(&mut self, data: Bytes) -> Result<(), Error> {
        let (id, finished) = (self.id, self.finished);
        let mut data = Some(data);
        poll_fn(|cx| {
            self.shared.with(|i| {
                if let Some(e) = send_refused(i, id, finished) {
                    return Poll::Ready(Err(e));
                }
                let admitted = i.admit(id);
                let st = i.streams.get_mut(&id).expect("checked above");
                if !admitted {
                    st.send.waker = Some(cx.waker().clone());
                    return Poll::Pending;
                }
                let b = data.take().expect("polled after completion");
                st.send.queued += b.len();
                st.send.queue.push_back(b);
                i.mark_ready(id, Dir::Send);
                Poll::Ready(Ok(()))
            })
        })
        .await
    }

    /// Queue FIN after everything accepted so far.
    pub fn finish(&mut self) -> Result<(), Error> {
        let (id, finished) = (self.id, self.finished);
        self.shared.with(|i| {
            if let Some(e) = send_refused(i, id, finished) {
                return Err(e);
            }
            i.streams.get_mut(&id).expect("checked above").send.end = Some(End::Fin);
            i.mark_ready(id, Dir::Send);
            Ok(())
        })?;
        self.finished = true;
        Ok(())
    }

    /// Abort the whole request (both directions) with `code`; idempotent. MASQUE layers
    /// use `H3_MESSAGE_ERROR` for capsule errors.
    pub fn abort(&self, code: H3Code) {
        abort(&self.shared, self.id, code)
    }
}

impl Drop for TunnelSend {
    fn drop(&mut self) {
        let (id, finished) = (self.id, self.finished);
        self.shared.with(|i| {
            if send_refused(i, id, finished).is_none() {
                // Err: the stream or connection is already over.
                let _ = i.conn.abort(id, H3Code::REQUEST_CANCELLED);
                i.wake_driver();
            }
            i.release_user(id);
        });
    }
}

/// The receiving half of a [`Tunnel`].
pub struct TunnelRecv {
    shared: Shared,
    id: StreamId,
}

impl std::fmt::Debug for TunnelRecv {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TunnelRecv")
            .field("stream", &self.id)
            .finish_non_exhaustive()
    }
}

impl TunnelRecv {
    /// The next bytes; `None` once the peer sent FIN. A peer RESET (or an abort) fails
    /// it with `StreamAborted`. Bytes that arrived before the upgrade come first.
    pub async fn recv(&mut self) -> Result<Option<Bytes>, Error> {
        let id = self.id;
        poll_fn(|cx| self.shared.with(|i| poll_recv(i, id, cx))).await
    }

    /// Abort the whole request (both directions) with `code`; idempotent.
    pub fn abort(&self, code: H3Code) {
        abort(&self.shared, self.id, code)
    }
}

fn poll_recv(
    i: &mut Inner,
    id: StreamId,
    cx: &mut Context<'_>,
) -> Poll<Result<Option<Bytes>, Error>> {
    let close = i.close.as_ref().map(|c| c.to_error());
    let Some(r) = i.streams.get_mut(&id).map(|s| &mut s.recv) else {
        return Poll::Ready(close.map_or(Ok(None), Err));
    };
    if !r.queue.is_empty() {
        r.consumer_waiting = false;
        let b = i.pop_body(id).expect("queue is not empty");
        i.mark_ready(id, Dir::Recv); // room to read on
        i.fire_cancels(id); // the last of a finished stream: see `recv_consumed`
        return Poll::Ready(Ok(Some(b)));
    }
    if let Some(e) = r.error.take() {
        r.eof = true;
        return Poll::Ready(Err(e));
    }
    if r.eof {
        // A tunnel carries no trailers: dropped.
        r.trailers = None;
        r.consumer_waiting = false;
        i.fire_cancels(id);
        return Poll::Ready(Ok(None));
    }
    if let Some(e) = close {
        return Poll::Ready(Err(e));
    }
    r.waker = Some(cx.waker().clone());
    if !std::mem::replace(&mut r.consumer_waiting, true) {
        i.mark_ready(id, Dir::Recv); // demand
    }
    Poll::Pending
}

impl Drop for TunnelRecv {
    fn drop(&mut self) {
        let id = self.id;
        self.shared.with(|i| {
            i.drop_reader(id);
            i.release_user(id);
        });
    }
}
