// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 mp0rta
//! The connection driver: owns the QUIC objects and runs the core's driving loop.
//!
//! One `poll` runs rounds until nothing moves or the work budget (transport operations
//! that returned `Ready`) is spent; then it wakes itself and yields. A round:
//! 1. executes core actions and opens local uni streams;
//! 2. accepts peer streams; a client opens streams for queued requests;
//! 3. writes the core's sendable streams (one write each);
//! 4. serves readiness tokens round-robin (reads, writes, `poll_stopped`);
//! 5. dispatches core events (also right after each `recv`, see `recv.rs`);
//! 6. closes with `H3_NO_ERROR` once a graceful shutdown has drained;
//! 7. stops once the connection is closed.
//!
//! The shared lock is never held across a transport call: a transport may invoke a
//! readiness waker synchronously, and that waker takes the lock.

mod recv;
mod send;

use crate::builder::Builder;
use crate::error::{Error, ErrorKind};
use crate::http_map::headers_from_block;
use crate::quic::{self, RecvStream, SendStream, TransportError};
use crate::state::assert_unlocked;
use crate::state::{CloseCause, Dir, Inner, Shared, StreamState};
use bytes::Bytes;
use h3wire::{Action, Event, H3Code, HeadersKind, Role, StreamId, UniKind, UsageError};
use std::collections::{HashMap, HashSet, VecDeque};
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

pub(crate) struct Driver<C: quic::Connection> {
    conn: C,
    shared: Shared,
    role: Role,
    /// Kept after `FinishStream` until `poll_stopped` resolves or the stream is reset.
    sends: HashMap<StreamId, C::Send>,
    recvs: HashMap<StreamId, C::Recv>,
    /// `Action::OpenUni` kinds waiting for `poll_open_uni`.
    open_uni: VecDeque<UniKind>,
    /// The rest of each DATA frame in flight: `[prefix, payload]`, written ones removed.
    frames: HashMap<StreamId, Vec<Bytes>>,
    /// Streams whose `FinishStream` was executed (kept for acknowledgement polling).
    finished: HashSet<StreamId>,
    /// Streams whose last write pended: skipped until their `Send` token fires.
    write_blocked: HashSet<StreamId>,
    work_budget: usize,
    /// Header-discovery read size: `max_encoded_field_section_size + 16`.
    discovery_len: usize,
    /// Per-stream read-ahead, connection cap `C` and demand chunk `D` (§3.2).
    read_ahead: usize,
    read_ahead_cap: usize,
    demand_chunk: usize,
    /// Server: accept new bidi streams (the Service is ready, or shutting down).
    pub(crate) accept_bidi: bool,
    /// Server: graceful shutdown sent its final GOAWAY cutoff (`finish_shutdown`).
    cutoff_sent: bool,
}

// No field is ever pinned.
impl<C: quic::Connection> Unpin for Driver<C> {}

impl<C: quic::Connection> Driver<C> {
    pub(crate) fn new(conn: C, role: Role, b: &Builder) -> Self {
        let config = b.core_config(conn.max_datagram_size().is_some());
        let discovery_len = config.max_encoded_field_section_size.saturating_add(16);
        let shared = Shared::new(h3wire::Connection::new(role, config));
        shared.with(|i| i.send_capacity = b.send_capacity);
        Driver {
            conn,
            shared,
            role,
            sends: HashMap::new(),
            recvs: HashMap::new(),
            open_uni: VecDeque::new(),
            frames: HashMap::new(),
            finished: HashSet::new(),
            write_blocked: HashSet::new(),
            work_budget: b.work_budget.max(1),
            discovery_len,
            read_ahead: b.read_ahead,
            read_ahead_cap: b.read_ahead_cap,
            demand_chunk: b.demand_chunk.max(1),
            accept_bidi: true,
            cutoff_sent: false,
        }
    }

    /// Test hook until `SendRequest` exists (Task 6): open a request stream and queue its
    /// HEADERS.
    #[cfg(test)]
    pub(crate) fn open_request(&mut self, fields: &[(&str, &str)], end: bool) -> StreamId {
        let mut cx = Context::from_waker(std::task::Waker::noop());
        let Poll::Ready(Ok((s, r))) = self.conn.poll_open_bidi(&mut cx) else {
            panic!("no stream credit");
        };
        let id = s.id();
        self.sends.insert(id, s);
        self.recvs.insert(id, r);
        let f: Vec<h3wire::FieldRef> = fields
            .iter()
            .map(|(n, v)| h3wire::FieldRef::new(n.as_bytes(), v.as_bytes()))
            .collect();
        self.shared.with(|i| {
            i.conn.send_headers(id, &f, end).unwrap();
            i.streams.insert(id, StreamState::new());
            i.push_ready(id, Dir::Recv);
            i.push_ready(id, Dir::Send);
        });
        id
    }

    pub(crate) fn shared(&self) -> Shared {
        self.shared.clone()
    }

    /// `Some` once the connection is closed. `Ok` for a clean close: an `H3_NO_ERROR`
    /// close by either side (graceful shutdown, the driver dropped, or the peer closing
    /// with `H3_NO_ERROR` once it is done). Handles still see the peer's close as
    /// `Transport`, keeping its code (spec §4.7).
    fn outcome(&self) -> Option<Result<(), Error>> {
        self.shared.with(|i| {
            i.close.as_ref().map(|c| match c {
                CloseCause::H3 { code, .. } if *code == H3Code::NO_ERROR => Ok(()),
                CloseCause::Transport(e) if e.peer_app_code == Some(H3Code::NO_ERROR.0) => Ok(()),
                c => Err(c.to_error()),
            })
        })
    }

    /// One round; `Ok(true)` if anything moved.
    fn round(&mut self, cx: &mut Context<'_>, budget: &mut usize) -> Result<bool, TransportError> {
        let mut moved = self.actions(cx, budget)?;
        if self.shared.with(|i| i.close.is_some()) {
            return Ok(true);
        }
        moved |= self.accept(cx, budget)?;
        moved |= self.write_sendable(budget)?;
        moved |= self.serve_ready(budget)?;
        self.shared.with(dispatch_events);
        let cutoff = self.role == Role::Client || self.cutoff_sent;
        if cutoff && self.shared.with(|i| i.graceful) && self.drained() {
            self.close(H3Code::NO_ERROR);
            return Ok(true);
        }
        Ok(moved)
    }

    /// Every request is over: none waits for its stream; on every stream with an entry
    /// the head was taken and the receive side ended; and every request send half is
    /// acknowledged or reset (checked on the halves: a reaped entry may still have one).
    fn drained(&self) -> bool {
        !self.sends.keys().any(|id| id.is_request())
            && self.shared.with(|i| {
                i.opens.values().all(|o| o.done.is_some())
                    && i.streams
                        .values()
                        .all(|st| st.head.is_none() && st.recv_terminal())
            })
    }

    /// Close the connection with `code` and fail every handle (no-op once closed).
    pub(crate) fn close(&mut self, code: H3Code) {
        if self.shared.with(|i| i.close.is_some()) {
            return;
        }
        self.conn.close(code.0);
        self.shared.with(|i| {
            i.conn.transport_closed();
            i.fail(CloseCause::H3 {
                code,
                by_peer: false,
            });
        });
    }

    /// Execute the core's actions; open (and bind) local uni streams.
    fn actions(
        &mut self,
        cx: &mut Context<'_>,
        budget: &mut usize,
    ) -> Result<bool, TransportError> {
        let actions: Vec<Action> = self
            .shared
            .with(|i| std::iter::from_fn(|| i.conn.poll_action()).collect());
        let mut moved = !actions.is_empty();
        for a in actions {
            match a {
                Action::OpenUni(kind) => self.open_uni.push_back(kind),
                Action::ResetStream { stream, code } => {
                    if let Some(s) = self.sends.get_mut(&stream) {
                        s.reset(code.0);
                    }
                    self.drop_send(stream);
                    self.shared.with(|i| i.send_terminal(stream));
                }
                Action::StopSending { stream, code } => {
                    if let Some(mut r) = self.recvs.remove(&stream) {
                        r.stop(code.0);
                    }
                    self.shared.with(|i| i.retained.remove(&stream));
                }
                Action::FinishStream(id) => {
                    if let Some(s) = self.sends.get_mut(&id) {
                        s.finish();
                        self.finished.insert(id);
                    }
                    self.shared.with(|i| i.send_terminal(id));
                }
                Action::CloseConnection { code, .. } => {
                    self.conn.close(code.0);
                    self.shared.with(|i| {
                        i.fail(CloseCause::H3 {
                            code,
                            by_peer: false,
                        })
                    });
                    return Ok(true);
                }
            }
        }
        while *budget > 0 {
            let Some(&kind) = self.open_uni.front() else {
                break;
            };
            let Poll::Ready(s) = self.conn.poll_open_uni(cx) else {
                break;
            };
            let s = s?;
            *budget -= 1;
            moved = true;
            self.open_uni.pop_front();
            let id = s.id();
            self.sends.insert(id, s);
            // An Err is a state notification only (the core is closed).
            self.shared.with(|i| {
                let _ = i.conn.bind_uni(kind, id);
                i.push_ready(id, Dir::Send); // first `poll_stopped`
            });
        }
        Ok(moved)
    }

    /// Accept peer uni and bidi streams; a client opens streams for queued requests.
    fn accept(&mut self, cx: &mut Context<'_>, budget: &mut usize) -> Result<bool, TransportError> {
        let mut moved = self.open_requests(cx, budget)?;
        while *budget > 0 {
            let Poll::Ready(r) = self.conn.poll_accept_uni(cx) else {
                break;
            };
            let r = r?;
            *budget -= 1;
            moved = true;
            let id = r.id();
            self.recvs.insert(id, r);
            self.shared.with(|i| i.push_ready(id, Dir::Recv));
        }
        // Server: gated on `Service::poll_ready` (spec §3.1).
        while *budget > 0 && (self.role == Role::Client || self.accept_bidi) {
            let Poll::Ready(r) = self.conn.poll_accept_bidi(cx) else {
                break;
            };
            let (s, r) = r?;
            *budget -= 1;
            moved = true;
            let id = r.id();
            if self.role == Role::Client {
                // RFC 9114 §6.1: the core closes with H3_STREAM_CREATION_ERROR.
                let _ = self.shared.with(|i| i.conn.recv(id, &[], false));
                continue;
            }
            self.sends.insert(id, s);
            self.recvs.insert(id, r);
            self.shared.with(|i| {
                i.streams.insert(id, StreamState::new());
                i.push_ready(id, Dir::Recv);
                i.push_ready(id, Dir::Send);
            });
        }
        Ok(moved)
    }

    /// Client: open a stream for each queued request, oldest first, and queue its
    /// HEADERS; then spawn its body pipe (outside the lock: it calls the executor).
    fn open_requests(
        &mut self,
        cx: &mut Context<'_>,
        budget: &mut usize,
    ) -> Result<bool, TransportError> {
        let mut moved = false;
        while *budget > 0
            && self
                .shared
                .with(|i| i.opens.values().any(|o| o.done.is_none()))
        {
            let Poll::Ready(r) = self.conn.poll_open_bidi(cx) else {
                break;
            };
            let (mut s, mut r) = r?;
            *budget -= 1;
            moved = true;
            let id = s.id();
            let (sent, on_open) = self.shared.with(|i| {
                // `None` only if its `send_request` was dropped since the check.
                let Some(o) = i.opens.values_mut().find(|o| o.done.is_none()) else {
                    return (false, None);
                };
                let (fields, end, on_open) = o.req.take().expect("queued");
                let res = i.conn.send_headers(id, &fields.as_refs(), end);
                let sent = res.is_ok();
                o.done = Some(res.map(|()| id).map_err(|e| ErrorKind::Usage(e).into()));
                i.pending_wakers.extend(o.waker.take());
                if sent {
                    // The user is the request's `InFlight`.
                    let st = StreamState {
                        users: 1,
                        ..StreamState::new()
                    };
                    i.streams.insert(id, st);
                    i.push_ready(id, Dir::Recv);
                    i.push_ready(id, Dir::Send);
                }
                (sent, on_open)
            });
            if !sent {
                s.reset(H3Code::REQUEST_CANCELLED.0);
                r.stop(H3Code::REQUEST_CANCELLED.0);
                continue;
            }
            self.sends.insert(id, s);
            self.recvs.insert(id, r);
            if let Some(f) = on_open {
                assert_unlocked();
                f(id);
            }
        }
        Ok(moved)
    }

    /// Serve the tokens queued at the start of this call, round-robin: a stream that
    /// made progress re-queues itself behind the others.
    fn serve_ready(&mut self, budget: &mut usize) -> Result<bool, TransportError> {
        let mut moved = false;
        let n = self.shared.with(|i| i.ready.len());
        for _ in 0..n {
            if *budget == 0 {
                break;
            }
            let Some((id, dir)) = self.shared.with(Inner::pop_ready) else {
                break;
            };
            moved |= match dir {
                Dir::Send => {
                    self.write_blocked.remove(&id);
                    self.write_stream(id, budget)? | self.poll_stopped(id, budget)?
                }
                Dir::Recv => self.read_stream(id, budget)?,
            };
        }
        Ok(moved)
    }

    /// The transport failed: close the core and fail every handle (first cause wins).
    fn transport_failed(&mut self, e: TransportError) {
        self.shared.with(|i| {
            i.conn.transport_closed();
            i.fail(CloseCause::Transport(Arc::new(e)));
        });
    }
}

/// Drain the core's events into per-stream state. Handles may call it right after a
/// local `abort`, so both halves see the abort at once.
pub(crate) fn dispatch_events(i: &mut Inner) {
    while let Some(e) = i.conn.poll_event() {
        let retryable = e.retryable();
        match e {
            Event::PeerSettings => i.wake_conn(),
            Event::Headers {
                stream,
                block,
                kind,
            } => match kind {
                // A 1xx does not end discovery; `send_request` ignores it (§4.3).
                HeadersKind::Informational => i.conn.release(block),
                HeadersKind::Trailers => {
                    let map = i.conn.headers(block).map(|h| headers_from_block(&h));
                    i.conn.release(block);
                    match map {
                        Ok(Ok(map)) => {
                            if let Some(st) = i.streams.get_mut(&stream) {
                                st.recv.trailers = Some(map);
                                i.pending_wakers.extend(st.recv.waker.take());
                            }
                        }
                        // Not representable as `http` headers. Recorded now: when the same
                        // `recv` reached FIN, `Finished` is already queued and the core
                        // emits no `StreamAborted`. Err: the core is closed.
                        Ok(Err(code)) => {
                            if i.conn.abort(stream, code).is_ok() {
                                i.record_abort(stream, code);
                            }
                        }
                        Err(_) => {}
                    }
                }
                HeadersKind::Request | HeadersKind::Response => {
                    if let Some(st) = i.streams.get_mut(&stream) {
                        st.discovering = false;
                        st.head = Some(block);
                        i.pending_wakers.extend(st.recv.waker.take());
                        if kind == HeadersKind::Request {
                            i.incoming.push_back(stream);
                        }
                    } else {
                        i.conn.release(block);
                    }
                }
            },
            Event::Finished(stream) => {
                if let Some(st) = i.streams.get_mut(&stream) {
                    st.recv.eof = true;
                    i.pending_wakers.extend(st.recv.waker.take());
                }
                i.fire_cancels(stream);
            }
            Event::StreamAborted {
                stream,
                code,
                source,
            } => {
                let waiters = i.cap_waiters.len();
                i.discard_body(stream);
                if i.cap_waiters.len() < waiters {
                    // Budget freed outside any read: the driver must not rely on this
                    // round having moved.
                    i.wake_driver();
                }
                let e: Error = ErrorKind::StreamAborted {
                    code,
                    source,
                    retryable,
                }
                .into();
                if let Some(st) = i.streams.get_mut(&stream) {
                    st.recv.trailers = None;
                    st.recv.error = Some(e.clone());
                    // A whole-stream abort ends the send side too.
                    st.send.error = Some(e);
                    i.pending_wakers.extend(st.recv.waker.take());
                }
                i.send_terminal(stream);
            }
            Event::SendStopped { stream, code } => {
                if let Some(st) = i.streams.get_mut(&stream) {
                    st.send.error = Some(ErrorKind::SendStopped { code }.into());
                }
                i.send_terminal(stream);
            }
            // Client: requests above the cutoff are aborted by the core (retryable);
            // queued ones never start. (Server: a push ID, no effect.)
            Event::GoAway { .. } => {
                i.peer_goaway = true;
                i.fail_opens(&ErrorKind::Usage(UsageError::GoingAway).into());
            }
            // Uni stream types are dispatched by Tasks 8–9;
            // `Closed` is handled where the cause is known.
            _ => {}
        }
    }
}

impl<C: quic::Connection> Future for Driver<C> {
    type Output = Result<(), Error>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = &mut *self;
        // Before any transport poll, so a readiness wake during this poll reschedules us.
        this.shared
            .with(|i| i.driver_waker = Some(cx.waker().clone()));
        let mut budget = this.work_budget;
        loop {
            if let Some(r) = this.outcome() {
                return Poll::Ready(r);
            }
            let moved = match this.round(cx, &mut budget) {
                Ok(m) => m,
                Err(e) => {
                    this.transport_failed(e);
                    true
                }
            };
            if budget == 0 {
                if let Some(r) = this.outcome() {
                    return Poll::Ready(r);
                }
                cx.waker().wake_by_ref();
                return Poll::Pending;
            }
            if !moved {
                // Server graceful shutdown: the cutoff goes out after a full pass that
                // started after GOAWAY(2^62-4), so requests already received count as
                // processed (spec §4.2).
                if this.role == Role::Server
                    && !this.cutoff_sent
                    && this.shared.with(|i| i.graceful)
                {
                    this.cutoff_sent = true;
                    // Err: closed; the next outcome check returns.
                    let _ = this.shared.with(|i| i.conn.finish_shutdown());
                    continue;
                }
                return Poll::Pending;
            }
        }
    }
}

impl<C: quic::Connection> Drop for Driver<C> {
    fn drop(&mut self) {
        self.close(H3Code::NO_ERROR);
    }
}
