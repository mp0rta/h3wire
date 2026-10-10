// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 mp0rta
//! The connection driver: owns the QUIC objects and runs the core's driving loop.
//!
//! One `poll` runs rounds until nothing moves or the work budget (transport operations
//! that returned `Ready`) is spent; then it wakes itself and yields. A round:
//! 1. executes core actions and opens local uni streams;
//! 2. accepts peer streams;
//! 3. writes the core's sendable streams;
//! 4. serves readiness tokens round-robin (reads, unblocked writes, `poll_stopped`);
//! 5. dispatches core events (also right after each `recv`, see `recv.rs`);
//! 6. stops once the connection is closed.
//!
//! The shared lock is never held across a transport call: a transport may invoke a
//! readiness waker synchronously, and that waker takes the lock.

mod recv;
mod send;

use crate::builder::Builder;
use crate::error::Error;
use crate::quic::{self, RecvStream, SendStream, TransportError};
use crate::state::{CloseCause, Dir, Inner, Shared, StreamState};
use bytes::Bytes;
use h3wire::{Action, Event, H3Code, HeadersKind, Role, StreamId, UniKind};
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
    /// Raw bytes read but not fed to the core yet, with FIN.
    retained: HashMap<StreamId, (Bytes, bool)>,
    /// `Action::OpenUni` kinds waiting for `poll_open_uni`.
    open_uni: VecDeque<UniKind>,
    /// Streams whose last write pended: skipped until their `Send` token fires.
    write_blocked: HashSet<StreamId>,
    work_budget: usize,
    /// Header-discovery read size: `max_encoded_field_section_size + 16`.
    discovery_len: usize,
}

// No field is ever pinned.
impl<C: quic::Connection> Unpin for Driver<C> {}

impl<C: quic::Connection> Driver<C> {
    pub(crate) fn new(conn: C, role: Role, b: &Builder) -> Self {
        let config = b.core_config(conn.max_datagram_size().is_some());
        let discovery_len = config.max_encoded_field_section_size.saturating_add(16);
        Driver {
            conn,
            shared: Shared::new(h3wire::Connection::new(role, config)),
            role,
            sends: HashMap::new(),
            recvs: HashMap::new(),
            retained: HashMap::new(),
            open_uni: VecDeque::new(),
            write_blocked: HashSet::new(),
            work_budget: b.work_budget.max(1),
            discovery_len,
        }
    }

    pub(crate) fn shared(&self) -> Shared {
        self.shared.clone()
    }

    /// `Some` once the connection is closed: `Ok` for a local `H3_NO_ERROR` close.
    fn outcome(&self) -> Option<Result<(), Error>> {
        self.shared.with(|i| {
            i.close.as_ref().map(|c| match c {
                CloseCause::H3 { code, .. } if *code == H3Code::NO_ERROR => Ok(()),
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
        Ok(moved)
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
                    if let Some(mut s) = self.sends.remove(&stream) {
                        s.reset(code.0);
                    }
                    self.write_blocked.remove(&stream);
                }
                Action::StopSending { stream, code } => {
                    if let Some(mut r) = self.recvs.remove(&stream) {
                        r.stop(code.0);
                    }
                    self.retained.remove(&stream);
                }
                Action::FinishStream(s) => {
                    if let Some(s) = self.sends.get_mut(&s) {
                        s.finish();
                    }
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

    /// Accept peer uni streams, and request streams on a server.
    fn accept(&mut self, cx: &mut Context<'_>, budget: &mut usize) -> Result<bool, TransportError> {
        let mut moved = false;
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
        // Task 7 gates this on `Service::poll_ready`.
        while self.role == Role::Server && *budget > 0 {
            let Poll::Ready(r) = self.conn.poll_accept_bidi(cx) else {
                break;
            };
            let (s, r) = r?;
            *budget -= 1;
            moved = true;
            let id = r.id();
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

/// Drain the core's events into per-stream state.
fn dispatch_events(i: &mut Inner) {
    while let Some(e) = i.conn.poll_event() {
        match e {
            Event::PeerSettings => i.wake_conn(),
            Event::Headers {
                stream,
                block,
                kind,
            } => match kind {
                // Task 4 delivers 1xx and trailers; a 1xx does not end discovery.
                HeadersKind::Informational | HeadersKind::Trailers => i.conn.release(block),
                HeadersKind::Request | HeadersKind::Response => {
                    if let Some(st) = i.streams.get_mut(&stream) {
                        st.discovering = false;
                        st.head = Some(block);
                    } else {
                        i.conn.release(block);
                    }
                }
            },
            // Terminal stream events, GOAWAY and uni stream types are dispatched by
            // Tasks 4–9; `Closed` is handled where the cause is known.
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
                return Poll::Pending;
            }
        }
    }
}

impl<C: quic::Connection> Drop for Driver<C> {
    fn drop(&mut self) {
        if self.shared.with(|i| i.close.is_some()) {
            return;
        }
        self.conn.close(H3Code::NO_ERROR.0);
        self.shared.with(|i| {
            i.conn.transport_closed();
            i.fail(CloseCause::H3 {
                code: H3Code::NO_ERROR,
                by_peer: false,
            });
        });
    }
}
