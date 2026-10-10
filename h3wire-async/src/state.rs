// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 mp0rta
//! Transport-independent state shared by the driver and every handle.
//!
//! Locking rule: the lock is never held while polling user code or a transport object.
//! Wakers collected under the lock (`pending_wakers`) are woken after it is released.

use crate::driver::datagram::{DgramState, Dgrams};
use crate::error::{Error, ErrorKind};
use crate::http_map::Fields;
use crate::quic::TransportError;
use crate::rt::{CancelToken, Owns};
use bytes::Bytes;
use h3wire::{AbortSource, Connection, H3Code, HeaderBlockId, StreamId};
use http::HeaderMap;
use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::sync::{Arc, Mutex, PoisonError, Weak};
use std::task::{Wake, Waker};

/// Which half of a stream a readiness token is for.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(crate) enum Dir {
    /// Writing, and `poll_stopped`.
    Send,
    /// Reading.
    Recv,
}

/// Why the connection ended.
#[derive(Clone, Debug)]
pub(crate) enum CloseCause {
    /// An HTTP/3 close: a connection error, or the driver going away.
    H3 { code: H3Code, by_peer: bool },
    /// The QUIC connection failed.
    Transport(Arc<TransportError>),
}

impl CloseCause {
    pub(crate) fn to_error(&self) -> Error {
        match self {
            CloseCause::H3 { code, by_peer } => ErrorKind::Closed {
                code: *code,
                by_peer: *by_peer,
            },
            CloseCause::Transport(e) => ErrorKind::Transport(e.clone()),
        }
        .into()
    }
}

/// Per-stream protocol state. The QUIC objects live in the driver.
#[derive(Debug)]
pub(crate) struct StreamState {
    /// Header discovery is running: the request (server) or final response (client)
    /// HEADERS has not been delivered yet.
    pub discovering: bool,
    /// The delivered request/response head, held until the application takes it. Whoever
    /// releases it must `mark_ready(id, Dir::Recv)`: a stream paused on it feeds again.
    pub head: Option<HeaderBlockId>,
    pub recv: RecvState,
    pub send: SendState,
    /// Executor tasks owning directions of this stream (spec §4.6).
    pub cancels: Vec<(Owns, CancelToken)>,
    /// Handles that still read this entry: a client `InFlight`, a `RecvBody`, a server
    /// per-request task. At 0, with both directions terminal, the entry is reaped.
    pub users: usize,
    /// Server: the final response HEADERS were queued (1xx not counted), or the peer
    /// stopped the response first, so there is nothing to send.
    pub final_sent: bool,
    /// Server: the response-body pipe failed (a body error, or a panic during it).
    pub task_failed: bool,
    /// Server: the request carries `expect: 100-continue`, not answered yet.
    pub expect_continue: bool,
    /// Server: the task ended with its body abandoned before the end while the response
    /// was still going out. The `H3_REQUEST_CANCELLED` abort waits for the send side to
    /// end, so a complete response is not reset (only reading stops, RFC 9114 §4.1).
    pub abort_after_send: bool,
    /// The transport delivered something on the stream (bytes, FIN or a reset). Server: a
    /// stream never seen is a hole graceful shutdown does not wait for (spec §4.2).
    pub seen: bool,
    /// The upgrade of a CONNECT (spec §4.5).
    pub up: Up,
    /// HTTP datagrams (spec §3.4).
    pub dgram: DgramState,
}

/// Where a CONNECT stream's upgrade stands (spec §4.5). The `Claim` holding it counts one
/// of the entry's `users`.
#[derive(Debug, Default)]
pub(crate) enum Up {
    /// No tunnel pending: not a CONNECT, the claim is not taken (server), or it is over.
    #[default]
    None,
    /// Server: an `OnUpgrade` holds the claim and no final response went out yet. The
    /// claim is the reader; its waker is `recv.waker`.
    Claimed,
    /// A 2xx went out (server) or came in (client): the tunnel can be taken.
    Active,
    /// The tunnel was taken; kept until the entry is reaped.
    Tunnel,
    /// Server: the final response settled a claim without a tunnel; its `OnUpgrade`
    /// resolves to this.
    Failed(Error),
}

impl StreamState {
    pub(crate) fn new() -> Self {
        StreamState {
            discovering: true,
            head: None,
            recv: RecvState::default(),
            send: SendState::default(),
            cancels: Vec::new(),
            users: 0,
            final_sent: false,
            task_failed: false,
            expect_continue: false,
            abort_after_send: false,
            seen: false,
            up: Up::None,
            dgram: DgramState::default(),
        }
    }

    /// The receive side failed with `e`: recorded for its reader and the datagram
    /// handle, which are woken.
    pub(crate) fn fail_recv(&mut self, e: Error, wakers: &mut Vec<Waker>) {
        self.recv.trailers = None;
        self.recv.error = Some(e.clone());
        self.dgram.error = Some(e);
        wakers.extend(self.recv.waker.take());
        wakers.extend(self.dgram.waker.take());
    }

    pub(crate) fn recv_terminal(&self) -> bool {
        self.recv.eof || self.recv.error.is_some()
    }

    /// The receive direction is terminal for `Owns::Both` (spec §4.6), when any of:
    /// - the reader consumed the end: FIN arrived, the queue is drained, the trailers taken;
    /// - no reader remains: its `RecvBody` (or, after a claim, the claim or `TunnelRecv`)
    ///   was dropped (`abandoned`; the queue was discarded and later body bytes are not
    ///   queued), or dropped at EOF (the rest was discarded), or a claim settled without
    ///   a tunnel was dropped (`drain`: read on and discarded);
    /// - the stream was reset, errored or aborted.
    ///
    /// So a Service still reading the tail of a finished request is not cancelled (it may
    /// be cut at its next `Pending` after the last chunk), while one that dropped its body
    /// and waits on something unrelated is.
    fn recv_consumed(&self) -> bool {
        let r = &self.recv;
        r.error.is_some()
            || r.abandoned
            || r.drain
            || (r.eof && r.queue.is_empty() && r.trailers.is_none())
    }
}

/// How the user side of a send ended.
#[derive(Debug)]
pub(crate) enum End {
    /// FIN only.
    Fin,
    /// Trailers, sent as HEADERS with `fin = true`.
    Trailers(Fields),
}

/// The send side of a request stream (spec §3.3).
#[derive(Debug, Default)]
pub(crate) struct SendState {
    /// Admitted payloads, oldest first. The head stays queued until its DATA frame is
    /// fully written.
    pub queue: VecDeque<Bytes>,
    pub queued: usize,
    /// Set by the producer once it ended; taken by the driver when the queue is empty.
    pub end: Option<End>,
    /// The producer, waiting for admission.
    pub waker: Option<Waker>,
    /// Finished, stopped, reset or aborted: the producer stops.
    pub done: bool,
    /// The transport acknowledged everything (`poll_stopped` returned `None`).
    pub acked: bool,
    /// Why the send side ended, if not by our FIN: `SendStopped` or `StreamAborted`.
    pub error: Option<Error>,
}

/// The receive side of a request stream (spec §3.2, §4.4).
#[derive(Debug, Default)]
pub(crate) struct RecvState {
    /// Parsed body bytes, oldest first. Bytes of a demand read sit at the front.
    pub queue: VecDeque<Bytes>,
    pub queued: usize,
    /// The part of `queued` counted against the connection's read-ahead cap.
    pub speculative: usize,
    /// A demand reservation: `Some(n)` with `n` bytes of it still queued; while the queue
    /// is empty, the demand read is in flight.
    pub reservation: Option<usize>,
    /// The core finished the receive side (`Event::Finished`), or the error was yielded.
    pub eof: bool,
    pub trailers: Option<HeaderMap>,
    pub error: Option<Error>,
    /// Receive ownership moved to an upgrade claim or tunnel: the `RecvBody` is an ended
    /// body that never aborts and is not the reader; queued bytes stay for the tunnel.
    pub detached: bool,
    pub waker: Option<Waker>,
    /// A consumer found the queue empty and has not been handed a frame since.
    pub consumer_waiting: bool,
    /// Task 7: a live per-request task owns the body. Dropping it then discards the queue
    /// and sets `abandoned`; the task commits the abort when it ends.
    pub task_owned: bool,
    pub abandoned: bool,
    /// The reader is gone without an abort (a claim settled without a tunnel): body bytes
    /// are dropped and the stream is read, as on demand, until its end.
    pub drain: bool,
}

/// Spawns a client request's body pipe once its stream exists.
pub(crate) type OnOpen = Box<dyn FnOnce(StreamId) + Send>;

/// A client request waiting for the driver to open its stream (spec §4.3); queued while
/// `done` is `None`. Only its `send_request` removes it, outside the lock: it may own the
/// user's body.
pub(crate) struct Open {
    /// The HEADERS, whether they end the stream, and the body pipe. Taken by the driver.
    pub req: Option<(Fields, bool, Option<OnOpen>)>,
    /// `RegisterDatagrams`: the stream starts with datagram semantics registered.
    pub datagrams: bool,
    pub done: Option<Result<StreamId, Error>>,
    pub waker: Option<Waker>,
}

pub(crate) struct Inner {
    pub conn: Connection,
    /// Client requests by ticket, oldest first.
    pub opens: BTreeMap<u64, Open>,
    pub next_open: u64,
    /// Client: the peer sent GOAWAY, so no new request may start.
    pub peer_goaway: bool,
    /// Graceful shutdown started: no new requests; the driver closes once drained.
    pub graceful: bool,
    pub streams: HashMap<StreamId, StreamState>,
    /// Server: streams whose request head was delivered, waiting for dispatch.
    pub incoming: VecDeque<StreamId>,
    /// Readiness tokens pushed by transport wakers, deduplicated by `ready_set`.
    pub ready: VecDeque<(StreamId, Dir)>,
    pub ready_set: HashSet<(StreamId, Dir)>,
    pub driver_waker: Option<Waker>,
    /// Woken by `Shared::with` after the lock is released.
    pub pending_wakers: Vec<Waker>,
    /// Connection-level waiters (`ConnInfo::settings`): woken on SETTINGS and on close.
    pub conn_wakers: Vec<Waker>,
    pub close: Option<CloseCause>,
    /// Raw request-stream bytes read but not fed to the core yet, with FIN (§3.2).
    pub retained: HashMap<StreamId, (Bytes, bool)>,
    /// Speculative (read-ahead) body bytes queued on every stream; capped by `C`.
    pub speculative: usize,
    /// Streams with read-ahead room that the connection cap holds back.
    pub cap_waiters: HashSet<StreamId>,
    /// Per-stream send-queue capacity `S`.
    pub send_capacity: usize,
    /// HTTP datagram queues and limits (spec §3.4).
    pub dgram: Dgrams,
    /// Streams whose `Action::FinishStream` the driver executed (property-test oracle).
    #[cfg(test)]
    pub fin_actions: HashSet<StreamId>,
}

impl Inner {
    /// Queue a readiness token and wake the driver (transport wakers, handles).
    pub(crate) fn mark_ready(&mut self, id: StreamId, dir: Dir) {
        self.push_ready(id, dir);
        self.wake_driver();
    }

    /// Queue a readiness token without waking: for the driver itself, which serves it in
    /// its next round or, out of budget, wakes itself.
    pub(crate) fn push_ready(&mut self, id: StreamId, dir: Dir) {
        if self.ready_set.insert((id, dir)) {
            self.ready.push_back((id, dir));
        }
    }

    pub(crate) fn pop_ready(&mut self) -> Option<(StreamId, Dir)> {
        let t = self.ready.pop_front()?;
        self.ready_set.remove(&t);
        Some(t)
    }

    pub(crate) fn wake_driver(&mut self) {
        self.pending_wakers.extend(self.driver_waker.take());
    }

    /// Register a connection-level waiter (deduplicated).
    pub(crate) fn wait_conn(&mut self, w: &Waker) {
        if !self.conn_wakers.iter().any(|x| x.will_wake(w)) {
            self.conn_wakers.push(w.clone());
        }
    }

    pub(crate) fn wake_conn(&mut self) {
        self.pending_wakers.append(&mut self.conn_wakers);
    }

    /// The connection is over: record the first cause and wake every handle.
    pub(crate) fn fail(&mut self, cause: CloseCause) {
        let e = self.close.get_or_insert(cause).to_error();
        self.fail_opens(&e);
        self.wake_conn();
        for st in self.streams.values_mut() {
            self.pending_wakers.extend(st.recv.waker.take());
            self.pending_wakers.extend(st.send.waker.take());
            self.pending_wakers.extend(st.dgram.waker.take());
            for (_, t) in st.cancels.drain(..) {
                self.pending_wakers.extend(t.fire());
            }
        }
    }

    /// Fail every queued client request with `e`.
    pub(crate) fn fail_opens(&mut self, e: &Error) {
        for o in self.opens.values_mut().filter(|o| o.done.is_none()) {
            o.done = Some(Err(e.clone()));
            self.pending_wakers.extend(o.waker.take());
        }
    }

    /// A producer may queue on `id` (spec §3.3): fewer than `S` bytes queued.
    pub(crate) fn admit(&self, id: StreamId) -> bool {
        self.streams
            .get(&id)
            .is_some_and(|st| st.send.queued < self.send_capacity)
    }

    /// A token for a task owning `owns` of `id`. It fires at once if those directions
    /// are already terminal, the stream is gone or the connection is closed.
    pub(crate) fn cancel_token(&mut self, id: StreamId, owns: Owns) -> CancelToken {
        let t = CancelToken::default();
        match self.streams.get_mut(&id) {
            Some(st) if self.close.is_none() => st.cancels.push((owns, t.clone())),
            _ => {
                t.fire();
            }
        }
        self.fire_cancels(id);
        t
    }

    /// Fire the tokens of `id` whose directions are now terminal, then reap the entry if
    /// nothing needs it any more.
    pub(crate) fn fire_cancels(&mut self, id: StreamId) {
        let Some(st) = self.streams.get_mut(&id) else {
            return;
        };
        let (send, both) = (st.send.done, st.send.done && st.recv_consumed());
        st.cancels.retain(|(owns, t)| {
            let fire = match owns {
                Owns::Both => both,
                Owns::Send => send,
            };
            if fire {
                self.pending_wakers.extend(t.fire());
            }
            !fire
        });
        self.reap(id);
    }

    /// A handle of `id` is gone (see `StreamState::users`).
    pub(crate) fn release_user(&mut self, id: StreamId) {
        if let Some(st) = self.streams.get_mut(&id) {
            st.users -= 1;
        }
        self.fire_cancels(id);
    }

    /// Remove `id`'s entry once no handle reads it and both directions are terminal,
    /// with everything it still holds: queued body bytes (their budget goes back), an
    /// undelivered head, retained raw bytes. The driver's transport halves are separate
    /// (a send half stays until acknowledged or reset).
    pub(crate) fn reap(&mut self, id: StreamId) {
        if !self
            .streams
            .get(&id)
            .is_some_and(|st| st.users == 0 && st.send.done && st.recv_terminal())
        {
            return;
        }
        let waiters = self.cap_waiters.len();
        self.discard_body(id);
        if self.cap_waiters.len() < waiters {
            self.wake_driver();
        }
        let st = self.streams.remove(&id).expect("checked above");
        if let Some(b) = st.head {
            self.conn.release(b);
        }
        self.retained.remove(&id);
        self.cap_waiters.remove(&id);
        self.dgram.take_pending(id); // the request ended undecided
    }

    /// The send side of `id` is over (finished, stopped, reset or aborted): drop what is
    /// queued, release the producer, fire the tokens.
    pub(crate) fn send_terminal(&mut self, id: StreamId) {
        let mut abort = false;
        if let Some(st) = self.streams.get_mut(&id) {
            self.pending_wakers.extend(st.send.waker.take());
            st.send = SendState {
                done: true,
                acked: st.send.acked,
                error: st.send.error.take(),
                ..SendState::default()
            };
            abort = std::mem::take(&mut st.abort_after_send) && !st.recv_terminal();
        }
        if abort {
            self.abort_local(id, H3Code::REQUEST_CANCELLED);
        }
        self.fire_cancels(id);
    }

    /// Abort `id` locally with `code` in both directions (a no-op once it is over) and
    /// record it in the per-stream state at once. The core emits `StreamAborted` only if
    /// the stream had no terminal event yet; after `Finished` (the peer's FIN was read) it
    /// emits nothing, so a send side still open is ended here with
    /// `StreamAborted { code, Local }` (and likewise a receive side not ended yet).
    /// Wakes the driver for the core's actions.
    pub(crate) fn abort_local(&mut self, id: StreamId, code: H3Code) {
        // Err: the connection is closed, the stream unknown or the code refused.
        if self.conn.abort(id, code).is_err() {
            return;
        }
        crate::driver::dispatch_events(self);
        self.record_abort(id, code);
    }

    /// After a successful local `conn.abort(id, code)`: end, as `StreamAborted { code,
    /// Local }`, each direction of `id` the core's own event has not ended (it emits none
    /// after `Finished`). Inside `dispatch_events` call it right after the abort, before
    /// a queued `Finished` is applied, so the reader sees the error, not a clean EOF.
    pub(crate) fn record_abort(&mut self, id: StreamId, code: H3Code) {
        self.wake_driver();
        let Some(st) = self.streams.get_mut(&id) else {
            return;
        };
        let e: Error = ErrorKind::StreamAborted {
            code,
            source: AbortSource::Local,
            retryable: false,
        }
        .into();
        let (recv, send) = (!st.recv_terminal(), !st.send.done);
        if recv {
            st.fail_recv(e.clone(), &mut self.pending_wakers);
            self.discard_body(id);
        }
        if send {
            if let Some(st) = self.streams.get_mut(&id) {
                st.send.error = Some(e);
            }
            self.send_terminal(id);
        } else if recv {
            self.fire_cancels(id);
        }
    }

    /// The reader of `id`'s receive side (a `RecvBody`, a claim or a `TunnelRecv`) is
    /// gone before reading to the end. If the direction ended (FIN, error, close) what is
    /// left goes and it counts as consumed. Otherwise the stream is aborted with
    /// `H3_REQUEST_CANCELLED` in both directions (no receive-only abort), or, while a
    /// per-request task owns it, the queue goes, `abandoned` is set and the task commits
    /// the abort when it ends. After a server task ended with a complete response (not a
    /// tunnel) still being written, the same holds and the abort waits for the response's
    /// end, as `Commit` does (RFC 9114 §4.1).
    pub(crate) fn drop_reader(&mut self, id: StreamId) {
        let closed = self.close.is_some();
        let Some(st) = self.streams.get_mut(&id) else {
            return;
        };
        let responding = st.final_sent && matches!(st.up, Up::None) && !st.send.done;
        let r = &mut st.recv;
        r.waker = None;
        r.consumer_waiting = false;
        if r.eof || r.error.is_some() || closed {
            r.trailers = None;
            self.discard_body(id);
        } else if r.task_owned || responding {
            r.abandoned = true;
            st.abort_after_send |= !r.task_owned;
            self.discard_body(id);
        } else {
            self.abort_local(id, H3Code::REQUEST_CANCELLED);
        }
        self.wake_driver();
    }

    /// The claim of `id`, settled without a tunnel (a non-2xx), is gone: it was the
    /// reader of the detached body. The request is not aborted (a client finishes a
    /// rejected CONNECT with FIN): what is queued goes, and the rest is read and dropped
    /// until the end, also without read-ahead.
    pub(crate) fn drain_reader(&mut self, id: StreamId) {
        let closed = self.close.is_some();
        let Some(r) = self.streams.get_mut(&id).map(|s| &mut s.recv) else {
            return;
        };
        r.waker = None;
        r.trailers = None;
        let live = !(r.eof || r.error.is_some() || closed);
        if live {
            r.drain = true;
            r.consumer_waiting = true; // demand reads, never handed a frame
        }
        self.discard_body(id);
        if live {
            self.mark_ready(id, Dir::Recv);
        }
    }

    /// Queue a body slice of `id`; `demand` counts it against the stream's reservation.
    /// Bytes of an abandoned or drained body (no reader) are dropped.
    pub(crate) fn queue_body(&mut self, id: StreamId, b: Bytes, demand: bool) {
        let Some(st) = self
            .streams
            .get_mut(&id)
            .filter(|s| !b.is_empty() && !s.recv.abandoned && !s.recv.drain)
        else {
            return;
        };
        let r = &mut st.recv;
        r.queued += b.len();
        match (demand, &mut r.reservation) {
            (true, Some(n)) => *n += b.len(),
            _ => {
                r.speculative += b.len();
                self.speculative += b.len();
            }
        }
        r.queue.push_back(b);
        self.pending_wakers.extend(r.waker.take());
    }

    /// Pop the next body chunk of `id`, giving its budget back. Does not wake the driver.
    pub(crate) fn pop_body(&mut self, id: StreamId) -> Option<Bytes> {
        let r = &mut self.streams.get_mut(&id)?.recv;
        let b = r.queue.pop_front()?;
        r.queued -= b.len();
        match r.reservation {
            // Demand bytes are at the front, and a chunk is never split between tiers.
            Some(n) if n > 0 => r.reservation = (n > b.len()).then(|| n - b.len()),
            _ => {
                r.speculative -= b.len();
                self.speculative -= b.len();
                for w in std::mem::take(&mut self.cap_waiters) {
                    self.push_ready(w, Dir::Recv);
                }
            }
        }
        Some(b)
    }

    /// Drop everything queued on `id` and its reservation. Does not wake the driver.
    pub(crate) fn discard_body(&mut self, id: StreamId) {
        while self.pop_body(id).is_some() {}
        if let Some(st) = self.streams.get_mut(&id) {
            st.recv.reservation = None;
        }
    }
}

/// `Arc<Mutex<Inner>>`; every handle holds one of these plus a `StreamId`.
#[derive(Clone)]
pub(crate) struct Shared(pub(crate) Arc<Mutex<Inner>>);

#[cfg(debug_assertions)]
thread_local! {
    static IN_LOCK: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// Sets `IN_LOCK` for its lifetime (debug builds only).
struct LockFlag;

impl LockFlag {
    fn set() -> Self {
        #[cfg(debug_assertions)]
        IN_LOCK.with(|f| f.set(true));
        LockFlag
    }
}

impl Drop for LockFlag {
    fn drop(&mut self) {
        #[cfg(debug_assertions)]
        IN_LOCK.with(|f| f.set(false));
    }
}

/// Call right before polling user code: panics in debug builds if the lock is held.
pub(crate) fn assert_unlocked() {
    #[cfg(debug_assertions)]
    IN_LOCK.with(|f| assert!(!f.get(), "user code polled under lock"));
}

impl Shared {
    pub(crate) fn new(conn: Connection) -> Self {
        Shared(Arc::new(Mutex::new(Inner {
            conn,
            opens: BTreeMap::new(),
            next_open: 0,
            peer_goaway: false,
            graceful: false,
            streams: HashMap::new(),
            incoming: VecDeque::new(),
            ready: VecDeque::new(),
            ready_set: HashSet::new(),
            driver_waker: None,
            pending_wakers: Vec::new(),
            conn_wakers: Vec::new(),
            close: None,
            retained: HashMap::new(),
            speculative: 0,
            cap_waiters: HashSet::new(),
            send_capacity: 64 * 1024,
            dgram: Dgrams::default(),
            #[cfg(test)]
            fin_actions: HashSet::new(),
        })))
    }

    /// Lock, run `f`, take `pending_wakers`, unlock, then wake them.
    pub(crate) fn with<R>(&self, f: impl FnOnce(&mut Inner) -> R) -> R {
        let (r, wakers) = {
            let mut g = self.0.lock().unwrap_or_else(PoisonError::into_inner);
            let _flag = LockFlag::set();
            let r = f(&mut g);
            (r, std::mem::take(&mut g.pending_wakers))
        };
        for w in wakers {
            w.wake();
        }
        r
    }

    /// A transport waker for one direction of `id`: pushes `(id, dir)` and wakes the
    /// driver. Holds the state weakly, so a transport keeping it alive leaks nothing.
    // ponytail: one Arc per transport poll; cache per (id, dir) if it shows in profiles.
    pub(crate) fn ready_waker(&self, id: StreamId, dir: Dir) -> Waker {
        Waker::from(Arc::new(ReadyWaker {
            inner: Arc::downgrade(&self.0),
            id,
            dir,
        }))
    }
}

struct ReadyWaker {
    inner: Weak<Mutex<Inner>>,
    id: StreamId,
    dir: Dir,
}

impl Wake for ReadyWaker {
    fn wake(self: Arc<Self>) {
        self.wake_by_ref();
    }

    fn wake_by_ref(self: &Arc<Self>) {
        if let Some(inner) = self.inner.upgrade() {
            Shared(inner).with(|i| i.mark_ready(self.id, self.dir));
        }
    }
}
