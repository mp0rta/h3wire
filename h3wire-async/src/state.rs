// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 mp0rta
//! Transport-independent state shared by the driver and every handle.
//!
//! Locking rule: the lock is never held while polling user code or a transport object.
//! Wakers collected under the lock (`pending_wakers`) are woken after it is released.

use crate::error::{Error, ErrorKind};
use crate::quic::TransportError;
use bytes::Bytes;
use h3wire::{Connection, H3Code, HeaderBlockId, StreamId};
use http::HeaderMap;
use std::collections::{HashMap, HashSet, VecDeque};
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
///
/// Task 5 adds `send` (queue, admission, waker) and the cancel tokens.
#[derive(Debug)]
pub(crate) struct StreamState {
    /// Header discovery is running: the request (server) or final response (client)
    /// HEADERS has not been delivered yet.
    pub discovering: bool,
    /// The delivered request/response head, held until the application takes it. Whoever
    /// releases it must `mark_ready(id, Dir::Recv)`: a stream paused on it feeds again.
    pub head: Option<HeaderBlockId>,
    pub recv: RecvState,
}

impl StreamState {
    pub(crate) fn new() -> Self {
        StreamState {
            discovering: true,
            head: None,
            recv: RecvState::default(),
        }
    }
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
    /// Receive ownership moved to a tunnel (Task 8): the `RecvBody` is an ended body that
    /// never aborts; queued bytes stay for the tunnel.
    pub detached: bool,
    pub waker: Option<Waker>,
    /// A consumer found the queue empty and has not been handed a frame since.
    pub consumer_waiting: bool,
    /// Task 7: a live per-request task owns the body. Dropping it then only sets
    /// `abandoned`; the task commits the abort when it ends.
    pub task_owned: bool,
    pub abandoned: bool,
}

pub(crate) struct Inner {
    pub conn: Connection,
    pub streams: HashMap<StreamId, StreamState>,
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
        self.close.get_or_insert(cause);
        self.wake_conn();
        for st in self.streams.values_mut() {
            self.pending_wakers.extend(st.recv.waker.take());
        }
    }

    /// Queue a body slice of `id`; `demand` counts it against the stream's reservation.
    pub(crate) fn queue_body(&mut self, id: StreamId, b: Bytes, demand: bool) {
        let Some(st) = self.streams.get_mut(&id).filter(|_| !b.is_empty()) else {
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
            streams: HashMap::new(),
            ready: VecDeque::new(),
            ready_set: HashSet::new(),
            driver_waker: None,
            pending_wakers: Vec::new(),
            conn_wakers: Vec::new(),
            close: None,
            retained: HashMap::new(),
            speculative: 0,
            cap_waiters: HashSet::new(),
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
