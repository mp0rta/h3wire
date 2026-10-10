// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 mp0rta
//! Transport-independent state shared by the driver and every handle.
//!
//! Locking rule: the lock is never held while polling user code or a transport object.
//! Wakers collected under the lock (`pending_wakers`) are woken after it is released.

use crate::error::{Error, ErrorKind};
use crate::quic::TransportError;
use h3wire::{Connection, H3Code, HeaderBlockId, StreamId};
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
/// Task 4 adds `recv` (body queue, tiers, waker), Task 5 adds `send` (queue, admission,
/// waker) and the cancel tokens.
#[derive(Debug)]
pub(crate) struct StreamState {
    /// Header discovery is running: the request (server) or final response (client)
    /// HEADERS has not been delivered yet.
    pub discovering: bool,
    /// The delivered request/response head, held until the application takes it.
    pub head: Option<HeaderBlockId>,
}

impl StreamState {
    pub(crate) fn new() -> Self {
        StreamState {
            discovering: true,
            head: None,
        }
    }
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
        // Tasks 4–9 also wake every per-stream waker here.
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
