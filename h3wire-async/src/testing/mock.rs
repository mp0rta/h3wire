// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 mp0rta
//! An in-memory QUIC transport with fault-injection knobs. Std only.

use crate::quic::{
    Connection, ReadError, RecvStream, SendDatagramError, SendStream, TransportError, WriteError,
    Written,
};
use bytes::{Buf, Bytes, BytesMut};
use h3wire::StreamId;
use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::{Arc, Mutex, MutexGuard};
use std::task::{Context, Poll, Waker};

/// Which end of a [`MockNet`] pair.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Side {
    /// The first connection of the pair; opens client-initiated stream ids.
    Client,
    /// The second connection of the pair.
    Server,
}

impl Side {
    fn idx(self) -> usize {
        self as usize
    }
    fn peer(self) -> Side {
        match self {
            Side::Client => Side::Server,
            Side::Server => Side::Client,
        }
    }
}

/// When `poll_stopped` reports completion.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Ack {
    /// As soon as FIN and all bytes have been read.
    Auto,
    /// Only after [`MockNet::ack_all`].
    Manual,
}

/// One observable transport event.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MockObs {
    /// Bytes accepted by a write.
    Write {
        side: Side,
        stream: StreamId,
        len: usize,
    },
    /// FIN queued.
    Fin { side: Side, stream: StreamId },
    /// RESET_STREAM sent.
    Reset {
        side: Side,
        stream: StreamId,
        code: u64,
    },
    /// STOP_SENDING sent.
    Stop {
        side: Side,
        stream: StreamId,
        code: u64,
    },
    /// A datagram handed to `send_datagram` (also when injected loss drops it).
    Datagram { side: Side, len: usize },
    /// The connection was closed with an application code.
    Close { side: Side, code: u64 },
}

/// One direction of a stream, keyed by (stream, writing side).
#[derive(Default)]
struct Dir {
    buf: VecDeque<Bytes>,
    fin: bool,
    eof_read: bool,
    acked: bool,
    reset: Option<u64>,
    stop: Option<u64>,
    read_w: Option<Waker>,
    write_w: Option<Waker>,
    stopped_w: Option<Waker>,
}

impl Dir {
    fn terminal(&self) -> bool {
        self.reset.is_some() || self.stop.is_some() || self.eof_read
    }
}

struct SideState {
    next_bidi: u64,
    next_uni: u64,
    accept_bidi: VecDeque<StreamId>,
    accept_uni: VecDeque<StreamId>,
    accept_bidi_w: Option<Waker>,
    accept_uni_w: Option<Waker>,
    open_w: Option<Waker>,
    dgrams: VecDeque<Bytes>,
    dgram_w: Option<Waker>,
    max_dgram: Option<usize>,
    credit: usize,
    used: usize,
    /// `Some`: the transport is dead, with the peer's close codes (if the peer closed).
    dead: Option<Dead>,
    closed: Option<u64>,
}

impl SideState {
    fn new() -> Self {
        SideState {
            next_bidi: 0,
            next_uni: 0,
            accept_bidi: VecDeque::new(),
            accept_uni: VecDeque::new(),
            accept_bidi_w: None,
            accept_uni_w: None,
            open_w: None,
            dgrams: VecDeque::new(),
            dgram_w: None,
            max_dgram: Some(1200),
            credit: usize::MAX,
            used: 0,
            dead: None,
            closed: None,
        }
    }
}

struct Net {
    dirs: HashMap<(StreamId, Side), Dir>,
    blocked: HashSet<(Side, StreamId)>,
    credit_returned: HashSet<StreamId>,
    sides: [SideState; 2],
    max_write: Option<usize>,
    ack_manual: bool,
    loss: bool,
    reorder: bool,
    early_wake: bool,
    coalesce: bool,
    trace: Vec<MockObs>,
    /// One-shot hooks run right after an accepted write by (side, stream).
    write_hooks: HashMap<(Side, StreamId), Box<dyn FnOnce() + Send>>,
}

fn register(slot: &mut Option<Waker>, cx: &Context<'_>) {
    *slot = Some(cx.waker().clone());
}

fn wake(slot: &mut Option<Waker>) {
    if let Some(w) = slot.take() {
        w.wake();
    }
}

/// How a dead transport died: the codes of the peer's close, if it closed.
#[derive(Clone, Copy, Default)]
struct Dead {
    app: Option<u64>,
    transport: Option<u64>,
}

fn dead_err(d: Dead) -> TransportError {
    TransportError {
        peer_app_code: d.app,
        peer_transport_code: d.transport,
        source: "mock transport is dead".into(),
    }
}

impl Net {
    fn dir(&mut self, id: StreamId, writer: Side) -> &mut Dir {
        self.dirs
            .get_mut(&(id, writer))
            .expect("unknown mock stream")
    }

    /// A poll is about to return `Pending` after registering its waker.
    fn pending<T>(&self, cx: &Context<'_>) -> Poll<T> {
        if self.early_wake {
            cx.waker().wake_by_ref();
        }
        Poll::Pending
    }

    fn wake_all(&mut self) {
        for d in self.dirs.values_mut() {
            wake(&mut d.read_w);
            wake(&mut d.write_w);
            wake(&mut d.stopped_w);
        }
        for s in &mut self.sides {
            wake(&mut s.accept_bidi_w);
            wake(&mut s.accept_uni_w);
            wake(&mut s.open_w);
            wake(&mut s.dgram_w);
        }
    }

    fn create_stream(&mut self, opener: Side, bidi: bool) -> StreamId {
        let s = &mut self.sides[opener.idx()];
        let (n, base) = if bidi {
            (&mut s.next_bidi, 0)
        } else {
            (&mut s.next_uni, 2)
        };
        let id = StreamId(*n * 4 + base + opener.idx() as u64);
        *n += 1;
        self.dirs.insert((id, opener), Dir::default());
        let peer = &mut self.sides[opener.peer().idx()];
        if bidi {
            self.dirs.insert((id, opener.peer()), Dir::default());
            self.sides[opener.idx()].used += 1;
            let peer = &mut self.sides[opener.peer().idx()];
            peer.accept_bidi.push_back(id);
            wake(&mut peer.accept_bidi_w);
        } else {
            peer.accept_uni.push_back(id);
            wake(&mut peer.accept_uni_w);
        }
        id
    }

    /// Return the opener's stream credit once both directions are terminal.
    fn touch(&mut self, id: StreamId) {
        let opener = if id.0 % 2 == 0 {
            Side::Client
        } else {
            Side::Server
        };
        let bidi = id.0 & 2 == 0;
        if !bidi || self.credit_returned.contains(&id) {
            return;
        }
        let done = [Side::Client, Side::Server]
            .iter()
            .all(|&w| self.dirs.get(&(id, w)).is_some_and(Dir::terminal));
        if done {
            self.credit_returned.insert(id);
            let s = &mut self.sides[opener.idx()];
            s.used -= 1;
            wake(&mut s.open_w);
        }
    }
}

/// Shared control and observation handle of an in-memory connection pair.
#[derive(Clone)]
pub struct MockNet(Arc<Mutex<Net>>);

impl std::fmt::Debug for MockNet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MockNet").finish_non_exhaustive()
    }
}

impl MockNet {
    /// A new pair: the first [`MockConn`] is the client side, the second the server side.
    pub fn pair() -> (MockNet, MockConn, MockConn) {
        let net = MockNet(Arc::new(Mutex::new(Net {
            dirs: HashMap::new(),
            blocked: HashSet::new(),
            credit_returned: HashSet::new(),
            sides: [SideState::new(), SideState::new()],
            max_write: None,
            ack_manual: false,
            loss: false,
            reorder: false,
            early_wake: false,
            coalesce: false,
            trace: Vec::new(),
            write_hooks: HashMap::new(),
        })));
        let c = MockConn {
            net: net.clone(),
            side: Side::Client,
        };
        let s = MockConn {
            net: net.clone(),
            side: Side::Server,
        };
        (net, c, s)
    }

    fn lock(&self) -> MutexGuard<'_, Net> {
        self.0.lock().unwrap()
    }

    /// Cap the bytes one `poll_write_chunks` accepts (`None`: unlimited).
    pub fn max_write(&self, n: Option<usize>) {
        self.lock().max_write = n;
    }

    /// Make writes by `side` on `stream` pend (or resume them).
    pub fn block_writes(&self, side: Side, stream: StreamId, on: bool) {
        let mut n = self.lock();
        if on {
            n.blocked.insert((side, stream));
        } else {
            n.blocked.remove(&(side, stream));
            if let Some(d) = n.dirs.get_mut(&(stream, side)) {
                wake(&mut d.write_w);
            }
        }
    }

    /// Choose when `poll_stopped` reports completion.
    pub fn ack_mode(&self, mode: Ack) {
        self.lock().ack_manual = mode == Ack::Manual;
    }

    /// Acknowledge every stream that exists now (Manual mode).
    pub fn ack_all(&self) {
        let mut n = self.lock();
        for d in n.dirs.values_mut() {
            if d.fin && d.eof_read {
                d.acked = true;
                wake(&mut d.stopped_w);
            }
        }
    }

    /// Silently drop datagrams passed to `send_datagram`.
    pub fn datagram_loss(&self, on: bool) {
        self.lock().loss = on;
    }

    /// Deliver datagrams in reverse order of sending.
    pub fn datagram_reorder(&self, on: bool) {
        self.lock().reorder = on;
    }

    /// The datagram limit `side` reports and enforces when sending.
    pub fn set_max_datagram_size(&self, side: Side, n: Option<usize>) {
        self.lock().sides[side.idx()].max_dgram = n;
    }

    /// Skip the next `n` bidirectional stream ids of `side`, as QUIC allows (they are
    /// opened implicitly and never used).
    pub fn skip_bidi(&self, side: Side, n: u64) {
        self.lock().sides[side.idx()].next_bidi += n;
    }

    /// Race injection: a poll that returns `Pending` also wakes the waker it just
    /// registered, as if readiness arrived before registration completed.
    pub fn readiness_before_register(&self, on: bool) {
        self.lock().early_wake = on;
    }

    /// Reads return up to `max_len` bytes across write boundaries (as quinn does), not
    /// one written chunk at a time.
    pub fn coalesce_reads(&self, on: bool) {
        self.lock().coalesce = on;
    }

    /// Fail `side`'s transport; its operations (pending ones included) return
    /// `TransportError { peer_app_code, .. }`.
    pub fn kill_transport(&self, side: Side, peer_app_code: Option<u64>) {
        self.kill(
            side,
            Dead {
                app: peer_app_code,
                transport: None,
            },
        );
    }

    /// Fail `side`'s transport as if the peer sent a transport-level CONNECTION_CLOSE
    /// with `code`: `TransportError { peer_transport_code: Some(code), .. }`.
    pub fn close_transport(&self, side: Side, code: u64) {
        self.kill(
            side,
            Dead {
                app: None,
                transport: Some(code),
            },
        );
    }

    fn kill(&self, side: Side, d: Dead) {
        let mut n = self.lock();
        if n.sides[side.idx()].dead.is_some() {
            return; // first failure wins, as with a real connection
        }
        n.sides[side.idx()].dead = Some(d);
        n.wake_all();
    }

    /// The stream credit the peer grants `side` for bidirectional streams.
    pub fn max_bidi_streams(&self, side: Side, n: usize) {
        let mut g = self.lock();
        g.sides[side.idx()].credit = n;
        wake(&mut g.sides[side.idx()].open_w);
    }

    /// Streams opened by the peer of `side` that `side` has not accepted yet.
    pub fn pending_accepts(&self, side: Side) -> usize {
        let n = self.lock();
        let s = &n.sides[side.idx()];
        s.accept_bidi.len() + s.accept_uni.len()
    }

    /// The code `side` closed the connection with.
    pub fn closed_with(&self, side: Side) -> Option<u64> {
        self.lock().sides[side.idx()].closed
    }

    /// Run `f` once, right after the next write by `side` on `stream` is accepted and
    /// outside the mock's lock: an action from another thread in the window between a
    /// write and its accounting.
    pub fn on_write(&self, side: Side, stream: StreamId, f: impl FnOnce() + Send + 'static) {
        self.lock().write_hooks.insert((side, stream), Box::new(f));
    }

    /// Everything observed so far, in order.
    pub fn trace(&self) -> Vec<MockObs> {
        self.lock().trace.clone()
    }
}

/// One end of the in-memory connection; implements [`Connection`].
#[derive(Debug)]
pub struct MockConn {
    net: MockNet,
    side: Side,
}

/// Send half of a mock stream.
#[derive(Debug)]
pub struct MockSend {
    net: MockNet,
    side: Side,
    id: StreamId,
}

/// Receive half of a mock stream.
#[derive(Debug)]
pub struct MockRecv {
    net: MockNet,
    side: Side,
    id: StreamId,
}

impl MockConn {
    fn halves(&self, id: StreamId) -> (MockSend, MockRecv) {
        (
            MockSend {
                net: self.net.clone(),
                side: self.side,
                id,
            },
            MockRecv {
                net: self.net.clone(),
                side: self.side,
                id,
            },
        )
    }
}

impl Connection for MockConn {
    type Send = MockSend;
    type Recv = MockRecv;

    fn poll_accept_bidi(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(MockSend, MockRecv), TransportError>> {
        let mut n = self.net.lock();
        let s = &mut n.sides[self.side.idx()];
        if let Some(code) = s.dead {
            return Poll::Ready(Err(dead_err(code)));
        }
        match s.accept_bidi.pop_front() {
            Some(id) => Poll::Ready(Ok(self.halves(id))),
            None => {
                register(&mut s.accept_bidi_w, cx);
                n.pending(cx)
            }
        }
    }

    fn poll_accept_uni(&mut self, cx: &mut Context<'_>) -> Poll<Result<MockRecv, TransportError>> {
        let mut n = self.net.lock();
        let s = &mut n.sides[self.side.idx()];
        if let Some(code) = s.dead {
            return Poll::Ready(Err(dead_err(code)));
        }
        match s.accept_uni.pop_front() {
            Some(id) => Poll::Ready(Ok(self.halves(id).1)),
            None => {
                register(&mut s.accept_uni_w, cx);
                n.pending(cx)
            }
        }
    }

    fn poll_open_bidi(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(MockSend, MockRecv), TransportError>> {
        let mut n = self.net.lock();
        let s = &mut n.sides[self.side.idx()];
        if let Some(code) = s.dead {
            return Poll::Ready(Err(dead_err(code)));
        }
        if s.used >= s.credit {
            register(&mut s.open_w, cx);
            return n.pending(cx);
        }
        let id = n.create_stream(self.side, true);
        Poll::Ready(Ok(self.halves(id)))
    }

    fn poll_open_uni(&mut self, _cx: &mut Context<'_>) -> Poll<Result<MockSend, TransportError>> {
        let mut n = self.net.lock();
        if let Some(code) = n.sides[self.side.idx()].dead {
            return Poll::Ready(Err(dead_err(code)));
        }
        let id = n.create_stream(self.side, false);
        Poll::Ready(Ok(self.halves(id).0))
    }

    fn poll_recv_datagram(&mut self, cx: &mut Context<'_>) -> Poll<Result<Bytes, TransportError>> {
        let mut n = self.net.lock();
        let s = &mut n.sides[self.side.idx()];
        if let Some(code) = s.dead {
            return Poll::Ready(Err(dead_err(code)));
        }
        match s.dgrams.pop_front() {
            Some(d) => Poll::Ready(Ok(d)),
            None => {
                register(&mut s.dgram_w, cx);
                n.pending(cx)
            }
        }
    }

    fn send_datagram(&mut self, data: Bytes) -> Result<(), SendDatagramError> {
        let mut n = self.net.lock();
        if let Some(code) = n.sides[self.side.idx()].dead {
            return Err(SendDatagramError::Transport(dead_err(code)));
        }
        match n.sides[self.side.idx()].max_dgram {
            None => return Err(SendDatagramError::Unsupported),
            Some(max) if data.len() > max => return Err(SendDatagramError::TooLarge),
            Some(_) => {}
        }
        n.trace.push(MockObs::Datagram {
            side: self.side,
            len: data.len(),
        });
        if n.loss {
            return Ok(());
        }
        let reorder = n.reorder;
        let peer = &mut n.sides[self.side.peer().idx()];
        if reorder {
            peer.dgrams.push_front(data);
        } else {
            peer.dgrams.push_back(data);
        }
        wake(&mut peer.dgram_w);
        Ok(())
    }

    fn max_datagram_size(&self) -> Option<usize> {
        self.net.lock().sides[self.side.idx()].max_dgram
    }

    fn close(&mut self, code: u64) {
        let mut n = self.net.lock();
        if n.sides[self.side.idx()].dead.is_some() {
            return; // closing a closed connection is a no-op
        }
        n.trace.push(MockObs::Close {
            side: self.side,
            code,
        });
        n.sides[self.side.idx()].closed = Some(code);
        n.sides[self.side.idx()].dead = Some(Dead::default());
        n.sides[self.side.peer().idx()].dead = Some(Dead {
            app: Some(code),
            transport: None,
        });
        n.wake_all();
    }
}

impl SendStream for MockSend {
    fn id(&self) -> StreamId {
        self.id
    }

    fn poll_write_chunks(
        &mut self,
        cx: &mut Context<'_>,
        bufs: &mut [Bytes],
    ) -> Poll<Result<Written, WriteError>> {
        let mut n = self.net.lock();
        if let Some(code) = n.sides[self.side.idx()].dead {
            return Poll::Ready(Err(WriteError::Transport(dead_err(code))));
        }
        let blocked = n.blocked.contains(&(self.side, self.id));
        let max_write = n.max_write;
        let d = n.dir(self.id, self.side);
        if let Some(code) = d.stop {
            return Poll::Ready(Err(WriteError::Stopped(code)));
        }
        if d.fin || d.reset.is_some() {
            return Poll::Ready(Err(WriteError::Closed));
        }
        if blocked {
            register(&mut d.write_w, cx);
            return n.pending(cx);
        }
        let mut room = max_write.unwrap_or(usize::MAX);
        let (mut bytes, mut chunks) = (0, 0);
        for b in bufs.iter_mut() {
            if b.is_empty() {
                chunks += 1; // like quinn: an empty chunk is trivially written
            } else if room == 0 {
                break;
            } else if b.len() <= room {
                room -= b.len();
                bytes += b.len();
                chunks += 1;
                d.buf.push_back(b.clone());
            } else {
                d.buf.push_back(b.slice(..room));
                b.advance(room);
                bytes += room;
                break;
            }
        }
        if bytes == 0 && bufs.iter().any(|b| !b.is_empty()) {
            register(&mut d.write_w, cx);
            return n.pending(cx);
        }
        wake(&mut d.read_w);
        n.trace.push(MockObs::Write {
            side: self.side,
            stream: self.id,
            len: bytes,
        });
        let hook = n.write_hooks.remove(&(self.side, self.id));
        drop(n);
        if let Some(f) = hook {
            f();
        }
        Poll::Ready(Ok(Written { bytes, chunks }))
    }

    fn finish(&mut self) {
        let mut n = self.net.lock();
        let d = n.dir(self.id, self.side);
        if d.fin || d.reset.is_some() {
            return;
        }
        d.fin = true;
        wake(&mut d.read_w);
        wake(&mut d.stopped_w);
        n.trace.push(MockObs::Fin {
            side: self.side,
            stream: self.id,
        });
    }

    fn reset(&mut self, code: u64) {
        let mut n = self.net.lock();
        let d = n.dir(self.id, self.side);
        d.reset = Some(code);
        d.buf.clear();
        wake(&mut d.read_w);
        wake(&mut d.stopped_w);
        n.trace.push(MockObs::Reset {
            side: self.side,
            stream: self.id,
            code,
        });
        n.touch(self.id);
    }

    fn poll_stopped(&mut self, cx: &mut Context<'_>) -> Poll<Result<Option<u64>, TransportError>> {
        let mut n = self.net.lock();
        if let Some(code) = n.sides[self.side.idx()].dead {
            return Poll::Ready(Err(dead_err(code)));
        }
        let manual = n.ack_manual;
        let d = n.dir(self.id, self.side);
        if let Some(code) = d.stop {
            return Poll::Ready(Ok(Some(code)));
        }
        let done = d.reset.is_some() || (d.fin && d.eof_read && (!manual || d.acked));
        if done {
            return Poll::Ready(Ok(None));
        }
        register(&mut d.stopped_w, cx);
        n.pending(cx)
    }
}

impl RecvStream for MockRecv {
    fn id(&self) -> StreamId {
        self.id
    }

    fn poll_read_chunk(
        &mut self,
        cx: &mut Context<'_>,
        max_len: usize,
    ) -> Poll<Result<Option<Bytes>, ReadError>> {
        let mut n = self.net.lock();
        if let Some(code) = n.sides[self.side.idx()].dead {
            return Poll::Ready(Err(ReadError::Transport(dead_err(code))));
        }
        let writer = self.side.peer();
        let coalesce = n.coalesce;
        let d = n.dir(self.id, writer);
        if d.stop.is_some() {
            return Poll::Ready(Err(ReadError::Closed));
        }
        if let Some(code) = d.reset {
            return Poll::Ready(Err(ReadError::Reset(code)));
        }
        if coalesce && d.buf.len() > 1 && d.buf[0].len() < max_len {
            let mut v = BytesMut::new();
            while let Some(f) = d.buf.front_mut().filter(|_| v.len() < max_len) {
                let k = f.len().min(max_len - v.len());
                v.extend_from_slice(&f.split_to(k));
                if f.is_empty() {
                    d.buf.pop_front();
                }
            }
            return Poll::Ready(Ok(Some(v.freeze())));
        }
        if let Some(front) = d.buf.front_mut() {
            let chunk = if front.len() <= max_len {
                d.buf.pop_front().unwrap()
            } else {
                front.split_to(max_len)
            };
            return Poll::Ready(Ok(Some(chunk)));
        }
        if d.fin {
            d.eof_read = true;
            wake(&mut d.stopped_w);
            n.touch(self.id);
            return Poll::Ready(Ok(None));
        }
        register(&mut d.read_w, cx);
        n.pending(cx)
    }

    fn stop(&mut self, code: u64) {
        let mut n = self.net.lock();
        let writer = self.side.peer();
        let d = n.dir(self.id, writer);
        d.stop = Some(code);
        d.buf.clear();
        wake(&mut d.write_w);
        wake(&mut d.stopped_w);
        n.trace.push(MockObs::Stop {
            side: self.side,
            stream: self.id,
            code,
        });
        n.touch(self.id);
    }
}
