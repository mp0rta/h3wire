// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 mp0rta
//! The §5.1 property test: random API calls, cancellations and transport knobs over an
//! h3wire-async client and server on `MockNet`, checked by the oracle [`check`] after
//! every op; then a cleanup phase, a graceful shutdown and the liveness assertion.
//!
//! A case runs either two h3wire-async endpoints, or an h3wire-async server facing a
//! raw `CorePeer` client. The peer adds what the async client never produces:
//! STOP_SENDING or RESET_STREAM alone on a chosen direction, a control stream (SETTINGS)
//! held back until after request HEADERS, raw frames the core does not write (unknown
//! types, empty DATA, a forbidden frame), and datagrams sent before the request's
//! HEADERS go out and before the server registers.

use crate::__testing::exec::TestExec;
use crate::__testing::{Ack, CorePeer, MockConn, MockNet, MockObs, PeerObs, Side};
use crate::body::RecvBody;
use crate::builder::Builder;
use crate::client::{ClientConnection, SendRequest};
use crate::datagram::{DatagramSlot, Datagrams, RegisterDatagrams};
use crate::error::{BoxError, Error, ErrorKind};
use crate::ext::ConnInfo;
use crate::server::ServerConnection;
use crate::state::{Inner, Shared};
use crate::upgrade::{self, OnUpgrade, TunnelRecv, TunnelSend};
use bytes::Bytes;
use futures::StreamExt;
use futures::channel::{mpsc, oneshot};
use h3wire::{AbortSource, Config as CoreConfig, Event, H3Code, Role, StreamId};
use http::{HeaderMap, HeaderValue, Method, Request, Response};
use http_body::{Body, Frame};
use proptest::prelude::*;
use proptest::test_runner::{Config, TestError, TestRunner};
use std::collections::{HashMap, HashSet};
use std::future::Future;
use std::hash::{DefaultHasher, Hash, Hasher};
use std::panic::AssertUnwindSafe;
use std::pin::{Pin, pin};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Wake, Waker};
use tower_service::Service;

/// The first request streams, then the control and QPACK streams of both sides.
const STREAMS: [StreamId; 8] = [
    StreamId(0),
    StreamId(4),
    StreamId(8),
    StreamId(12),
    StreamId(2),
    StreamId(3),
    StreamId(6),
    StreamId(7),
];
/// Requests per case.
const MAX_REQS: usize = 12;
/// Polls of the whole world per settle before it counts as busy-looping.
const SETTLE_LIMIT: usize = 200_000;
/// Cleanup rounds (each settles) in a row without progress before liveness fails.
const STALL_ROUNDS: usize = 3;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Kind {
    Get,
    Post,
    Connect,
}

/// One step. A `u8` request number picks (modulo) among the requests holding what the
/// op acts on; an op with nothing to act on does nothing.
#[derive(Clone, Debug)]
enum Op {
    /// Client `send_request`; `dgram` adds `RegisterDatagrams`. A `CorePeer` client
    /// sends the HEADERS and, with `dgram`, a datagram for the stream at once (before
    /// the HEADERS are written).
    Request {
        kind: Kind,
        dgram: bool,
    },
    /// Poll the response future once.
    PollResponse(u8),
    /// Drop the response future (cancels a pending one).
    DropResponse(u8),
    /// Server: answer with `status`; `body`: a streamed body (else empty).
    Respond {
        k: u8,
        status: u16,
        body: bool,
    },
    /// Server, the MASQUE pattern: register datagrams, claim the upgrade
    /// (`upgrade::on`), answer 200 with an empty body.
    Accept(u8),
    /// Server: the Service fails (no response).
    FailService(u8),
    /// Queue `n` body or tunnel bytes in `pieces` chunks at once (a pending
    /// `TunnelSend::send` is cancelled, and stops the rest).
    Send(Side, u8, u16, u8),
    /// End the body (`Some(n)`: with an `n`-byte trailer value) or finish the tunnel.
    Finish(Side, u8, Option<u16>),
    /// Fail the body, or abort the tunnel.
    Abort(Side, u8),
    /// Poll the reader (body, claim or tunnel) a few times; a pending poll is dropped.
    Read(Side, u8),
    /// Drop the reader: the tunnel half, a pending `OnUpgrade`, else the message.
    DropReader(Side, u8),
    /// `upgrade::on` once, then poll the `OnUpgrade` (client: registers datagrams first).
    Upgrade(Side, u8),
    /// `DatagramSlot::register`.
    Register(Side, u8),
    DgSend(Side, u8, u8),
    DgRecv(Side, u8),
    DropDatagrams(Side, u8),
    MaxWrite(Option<u16>),
    /// Block writes on stream `STREAMS[n % 8]` (request and uni streams alike).
    Block(Side, u8, bool),
    AckManual(bool),
    AckAll,
    Loss(bool),
    Reorder(bool),
    MaxDatagram(Side, Option<u16>),
    EarlyWake(bool),
    Coalesce(bool),
    Shutdown(Side),
    /// Both transports die.
    Kill,
    /// `CorePeer` client: STOP_SENDING alone (the response direction).
    PeerStop(u8),
    /// `CorePeer` client: RESET_STREAM alone (the request direction).
    PeerReset(u8),
    /// `CorePeer` client: raw bytes on the request stream.
    PeerRaw(u8, Raw),
    /// `CorePeer` client: open the held-back control stream (SETTINGS).
    BindControl,
    /// Drop the connection future (closes with `H3_NO_ERROR`).
    DropConn(Side),
}

/// Raw frames a `CorePeer` writes past its core.
#[derive(Clone, Copy, Debug)]
enum Raw {
    /// A reserved (unknown) frame type with a payload: ignored by the receiver.
    Grease,
    /// An empty DATA frame.
    EmptyData,
    /// An HTTP/2-only frame type (0x02): a connection error.
    Forbidden,
}

impl Raw {
    fn bytes(self) -> &'static [u8] {
        match self {
            // Type 0x21 (reserved), length 3.
            Raw::Grease => &[0x21, 3, 1, 2, 3],
            Raw::EmptyData => &[0x00, 0],
            Raw::Forbidden => &[0x02, 1, 0],
        }
    }
}

/// One case's endpoints: the limits of each side, and `Some(defer_control)` for a
/// `CorePeer` client.
#[derive(Clone, Debug)]
struct Setup {
    client: Limits,
    server: Limits,
    peer: Option<bool>,
}

/// One side's builder limits.
#[derive(Clone, Debug)]
struct Limits {
    read_ahead: usize,
    cap: usize,
    demand: usize,
    send: usize,
    field: usize,
    budget: usize,
    dq: usize,
    stream_cap: (usize, usize),
    conn_cap: (usize, usize),
}

impl Limits {
    fn builder(&self) -> Builder {
        let mut b = Builder::new();
        b.read_ahead(self.read_ahead)
            .read_ahead_cap(self.cap)
            .demand_chunk(self.demand)
            .send_capacity(self.send)
            .max_encoded_field_section_size(self.field)
            .work_budget(self.budget)
            .datagram_queue(self.dq)
            .pending_datagrams_per_stream(self.stream_cap.0, self.stream_cap.1)
            .pending_datagrams_per_conn(self.conn_cap.0, self.conn_cap.1);
        b
    }
}

type Frm = Result<Frame<Bytes>, BoxError>;
type Log = Arc<Mutex<Vec<String>>>;
type RespFut = Pin<Box<dyn Future<Output = Result<Response<RecvBody>, Error>> + Send>>;
type Handed = (Request<RecvBody>, oneshot::Sender<Response<PBody>>);
type SvcFut = Pin<Box<dyn Future<Output = Result<Response<PBody>, BoxError>> + Send>>;

/// A body fed by the test through a channel (ends when the sender goes); `None`: empty.
struct PBody(Option<mpsc::UnboundedReceiver<Frm>>);

impl Body for PBody {
    type Data = Bytes;
    type Error = BoxError;

    fn poll_frame(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Frm>> {
        match &mut self.0 {
            None => Poll::Ready(None),
            Some(rx) => rx.poll_next_unpin(cx),
        }
    }

    fn is_end_stream(&self) -> bool {
        self.0.is_none()
    }
}

/// Hands each request to the world; its future waits for the world's response.
#[derive(Clone)]
struct Svc {
    tx: mpsc::UnboundedSender<Handed>,
    shared: Arc<Mutex<Option<Shared>>>,
    log: Log,
}

impl Service<Request<RecvBody>> for Svc {
    type Response = Response<PBody>;
    type Error = BoxError;
    type Future = SvcFut;

    fn poll_ready(&mut self, _: &mut Context<'_>) -> Poll<Result<(), BoxError>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, req: Request<RecvBody>) -> SvcFut {
        let (tx, rx) = oneshot::channel();
        let guard = CancelGuard {
            shared: self.shared.lock().unwrap().clone().expect("set at build"),
            id: req.body().stream_id(),
            log: self.log.clone(),
            live: true,
        };
        let _ = self.tx.unbounded_send((req, tx));
        Box::pin(async move {
            let mut guard = guard; // the whole guard, not just `live`
            let r = rx.await;
            guard.live = false;
            r.map_err(|_| "no response".into())
        })
    }
}

/// Inside a Service future: dropped while still `live` means the task was cancelled,
/// which spec §4.6 (and the Task 7 ruling) allows only once both directions are terminal
/// (or the connection closed): [`task_over`].
struct CancelGuard {
    shared: Shared,
    id: StreamId,
    log: Log,
    live: bool,
}

impl Drop for CancelGuard {
    fn drop(&mut self) {
        if !self.live {
            return;
        }
        let id = self.id;
        let ok = self.shared.with(|i| task_over(i, id));
        if !ok {
            self.log.lock().unwrap().push(format!(
                "server task of {id:?} cancelled while a direction is live"
            ));
        }
    }
}

/// The server per-request task of `id` may be cancelled (spec §4.6, Task 7 ruling): the
/// connection closed, or the send side is done and the receive side consumed ((a) the
/// reader took EOF, (b) no reader remains, (c) reset or errored). Restated here, not taken
/// from `StreamState`, so the oracle stays independent of the code it checks.
fn task_over(i: &Inner, id: StreamId) -> bool {
    i.close.is_some()
        || i.streams.get(&id).is_none_or(|st| {
            let r = &st.recv;
            let consumed = r.error.is_some()
                || r.abandoned
                || (r.eof && r.queue.is_empty() && r.trailers.is_none());
            st.send.done && consumed
        })
}

/// Records any wake.
#[derive(Default)]
struct Flag(AtomicBool);

impl Wake for Flag {
    fn wake(self: Arc<Self>) {
        self.0.store(true, Ordering::SeqCst);
    }
    fn wake_by_ref(self: &Arc<Self>) {
        self.0.store(true, Ordering::SeqCst);
    }
}

enum Msg {
    Req(Request<RecvBody>),
    Resp(Response<RecvBody>),
}

impl Msg {
    fn body(&mut self) -> &mut RecvBody {
        match self {
            Msg::Req(r) => r.body_mut(),
            Msg::Resp(r) => r.body_mut(),
        }
    }

    fn on(&mut self) -> OnUpgrade {
        match self {
            Msg::Req(r) => upgrade::on(r),
            Msg::Resp(r) => upgrade::on(r),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum TxEnd {
    Fin,
    Trailers,
    Failed,
}

/// One endpoint's handles of one request, and what they produced and observed.
#[derive(Default)]
struct Half {
    msg: Option<Msg>,
    on_called: bool,
    up: Option<OnUpgrade>,
    rx: Option<TunnelRecv>,
    tx: Option<TunnelSend>,
    chan: Option<mpsc::UnboundedSender<Frm>>,
    slot: Option<DatagramSlot>,
    dg: Option<Datagrams>,
    /// Bytes produced towards the peer, and how that ended.
    sent: usize,
    sent_end: Option<TxEnd>,
    /// Bytes the reader got; trailers seen; its end (`true`: clean).
    got: usize,
    got_trailers: bool,
    got_end: Option<bool>,
    /// Receive-side errors seen (reader and datagrams), each with the trace length when
    /// it was seen, for the final excuse check.
    errs: Vec<(Error, usize)>,
    /// The datagram handle's end (`true`: `Ok(None)`).
    dg_end: Option<bool>,
}

impl Half {
    /// The handles still held.
    fn held(&self) -> Vec<&'static str> {
        [
            (self.msg.is_some(), "msg"),
            (self.up.is_some(), "up"),
            (self.rx.is_some(), "rx"),
            (self.tx.is_some(), "tx"),
            (self.chan.is_some(), "chan"),
            (self.dg.is_some(), "dg"),
        ]
        .into_iter()
        .filter_map(|(on, name)| on.then_some(name))
        .collect()
    }

    fn open(&self) -> bool {
        !self.held().is_empty()
    }
}

struct Req {
    kind: Kind,
    sid: Option<StreamId>,
    resp: Option<RespFut>,
    /// The status the client got, and the one the server sent.
    status: Option<u16>,
    sent_status: Option<u16>,
    reply: Option<oneshot::Sender<Response<PBody>>>,
    halves: [Half; 2],
}

fn idx(s: Side) -> usize {
    match s {
        Side::Client => 0,
        Side::Server => 1,
    }
}

fn other(s: Side) -> Side {
    match s {
        Side::Client => Side::Server,
        Side::Server => Side::Client,
    }
}

/// Byte `o` of the stream of request `k` sent by `from`.
fn pat(k: usize, from: Side, o: usize) -> u8 {
    (o.wrapping_mul(31) ^ (k * 2 + idx(from)).wrapping_mul(101)) as u8
}

fn pattern(k: usize, from: Side, off: usize, n: usize) -> Bytes {
    (off..off + n).map(|o| pat(k, from, o)).collect()
}

/// What one poll of a reader gave.
enum Seen {
    Pending,
    Data(Bytes),
    Trailers,
    End,
    Err(Error),
}

fn body_seen(p: Poll<Option<Result<Frame<Bytes>, Error>>>) -> Seen {
    match p {
        Poll::Pending => Seen::Pending,
        Poll::Ready(None) => Seen::End,
        Poll::Ready(Some(Err(e))) => Seen::Err(e),
        Poll::Ready(Some(Ok(f))) => match f.into_data() {
            Ok(b) => Seen::Data(b),
            Err(_) => Seen::Trailers,
        },
    }
}

/// Coverage counters of the peer-only generators, summed over every case of the run;
/// printed when `H3WIRE_PROPS_STATS` is set.
#[derive(Clone, Copy, Debug)]
enum Stat {
    PeerCases,
    PeerStop,
    PeerReset,
    RawGrease,
    RawEmptyData,
    RawForbidden,
    /// The server got a request while the peer still held its SETTINGS back.
    HeadersBeforeSettings,
    /// A datagram sent with the request, before its HEADERS were written.
    EarlyDatagram,
    /// The server held pending (unregistered) datagrams of a peer request.
    PendingDatagrams,
}

static STATS: [AtomicUsize; 9] = [const { AtomicUsize::new(0) }; 9];

fn stat(s: Stat) {
    STATS[s as usize].fetch_add(1, Ordering::Relaxed);
}

struct World {
    net: MockNet,
    exec: TestExec,
    flag: Arc<Flag>,
    /// The h3wire-async client, or `peer`.
    send: Option<SendRequest<PBody>>,
    client: Option<ClientConnection<MockConn>>,
    peer: Option<CorePeer<MockConn>>,
    server: Option<ServerConnection<MockConn, Svc, TestExec>>,
    /// The h3wire-async endpoints' state: client (none for a peer), server.
    shared: [Option<Shared>; 2],
    limits: [Limits; 2],
    /// The last settle ended quiescent.
    quiet: bool,
    /// Trace length when both transports were killed.
    killed_at: Option<usize>,
    /// The peer's control stream (SETTINGS) is still held back.
    control_deferred: bool,
    handed: mpsc::UnboundedReceiver<Handed>,
    log: Log,
    reqs: Vec<Req>,
    blocked: HashSet<(Side, StreamId)>,
    early_wake: bool,
    trace: Log,
}

impl World {
    fn new(setup: &Setup, trace: Log) -> World {
        let (cl, sl) = (&setup.client, &setup.server);
        let (net, c, s) = MockNet::pair();
        let exec = TestExec::default();
        let log = Log::default();
        let (tx, handed) = mpsc::unbounded();
        let svc = Svc {
            tx,
            shared: Default::default(),
            log: log.clone(),
        };
        let cell = svc.shared.clone();
        let server = sl.builder().serve_connection(s, svc, exec.clone());
        *cell.lock().unwrap() = Some(server.driver.shared());
        let (send, client, peer) = match setup.peer {
            None => {
                let (send, client) =
                    futures::executor::block_on(cl.builder().handshake(c, exec.clone())).unwrap();
                (Some(send), Some(client), None)
            }
            Some(defer) => {
                let mut cfg = CoreConfig::default();
                cfg.h3_datagram = true;
                let mut p = CorePeer::new(Role::Client, cfg, c);
                p.defer_control(defer);
                (None, None, Some(p))
            }
        };
        World {
            shared: [
                send.as_ref().map(|s| s.shared.clone()),
                Some(server.driver.shared()),
            ],
            net,
            exec,
            flag: Arc::default(),
            send,
            client,
            peer,
            server: Some(server),
            limits: [cl.clone(), sl.clone()],
            quiet: true,
            killed_at: None,
            control_deferred: setup.peer == Some(true),
            handed,
            log,
            reqs: Vec::new(),
            blocked: HashSet::new(),
            early_wake: false,
            trace,
        }
    }

    fn note(&self, s: String) {
        self.trace.lock().unwrap().push(s);
    }

    fn bad(&self, s: String) {
        self.note(format!("VIOLATION: {s}"));
        self.log.lock().unwrap().push(s);
    }

    fn waker(&self) -> Waker {
        Waker::from(self.flag.clone())
    }

    /// Run every task and both connections until nothing is woken. `false` if the
    /// limit was reached first.
    fn settle(&mut self) -> bool {
        let limit = if self.early_wake { 64 } else { SETTLE_LIMIT };
        let waker = self.waker();
        let mut cx = Context::from_waker(&waker);
        for _ in 0..limit {
            self.flag.0.store(false, Ordering::SeqCst);
            self.exec.tick(&mut cx);
            if let Some(c) = &mut self.client {
                if let Poll::Ready(r) = Pin::new(c).poll(&mut cx) {
                    self.note(format!("client connection ended: {r:?}"));
                    self.client = None;
                }
            }
            if let Some(s) = &mut self.server {
                if let Poll::Ready(r) = Pin::new(s).poll(&mut cx) {
                    self.note(format!("server connection ended: {r:?}"));
                    self.server = None;
                }
            }
            self.take_requests();
            // After the server: what the peer queued this op reaches the wire now.
            if let Some(p) = &mut self.peer {
                while p.poll_step(&mut cx).is_ready() {}
            }
            if !self.flag.0.load(Ordering::SeqCst) {
                self.quiet = true;
                return true;
            }
        }
        self.quiet = false;
        false
    }

    fn take_requests(&mut self) {
        while let Ok((req, reply)) = self.handed.try_recv() {
            let k: usize = req.headers()["x-k"].to_str().unwrap().parse().unwrap();
            let sid = req.body().stream_id();
            self.note(format!("server got request {k} on {sid:?}"));
            if self.control_deferred {
                stat(Stat::HeadersBeforeSettings);
            }
            let r = &mut self.reqs[k];
            r.sid = Some(sid);
            r.reply = Some(reply);
            let h = &mut r.halves[1];
            h.slot = req.extensions().get::<DatagramSlot>().cloned();
            h.msg = Some(Msg::Req(req));
        }
    }

    /// Request `k` (modulo) among those `f` accepts, if any: an op picks among the
    /// requests holding what it acts on.
    fn pick(&self, k: u8, f: impl Fn(&Req) -> bool) -> Option<usize> {
        let c: Vec<usize> = (0..self.reqs.len()).filter(|&i| f(&self.reqs[i])).collect();
        (!c.is_empty()).then(|| c[k as usize % c.len()])
    }

    /// As [`Self::pick`], on the half of side `s`.
    fn pick_half(&self, k: u8, s: Side, f: impl Fn(&Half) -> bool) -> Option<usize> {
        self.pick(k, |r| f(&r.halves[idx(s)]))
    }

    fn apply(&mut self, op: &Op) {
        self.note(format!("{op:?}"));
        let waker = self.waker();
        let mut cx = Context::from_waker(&waker);
        let cx = &mut cx;
        if self.peer.is_some() && self.peer_op(op, cx) {
            return;
        }
        match *op {
            Op::Request { kind, dgram } => self.request(kind, dgram),
            Op::PollResponse(k) => {
                if let Some(k) = self.pick(k, |r| r.resp.is_some()) {
                    self.poll_response(k, cx);
                }
            }
            Op::DropResponse(k) => {
                if let Some(k) = self.pick(k, |r| r.resp.is_some()) {
                    self.reqs[k].resp = None;
                }
            }
            Op::Respond { k, status, body } => {
                if let Some(k) = self.pick(k, |r| r.reply.is_some()) {
                    self.respond(k, status, body);
                }
            }
            Op::Accept(k) => {
                if let Some(k) = self.pick(k, |r| r.reply.is_some()) {
                    self.register(k, Side::Server);
                    self.upgrade(k, Side::Server, cx);
                    self.respond(k, 200, false);
                }
            }
            Op::FailService(k) => {
                if let Some(k) = self.pick(k, |r| r.reply.is_some()) {
                    self.reqs[k].reply = None;
                }
            }
            Op::Send(s, k, n, pieces) => {
                if let Some(k) = self.pick_half(k, s, |h| {
                    h.sent_end.is_none() && (h.chan.is_some() || h.tx.is_some())
                }) {
                    let n = usize::from(n);
                    let piece = n.div_ceil(usize::from(pieces));
                    for j in (0..n).step_by(piece) {
                        if !self.send_bytes(k, s, piece.min(n - j), cx) {
                            break;
                        }
                    }
                }
            }
            Op::Finish(s, k, trailers) => {
                if let Some(k) = self.pick_half(k, s, |h| {
                    h.sent_end.is_none() && (h.chan.is_some() || h.tx.is_some())
                }) {
                    self.finish(k, s, trailers);
                }
            }
            Op::Abort(s, k) => {
                if let Some(k) = self.pick_half(k, s, |h| {
                    h.tx.is_some() || h.rx.is_some() || h.chan.is_some()
                }) {
                    let h = &mut self.reqs[k].halves[idx(s)];
                    if let Some(t) = &h.tx {
                        t.abort(H3Code::MESSAGE_ERROR);
                    } else if let Some(t) = &h.rx {
                        t.abort(H3Code::MESSAGE_ERROR);
                    } else if let Some(c) = h.chan.take() {
                        let _ = c.unbounded_send(Err("body failed".into()));
                    } else {
                        return;
                    }
                    h.sent_end.get_or_insert(TxEnd::Failed);
                }
            }
            Op::Read(s, k) => {
                if let Some(k) = self.pick_half(k, s, |h| h.rx.is_some() || h.msg.is_some()) {
                    self.read(k, s, 4, cx);
                }
            }
            Op::DropReader(s, k) => {
                if let Some(k) = self.pick_half(k, s, |h| {
                    h.rx.is_some() || h.up.is_some() || h.msg.is_some()
                }) {
                    let h = &mut self.reqs[k].halves[idx(s)];
                    if h.rx.take().is_none() && h.up.take().is_none() {
                        h.msg = None;
                    }
                }
            }
            Op::Upgrade(s, k) => {
                if let Some(k) = self.pick_half(k, s, |h| {
                    h.up.is_some() || (h.msg.is_some() && !h.on_called)
                }) {
                    if s == Side::Client {
                        self.register(k, s); // the client's MASQUE pattern
                    }
                    self.upgrade(k, s, cx);
                }
            }
            Op::Register(s, k) => {
                if let Some(k) = self.pick_half(k, s, |h| h.slot.is_some() && h.dg.is_none()) {
                    self.register(k, s);
                }
            }
            Op::DgSend(s, k, n) => {
                if let Some(k) = self.pick_half(k, s, |h| h.dg.is_some()) {
                    if let Some(d) = &self.reqs[k].halves[idx(s)].dg {
                        let mut p = vec![k as u8, idx(s) as u8];
                        p.extend_from_slice(&pattern(k, s, 0, n as usize));
                        let r = d.send(p.into());
                        self.note(format!("  -> {r:?}"));
                    }
                }
            }
            Op::DgRecv(s, k) => {
                if let Some(k) = self.pick_half(k, s, |h| h.dg.is_some()) {
                    self.read_dg(k, s, 8, cx);
                }
            }
            Op::DropDatagrams(s, k) => {
                if let Some(k) = self.pick_half(k, s, |h| h.dg.is_some()) {
                    self.reqs[k].halves[idx(s)].dg = None;
                }
            }
            Op::MaxWrite(n) => self.net.max_write(n.map(usize::from)),
            Op::Block(s, n, on) => {
                let id = STREAMS[n as usize % STREAMS.len()];
                self.net.block_writes(s, id, on);
                if on {
                    self.blocked.insert((s, id));
                } else {
                    self.blocked.remove(&(s, id));
                }
            }
            Op::AckManual(on) => {
                self.net.ack_mode(if on { Ack::Manual } else { Ack::Auto });
                if !on {
                    // The mock wakes no `poll_stopped` waiter when the mode changes.
                    self.net.ack_all();
                }
            }
            Op::AckAll => self.net.ack_all(),
            Op::Loss(on) => self.net.datagram_loss(on),
            Op::Reorder(on) => self.net.datagram_reorder(on),
            Op::MaxDatagram(s, n) => self.net.set_max_datagram_size(s, n.map(usize::from)),
            Op::EarlyWake(on) => {
                self.early_wake = on;
                self.net.readiness_before_register(on);
            }
            Op::Coalesce(on) => self.net.coalesce_reads(on),
            Op::Shutdown(s) => self.shutdown(s),
            Op::Kill => {
                let at = self.net.trace().len();
                self.killed_at.get_or_insert(at); // the first kill counts
                self.net.kill_transport(Side::Client, None);
                self.net.kill_transport(Side::Server, None);
            }
            // Without a `CorePeer` client.
            Op::PeerStop(_) | Op::PeerReset(_) | Op::PeerRaw(..) | Op::BindControl => {}
            Op::DropConn(Side::Client) => self.client = None,
            Op::DropConn(Side::Server) => self.server = None,
        }
    }

    /// The client side of `op` for a `CorePeer` client; `false` for server-side ops.
    fn peer_op(&mut self, op: &Op, cx: &mut Context<'_>) -> bool {
        // A request of the peer whose request direction is still open.
        let open = |r: &Req| r.halves[0].sent_end.is_none();
        // ... and may carry DATA: a CONNECT only once its 2xx arrived (else the peer's
        // core refuses it).
        let p = self.peer.as_ref().expect("peer");
        let tunnel_up = |sid| {
            let heads = p.headers(sid);
            let st = heads
                .first()
                .and_then(|h| h.iter().find(|(n, _)| n == ":status").cloned());
            st.is_some_and(|(_, v)| v.starts_with('2'))
        };
        let sendable =
            |r: &Req| open(r) && (r.kind != Kind::Connect || tunnel_up(r.sid.expect("opened")));
        match *op {
            Op::Request { kind, dgram } => self.peer_request(kind, dgram, cx),
            Op::Send(Side::Client, k, n, _) => {
                if let Some(k) = self.pick(k, sendable) {
                    let r = &mut self.reqs[k];
                    let data = pattern(k, Side::Client, r.halves[0].sent, n.into());
                    let p = self.peer.as_mut().expect("peer");
                    p.send_body(r.sid.expect("opened"), &data, false);
                    r.halves[0].sent += usize::from(n);
                }
            }
            Op::Finish(Side::Client, k, _) => {
                if let Some(k) = self.pick(k, open) {
                    self.peer_finish(k);
                }
            }
            Op::Abort(Side::Client, k) => {
                if let Some(k) = self.pick(k, |r| r.sid.is_some()) {
                    let r = &mut self.reqs[k];
                    let p = self.peer.as_mut().expect("peer");
                    let _ = p.abort(r.sid.expect("opened"), H3Code::MESSAGE_ERROR);
                    r.halves[0].sent_end.get_or_insert(TxEnd::Failed);
                }
            }
            Op::DgSend(Side::Client, k, n) => {
                if let Some(k) = self.pick(k, |r| r.sid.is_some()) {
                    self.peer_datagram(k, n.into());
                }
            }
            Op::PeerStop(k) => {
                if let Some(k) = self.pick(k, |r| r.sid.is_some()) {
                    let sid = self.reqs[k].sid.expect("opened");
                    self.peer
                        .as_mut()
                        .expect("peer")
                        .stop_sending(sid, H3Code::REQUEST_CANCELLED);
                    stat(Stat::PeerStop);
                }
            }
            Op::PeerReset(k) => {
                if let Some(k) = self.pick(k, |r| r.sid.is_some()) {
                    let r = &mut self.reqs[k];
                    let p = self.peer.as_mut().expect("peer");
                    p.reset(r.sid.expect("opened"), H3Code::REQUEST_CANCELLED);
                    r.halves[0].sent_end.get_or_insert(TxEnd::Failed);
                    stat(Stat::PeerReset);
                }
            }
            Op::PeerRaw(k, raw) => {
                if let Some(k) = self.pick(k, |r| r.sid.is_some()) {
                    let sid = self.reqs[k].sid.expect("opened");
                    self.peer.as_mut().expect("peer").send_raw(sid, raw.bytes());
                    stat(match raw {
                        Raw::Grease => Stat::RawGrease,
                        Raw::EmptyData => Stat::RawEmptyData,
                        Raw::Forbidden => Stat::RawForbidden,
                    });
                }
            }
            Op::BindControl => self.bind_control(),
            // The async client's own calls and connection: nothing for a peer.
            Op::PollResponse(_)
            | Op::DropResponse(_)
            | Op::Shutdown(Side::Client)
            | Op::DropConn(Side::Client) => {}
            Op::Read(Side::Client, _)
            | Op::DropReader(Side::Client, _)
            | Op::Upgrade(Side::Client, _)
            | Op::Register(Side::Client, _)
            | Op::DgRecv(Side::Client, _)
            | Op::DropDatagrams(Side::Client, _) => {}
            _ => return false,
        }
        true
    }

    fn peer_request(&mut self, kind: Kind, dgram: bool, cx: &mut Context<'_>) {
        let k = self.reqs.len();
        if k == MAX_REQS {
            return;
        }
        let p = self.peer.as_mut().expect("peer");
        let Poll::Ready(Ok(sid)) = pin!(p.open_bidi()).poll(cx) else {
            return;
        };
        let ks = k.to_string();
        let (fields, end): (Vec<(&str, &str)>, bool) = match kind {
            Kind::Connect => (vec![(":method", "CONNECT"), (":authority", "a:443")], false),
            _ => {
                let (m, path) = match kind {
                    Kind::Get => ("GET", "/g"),
                    _ => ("POST", "/p"),
                };
                let f = [
                    (":method", m),
                    (":scheme", "https"),
                    (":authority", "a"),
                    (":path", path),
                ];
                (f.to_vec(), kind == Kind::Get)
            }
        };
        let mut fields = fields;
        fields.push(("x-k", &ks));
        if p.send_headers(sid, &fields, end).is_err() {
            // Refused (GOAWAY): give the opened stream up.
            p.reset(sid, H3Code::REQUEST_CANCELLED);
            p.stop_sending(sid, H3Code::REQUEST_CANCELLED);
            return;
        }
        let mut client = Half::default();
        if end {
            client.sent_end = Some(TxEnd::Fin);
        }
        self.reqs.push(Req {
            kind,
            sid: Some(sid),
            resp: None,
            status: None,
            sent_status: None,
            reply: None,
            halves: [client, Half::default()],
        });
        // Sent now, so it reaches the server before the HEADERS are written.
        if dgram && self.peer_datagram(k, 3) {
            stat(Stat::EarlyDatagram);
        }
    }

    /// `false` if the peer could not send it (not negotiated yet, or closed).
    fn peer_datagram(&mut self, k: usize, n: usize) -> bool {
        let mut d = vec![k as u8, idx(Side::Client) as u8];
        d.extend_from_slice(&pattern(k, Side::Client, 0, n));
        let sid = self.reqs[k].sid.expect("opened");
        let r = self.peer.as_mut().expect("peer").send_datagram(sid, &d);
        self.note(format!("  -> {r:?}"));
        r.is_ok()
    }

    fn peer_finish(&mut self, k: usize) {
        let r = &mut self.reqs[k];
        let p = self.peer.as_mut().expect("peer");
        // FIN only: trailers queued through the core would overtake body bytes the peer
        // has not framed yet.
        p.send_body(r.sid.expect("opened"), &[], true);
        r.halves[0].sent_end = Some(TxEnd::Fin);
    }

    fn bind_control(&mut self) {
        if std::mem::take(&mut self.control_deferred) {
            self.peer.as_mut().expect("peer").bind_control_now();
        }
    }

    fn request(&mut self, kind: Kind, dgram: bool) {
        let k = self.reqs.len();
        if k == MAX_REQS {
            return;
        }
        let (chan, body) = match kind {
            Kind::Post => {
                let (tx, rx) = mpsc::unbounded();
                (Some(tx), PBody(Some(rx)))
            }
            _ => (None, PBody(None)),
        };
        let mut b = Request::builder().header("x-k", k);
        b = match kind {
            Kind::Get => b.method(Method::GET).uri("https://a/g"),
            Kind::Post => b.method(Method::POST).uri("https://a/p"),
            Kind::Connect => b.method(Method::CONNECT).uri("a:443"),
        };
        if dgram {
            b = b.extension(RegisterDatagrams);
        }
        let send = self.send.as_mut().expect("async client");
        let resp = send.send_request(b.body(body).unwrap());
        let mut client = Half {
            chan,
            ..Half::default()
        };
        // A GET ends with its HEADERS; a CONNECT's bytes go through its tunnel.
        if kind == Kind::Get {
            client.sent_end = Some(TxEnd::Fin);
        }
        self.reqs.push(Req {
            kind,
            sid: None,
            resp: Some(Box::pin(resp)),
            status: None,
            sent_status: None,
            reply: None,
            halves: [client, Half::default()],
        });
    }

    fn poll_response(&mut self, k: usize, cx: &mut Context<'_>) {
        let r = &mut self.reqs[k];
        let Some(f) = &mut r.resp else {
            return;
        };
        let Poll::Ready(res) = f.as_mut().poll(cx) else {
            return;
        };
        r.resp = None;
        match res {
            Ok(resp) => {
                let st = resp.status().as_u16();
                r.status = Some(st);
                let sent = r.sent_status;
                let h = &mut r.halves[0];
                h.slot = resp.extensions().get::<DatagramSlot>().cloned();
                h.msg = Some(Msg::Resp(resp));
                self.note(format!("  response {k}: {st}"));
                if sent != Some(st) {
                    self.bad(format!("request {k} got {st}, the server sent {sent:?}"));
                }
            }
            Err(e) => self.note(format!("  response {k}: {e:?}")),
        }
    }

    fn respond(&mut self, k: usize, status: u16, body: bool) {
        let r = &mut self.reqs[k];
        let Some(reply) = r.reply.take() else {
            return;
        };
        let tunnel = r.kind == Kind::Connect && (200..300).contains(&status);
        let with_body = body && status != 204;
        let (chan, pb) = if with_body {
            let (tx, rx) = mpsc::unbounded();
            (Some(tx), PBody(Some(rx)))
        } else {
            (None, PBody(None))
        };
        let resp = Response::builder().status(status).body(pb).unwrap();
        if reply.send(resp).is_ok() {
            r.sent_status = Some(status);
            let h = &mut r.halves[1];
            h.chan = chan;
            if !with_body && !tunnel {
                h.sent_end = Some(TxEnd::Fin);
            }
        }
    }

    fn register(&mut self, k: usize, s: Side) {
        let h = &mut self.reqs[k].halves[idx(s)];
        if h.dg.is_none() {
            h.dg = h.slot.as_ref().and_then(DatagramSlot::register);
        }
    }

    /// Queue `n` bytes; `false` if they were not accepted.
    fn send_bytes(&mut self, k: usize, s: Side, n: usize, cx: &mut Context<'_>) -> bool {
        let h = &mut self.reqs[k].halves[idx(s)];
        if h.sent_end.is_some() {
            return false;
        }
        let data = pattern(k, s, h.sent, n);
        let ok = if let Some(t) = &mut h.tx {
            matches!(pin!(t.send(data)).poll(cx), Poll::Ready(Ok(())))
        } else if let Some(c) = &h.chan {
            c.unbounded_send(Ok(Frame::data(data))).is_ok()
        } else {
            false
        };
        if ok {
            h.sent += n;
        }
        ok
    }

    fn finish(&mut self, k: usize, s: Side, trailers: Option<u16>) {
        let h = &mut self.reqs[k].halves[idx(s)];
        if h.sent_end.is_some() {
            return;
        }
        if let Some(t) = &mut h.tx {
            if t.finish().is_ok() {
                h.sent_end = Some(TxEnd::Fin);
            }
        } else if let Some(c) = h.chan.take() {
            if let Some(n) = trailers {
                let mut m = HeaderMap::new();
                let v = HeaderValue::from_str(&"t".repeat(n.into())).unwrap();
                m.insert("x-t", v);
                let _ = c.unbounded_send(Ok(Frame::trailers(m)));
            }
            h.sent_end = Some(if trailers.is_some() {
                TxEnd::Trailers
            } else {
                TxEnd::Fin
            });
        }
    }

    fn upgrade(&mut self, k: usize, s: Side, cx: &mut Context<'_>) {
        let h = &mut self.reqs[k].halves[idx(s)];
        if h.up.is_none() && !h.on_called {
            let Some(m) = &mut h.msg else {
                return;
            };
            h.on_called = true;
            h.up = Some(m.on());
        }
        let Some(up) = &mut h.up else {
            return;
        };
        let Poll::Ready(r) = Pin::new(up).poll(cx) else {
            return;
        };
        h.up = None;
        match r {
            Ok(t) => {
                let (tx, rx) = t.split();
                h.tx = Some(tx);
                h.rx = Some(rx);
                self.note(format!("  {s:?} tunnel {k}"));
            }
            Err(e) => self.note(format!("  {s:?} upgrade {k}: {e:?}")),
        }
    }

    /// Poll the reader of `s` for request `k` up to `max` times; `true` once it ended.
    fn read(&mut self, k: usize, s: Side, max: usize, cx: &mut Context<'_>) -> bool {
        for _ in 0..max {
            let h = &mut self.reqs[k].halves[idx(s)];
            let (seen, tunnel) = if let Some(rx) = &mut h.rx {
                let seen = match pin!(rx.recv()).poll(cx) {
                    Poll::Pending => Seen::Pending,
                    Poll::Ready(Ok(Some(b))) => Seen::Data(b),
                    Poll::Ready(Ok(None)) => Seen::End,
                    Poll::Ready(Err(e)) => Seen::Err(e),
                };
                (seen, true)
            } else if let Some(m) = &mut h.msg {
                (body_seen(Pin::new(m.body()).poll_frame(cx)), false)
            } else {
                return true;
            };
            let end = matches!(seen, Seen::End | Seen::Err(_));
            if matches!(seen, Seen::Pending) {
                return false;
            }
            self.record(k, s, seen, tunnel);
            if end {
                return true;
            }
        }
        false
    }

    /// Check one reader observation against what the peer produced.
    fn record(&mut self, k: usize, s: Side, seen: Seen, tunnel: bool) {
        let r = &mut self.reqs[k];
        let (kind, status) = (r.kind, r.status);
        let peer = &r.halves[idx(other(s))];
        let (peer_sent, peer_end) = (peer.sent, peer.sent_end);
        let h = &mut r.halves[idx(s)];
        let who = format!("{s:?} reader of request {k}");
        let mut bad = None;
        match seen {
            Seen::Pending => {}
            Seen::Data(b) => {
                if h.got_end.is_some() {
                    bad = Some("data after its end".to_string());
                } else if b
                    .iter()
                    .enumerate()
                    .any(|(j, &x)| x != pat(k, other(s), h.got + j))
                {
                    bad = Some(format!("corrupt bytes at offset {}", h.got));
                }
                h.got += b.len();
            }
            Seen::Trailers => {
                if h.got_end.is_some() {
                    bad = Some("trailers after its end".to_string());
                }
                h.got_trailers = true;
            }
            Seen::End => {
                // A CONNECT body detached for a tunnel (or carrying none) ends at once.
                let detached = !tunnel
                    && kind == Kind::Connect
                    && (s == Side::Server || status.is_some_and(|x| (200..300).contains(&x)));
                if !detached && h.got_end.is_none() {
                    h.got_end = Some(true);
                    let trailers = peer_end == Some(TxEnd::Trailers);
                    let ok = matches!(peer_end, Some(TxEnd::Fin | TxEnd::Trailers))
                        && h.got == peer_sent
                        && (tunnel || h.got_trailers == trailers);
                    if !ok {
                        bad = Some(format!(
                            "clean end after {} bytes (trailers {}), but the peer sent {} \
                             ending {:?}",
                            h.got, h.got_trailers, peer_sent, peer_end
                        ));
                    }
                }
            }
            Seen::Err(e) => {
                if h.got_end == Some(true) {
                    bad = Some(format!("error after its clean end: {e:?}"));
                }
                h.got_end.get_or_insert(false);
                self.note(format!("  {who}: {e:?}"));
                let at = self.net.trace().len();
                self.reqs[k].halves[idx(s)].errs.push((e, at));
            }
        }
        if let Some(b) = bad {
            self.bad(format!("{who}: {b}"));
        }
    }

    /// Poll the datagram handle up to `max` times; `true` once it ended.
    fn read_dg(&mut self, k: usize, s: Side, max: usize, cx: &mut Context<'_>) -> bool {
        for _ in 0..max {
            let h = &mut self.reqs[k].halves[idx(s)];
            let Some(d) = &mut h.dg else {
                return true;
            };
            let r = match pin!(d.recv()).poll(cx) {
                Poll::Pending => return false,
                Poll::Ready(r) => r,
            };
            let ended = h.dg_end;
            let at = self.net.trace().len();
            let bad = match r {
                Ok(Some(b)) => {
                    if ended.is_some() {
                        Some("a datagram after its end".to_string())
                    } else if b.len() < 2 || b[0] as usize != k || b[1] as usize != idx(other(s)) {
                        Some(format!("a misrouted datagram {:?}", &b[..b.len().min(2)]))
                    } else {
                        None
                    }
                }
                Ok(None) => {
                    h.dg_end = Some(true);
                    (ended == Some(false)).then(|| "Ok(None) after an error".to_string())
                }
                Err(e) => {
                    h.dg_end = Some(false);
                    h.errs.push((e, at));
                    (ended == Some(true)).then(|| "an error after Ok(None)".to_string())
                }
            };
            if let Some(b) = bad {
                self.bad(format!("{s:?} datagrams of request {k}: {b}"));
            }
            if self.reqs[k].halves[idx(s)].dg_end.is_some() {
                return true;
            }
        }
        false
    }

    fn shutdown(&mut self, s: Side) {
        match s {
            Side::Client => {
                if let Some(c) = &mut self.client {
                    Pin::new(c).graceful_shutdown();
                }
            }
            Side::Server => {
                if let Some(c) = &mut self.server {
                    Pin::new(c).graceful_shutdown();
                }
            }
        }
    }

    /// One cleanup step for request `k`: answer, end producers, take pending upgrades,
    /// drain consumers. `true` while anything of it is still open.
    fn wind_down(&mut self, k: usize, cx: &mut Context<'_>) -> bool {
        // Take a client 2xx CONNECT's tunnel before its response could be dropped.
        let r = &self.reqs[k];
        let ok = r.status.is_some_and(|x| (200..300).contains(&x));
        let c = &r.halves[0];
        if r.kind == Kind::Connect && ok && !c.on_called && c.msg.is_some() {
            self.upgrade(k, Side::Client, cx);
        }
        // Then consumers: what this step's own calls abort is read after the next
        // settle, once the abort is on the wire.
        for s in [Side::Client, Side::Server] {
            if self.read(k, s, usize::MAX, cx) {
                let h = &mut self.reqs[k].halves[idx(s)];
                if h.rx.take().is_none() {
                    h.msg = None;
                }
            }
            if self.read_dg(k, s, usize::MAX, cx) {
                self.reqs[k].halves[idx(s)].dg = None;
            }
        }
        self.poll_response(k, cx);
        let r = &mut self.reqs[k];
        if r.reply.is_some() {
            let claimed = r.halves[1].on_called;
            let status = if r.kind == Kind::Connect && !claimed {
                404
            } else {
                200
            };
            self.respond(k, status, false);
        }
        for s in [Side::Client, Side::Server] {
            let h = &mut self.reqs[k].halves[idx(s)];
            if h.chan.take().is_some() {
                h.sent_end.get_or_insert(TxEnd::Fin);
            }
            if let Some(mut t) = h.tx.take() {
                if h.sent_end.is_none() && t.finish().is_ok() {
                    h.sent_end = Some(TxEnd::Fin);
                }
            }
            if self.reqs[k].halves[idx(s)].up.is_some() {
                self.upgrade(k, s, cx);
            }
        }
        let r = &self.reqs[k];
        r.resp.is_some() || r.reply.is_some() || r.halves.iter().any(Half::open)
    }

    /// Cleanup: lift every knob, end every producer, drain every consumer.
    fn cleanup(&mut self) -> Result<(), String> {
        self.note("-- cleanup".into());
        self.early_wake = false;
        self.net.readiness_before_register(false);
        for (s, id) in self.blocked.drain() {
            self.net.block_writes(s, id, false);
        }
        self.net.max_write(None);
        self.net.ack_mode(Ack::Auto);
        self.net.ack_all();
        if self.peer.is_some() {
            self.bind_control();
            for k in 0..self.reqs.len() {
                if self.reqs[k].halves[0].sent_end.is_none() {
                    self.peer_finish(k);
                }
            }
        }
        let (mut last, mut stalled) = (String::new(), 0);
        while stalled < STALL_ROUNDS {
            if !self.settle() {
                return Err("cleanup: no quiescence".into());
            }
            check(self, &self.net.trace())?;
            let waker = self.waker();
            let mut cx = Context::from_waker(&waker);
            let mut open = Vec::new();
            for k in 0..self.reqs.len() {
                if self.wind_down(k, &mut cx) {
                    open.push(k);
                }
            }
            if open.is_empty() {
                return Ok(());
            }
            let state: Vec<String> = open
                .iter()
                .map(|&k| {
                    let r = &self.reqs[k];
                    let [c, s] = &r.halves;
                    format!(
                        "   open {k}: resp {} reply {} client {:?} got {} server {:?} got {}",
                        r.resp.is_some(),
                        r.reply.is_some(),
                        c.held(),
                        c.got,
                        s.held(),
                        s.got
                    )
                })
                .collect();
            let state = state.join("\n");
            stalled = if state == last { stalled + 1 } else { 0 };
            if stalled == 0 {
                self.note(state.clone());
            }
            last = state;
        }
        Err("liveness: cleanup stalled with requests open".into())
    }

    /// Shutdown and the liveness assertion.
    fn finish_case(&mut self) -> Result<(), String> {
        for r in &mut self.reqs {
            for h in &mut r.halves {
                h.slot = None;
            }
        }
        if !self.settle() {
            return Err("no quiescence after cleanup".into());
        }
        // A closed connection reaps nothing more (a graceful close by one side may
        // overtake the other's stream teardown).
        let closed = self
            .net
            .trace()
            .iter()
            .any(|o| matches!(o, MockObs::Close { .. }));
        if self.killed_at.is_none() && !closed {
            let sides = [Side::Client, Side::Server].iter().zip(&self.shared);
            for (s, sh) in sides.filter_map(|(s, sh)| Some((s, sh.as_ref()?))) {
                let left: Vec<StreamId> = sh.with(|i| i.streams.keys().copied().collect());
                if !left.is_empty() {
                    return Err(format!("{s:?} streams never completed: {left:?}"));
                }
            }
        }
        self.note("-- shutdown".into());
        self.shutdown(Side::Client);
        self.shutdown(Side::Server);
        if !self.settle() {
            return Err("no quiescence after shutdown".into());
        }
        check(self, &self.net.trace())?;
        if self.client.is_some() || self.server.is_some() {
            return Err(format!(
                "liveness: connection still open (client {}, server {})",
                self.client.is_some(),
                self.server.is_some()
            ));
        }
        if self.exec.pending() > 0 {
            return Err(format!(
                "liveness: {} tasks still pending",
                self.exec.pending()
            ));
        }
        excuses(self, &self.net.trace())
    }
}

/// The §5.1 oracle, run after every op: the bounds and the transport-level invariants.
fn check(w: &World, mock: &[MockObs]) -> Result<(), String> {
    if let Some(v) = w.log.lock().unwrap().first() {
        return Err(v.clone());
    }
    if w.exec.panics() > 0 {
        return Err("a task panicked".into());
    }
    let sides = [Side::Client, Side::Server].into_iter().zip(&w.limits);
    for ((side, l), sh) in sides
        .zip(&w.shared)
        .filter_map(|(x, sh)| Some((x, sh.as_ref()?)))
    {
        let info = ConnInfo::new(sh.clone());
        let (queued, reservations, _) = info.__debug_recv_accounting();
        let bound = l.cap + l.demand.max(crate::state::MIN_CHARGE) * reservations;
        if queued > bound {
            return Err(format!(
                "{side:?}: {queued} body bytes queued > C + D × {reservations} = {bound}"
            ));
        }
        let (streams, out) = info.__debug_buffers();
        if out > l.dq {
            return Err(format!("{side:?}: {out} outgoing datagrams > {}", l.dq));
        }
        let (mut pn, mut pb) = (0, 0);
        for st in &streams {
            let id = st.id;
            if st.retained > l.field + 16 {
                return Err(format!(
                    "{side:?} {id:?}: {} retained raw bytes",
                    st.retained
                ));
            }
            let largest = st.send_chunks.iter().copied().max().unwrap_or(0);
            if st.send_queued != st.send_chunks.iter().sum::<usize>() {
                return Err(format!("{side:?} {id:?}: send queue miscounted"));
            }
            if st.send_queued > 0 && st.send_queued >= l.send + largest {
                return Err(format!(
                    "{side:?} {id:?}: {} bytes queued to send ≥ S {} + chunk {largest}",
                    st.send_queued, l.send
                ));
            }
            if st.dgram_queue > l.dq {
                return Err(format!(
                    "{side:?} {id:?}: {} datagrams queued",
                    st.dgram_queue
                ));
            }
            let (n, b) = st.pending_dgrams;
            if n > l.stream_cap.0 || b > l.stream_cap.1 {
                return Err(format!("{side:?} {id:?}: {n} pending datagrams, {b} bytes"));
            }
            (pn, pb) = (pn + n, pb + b);
        }
        let (_, n, b) = info.__debug_datagram_accounting();
        if (n, b) != (pn, pb) {
            return Err(format!("{side:?}: pending datagrams miscounted"));
        }
        if side == Side::Server && w.peer.is_some() && n > 0 {
            stat(Stat::PendingDatagrams);
        }
        if n > l.conn_cap.0 || b > l.conn_cap.1 {
            return Err(format!(
                "{side:?}: {n} pending datagrams, {b} bytes on the connection"
            ));
        }
        let fins = sh.with(|i| i.fin_actions.clone());
        for o in mock {
            if let MockObs::Fin { side: s, stream } = o {
                if *s == side && !fins.contains(stream) {
                    return Err(format!("{side:?} FIN on {stream:?} without FinishStream"));
                }
            }
        }
    }
    let mut seen = HashMap::new();
    for o in mock {
        let key = match o {
            MockObs::Fin { side, stream } => (0, *side, *stream),
            MockObs::Reset { side, stream, .. } => (1, *side, *stream),
            MockObs::Stop { side, stream, .. } => (2, *side, *stream),
            _ => continue,
        };
        if std::mem::replace(seen.entry(key).or_insert(false), true) {
            return Err(format!("duplicate completion {o:?}"));
        }
    }
    if w.quiet {
        cancelled(w)?;
    }
    if let Some(p) = &w.peer {
        peer_received(w, p)?;
    }
    Ok(())
}

/// After a quiescent settle, every executor task whose directions are over has been
/// cancelled, even though the world still holds what its user future waits on: a server
/// task's reply sender or response body, a client pipe's body sender.
fn cancelled(w: &World) -> Result<(), String> {
    for (k, r) in w.reqs.iter().enumerate() {
        let Some(sid) = r.sid else {
            continue;
        };
        let server = w.shared[1].as_ref().expect("async server");
        let chan = r.halves[1].chan.as_ref();
        if (r.reply.is_some() || chan.is_some()) && server.with(|i| task_over(i, sid)) {
            if r.reply.as_ref().is_some_and(|x| !x.is_canceled()) {
                return Err(format!(
                    "server task of request {k} not cancelled (Service)"
                ));
            }
            if chan.is_some_and(|c| !c.is_closed()) {
                return Err(format!(
                    "server task of request {k} not cancelled (body pipe)"
                ));
            }
        }
        let (Some(c), Some(client)) = (&r.halves[0].chan, &w.shared[0]) else {
            continue;
        };
        let over =
            client.with(|i| i.close.is_some() || i.streams.get(&sid).is_none_or(|st| st.send.done));
        if over && !c.is_closed() {
            return Err(format!("client body pipe of request {k} not cancelled"));
        }
    }
    Ok(())
}

/// What a `CorePeer` client received: the server's bytes in order, the whole of them at
/// a clean end, and the status the server sent.
fn peer_received(w: &World, p: &CorePeer<MockConn>) -> Result<(), String> {
    let finished: HashSet<StreamId> = p
        .trace()
        .iter()
        .filter_map(|o| match o {
            PeerObs::Event(Event::Finished(s)) => Some(*s),
            _ => None,
        })
        .collect();
    for (k, r) in w.reqs.iter().enumerate() {
        let Some(sid) = r.sid else {
            continue;
        };
        let body = p.body(sid);
        if let Some(o) = (0..body.len()).find(|&o| body[o] != pat(k, Side::Server, o)) {
            return Err(format!(
                "peer got corrupt bytes of request {k} at offset {o}"
            ));
        }
        let server = &r.halves[1];
        let complete = matches!(server.sent_end, Some(TxEnd::Fin | TxEnd::Trailers))
            && body.len() == server.sent;
        if finished.contains(&sid) && !complete {
            return Err(format!(
                "peer finished request {k} after {} bytes; the server sent {} ending {:?}",
                body.len(),
                server.sent,
                server.sent_end
            ));
        }
        let heads = p.headers(sid);
        let status = heads
            .first()
            .and_then(|h| h.iter().find(|(n, _)| n == ":status"));
        if let Some((_, v)) = status {
            if r.sent_status.map(|x| x.to_string()).as_ref() != Some(v) {
                return Err(format!(
                    "peer got {v} for request {k}; sent {:?}",
                    r.sent_status
                ));
            }
        }
    }
    Ok(())
}

/// Every receive-side error has a cause on the wire that came before it was seen:
/// - `StreamAborted` from the peer: the peer's RESET_STREAM on that stream;
/// - `StreamAborted` of our own (or a GOAWAY cutoff): our STOP_SENDING on it, or our
///   CONNECTION_CLOSE (a graceful close may go out before a queued STOP_SENDING);
/// - `Body` (our request body failed, so we aborted): as our own `StreamAborted`;
/// - `Closed` / `Transport`: a CONNECTION_CLOSE, or both transports killed.
///
/// So a peer STOP_SENDING, which only stops our sending, never ends receiving.
fn excuses(w: &World, mock: &[MockObs]) -> Result<(), String> {
    let first = |f: &dyn Fn(&MockObs) -> bool| mock.iter().position(f);
    let close = first(&|o| matches!(o, MockObs::Close { .. }));
    let closed = close.into_iter().chain(w.killed_at).min();
    for (k, r) in w.reqs.iter().enumerate() {
        for s in [Side::Client, Side::Server] {
            for (e, at) in &r.halves[idx(s)].errs {
                let before = |i: Option<usize>| i.is_some_and(|i| i < *at);
                let ok = match (e.kind(), r.sid) {
                    // The peer's RESET_STREAM ends our receiving; our own abort ends it
                    // with our STOP_SENDING (or our close).
                    (ErrorKind::StreamAborted { .. } | ErrorKind::Body(_), Some(sid)) => {
                        let peer = matches!(
                            e.kind(),
                            ErrorKind::StreamAborted {
                                source: AbortSource::Peer,
                                ..
                            }
                        );
                        before(first(&|o| match *o {
                            MockObs::Reset { side, stream, .. } => {
                                peer && side == other(s) && stream == sid
                            }
                            MockObs::Stop { side, stream, .. } => {
                                !peer && side == s && stream == sid
                            }
                            // Our close overtook the STOP_SENDING of our abort.
                            MockObs::Close { side, .. } => !peer && side == s,
                            _ => false,
                        }))
                    }
                    (ErrorKind::Closed { .. } | ErrorKind::Transport(_), _) => {
                        closed.is_some_and(|c| c <= *at)
                    }
                    _ => false,
                };
                if !ok {
                    return Err(format!(
                        "{s:?} receive side of request {k} ended by {e:?} (trace position {at}) \
                         with no cause before it"
                    ));
                }
            }
        }
    }
    Ok(())
}

fn run_case(setup: &Setup, ops: &[Op], trace: Log) -> Result<(), String> {
    let mut w = World::new(setup, trace);
    if w.peer.is_some() {
        stat(Stat::PeerCases);
    }
    for op in ops {
        w.apply(op);
        if !w.settle() && !w.early_wake {
            return Err(format!("no quiescence after {op:?}"));
        }
        check(&w, &w.net.trace())?;
    }
    w.cleanup()?;
    w.finish_case()
}

fn side() -> impl Strategy<Value = Side> {
    prop_oneof![Just(Side::Client), Just(Side::Server)]
}

fn op() -> impl Strategy<Value = Op> {
    let k = || 0u8..16;
    let sk = move || (side(), k());
    let kind = prop_oneof![1 => Just(Kind::Get), 2 => Just(Kind::Post), 2 => Just(Kind::Connect)];
    let status = prop_oneof![Just(200u16), Just(404), Just(204)];
    let body = prop_oneof![3 => Just(true), 1 => Just(false)];
    // Kill and DropConn end the case early: kept rare.
    prop_oneof![
        60 => (kind, any::<bool>()).prop_map(|(kind, dgram)| Op::Request { kind, dgram }),
        60 => k().prop_map(Op::PollResponse),
        9 => k().prop_map(Op::DropResponse),
        48 => (k(), status, body).prop_map(|(k, status, body)| Op::Respond { k, status, body }),
        36 => k().prop_map(Op::Accept),
        9 => k().prop_map(Op::FailService),
        120 => (side(), k(), 1u16..3000, 1u8..4).prop_map(|(s, k, n, p)| Op::Send(s, k, n, p)),
        // Large trailers may exceed the peer's field section limit: a connection error.
        24 => (side(), k(), proptest::option::weighted(0.5, prop_oneof![4 => 1u16..100, 1 => 100u16..1500]))
            .prop_map(|(s, k, t)| Op::Finish(s, k, t)),
        9 => sk().prop_map(|(s, k)| Op::Abort(s, k)),
        120 => sk().prop_map(|(s, k)| Op::Read(s, k)),
        12 => sk().prop_map(|(s, k)| Op::DropReader(s, k)),
        48 => sk().prop_map(|(s, k)| Op::Upgrade(s, k)),
        48 => sk().prop_map(|(s, k)| Op::Register(s, k)),
        60 => (side(), k(), 0u8..80).prop_map(|(s, k, n)| Op::DgSend(s, k, n)),
        36 => sk().prop_map(|(s, k)| Op::DgRecv(s, k)),
        9 => sk().prop_map(|(s, k)| Op::DropDatagrams(s, k)),
        12 => proptest::option::of(1u16..2000).prop_map(Op::MaxWrite),
        12 => (side(), 0u8..8, any::<bool>()).prop_map(|(s, n, on)| Op::Block(s, n, on)),
        9 => any::<bool>().prop_map(Op::AckManual),
        9 => Just(Op::AckAll),
        6 => any::<bool>().prop_map(Op::Loss),
        6 => any::<bool>().prop_map(Op::Reorder),
        9 => (side(), proptest::option::of(10u16..1300)).prop_map(|(s, n)| Op::MaxDatagram(s, n)),
        9 => any::<bool>().prop_map(Op::EarlyWake),
        9 => any::<bool>().prop_map(Op::Coalesce),
        6 => side().prop_map(Op::Shutdown),
        1 => Just(Op::Kill),
        // `CorePeer` client only (no-ops otherwise).
        12 => k().prop_map(Op::PeerStop),
        12 => k().prop_map(Op::PeerReset),
        12 => (k(), prop_oneof![4 => Just(Raw::Grease), 4 => Just(Raw::EmptyData), 1 => Just(Raw::Forbidden)])
            .prop_map(|(k, r)| Op::PeerRaw(k, r)),
        9 => Just(Op::BindControl),
        1 => side().prop_map(Op::DropConn),
    ]
}

fn limits() -> impl Strategy<Value = Limits> {
    (
        0usize..4000,
        0usize..8000,
        1usize..2000,
        1usize..4000,
        prop_oneof![Just(300usize), Just(1000), Just(65536)],
        1usize..=64,
        1usize..6,
        (1usize..5, 1usize..200),
        (1usize..8, 1usize..400),
    )
        .prop_map(
            |(read_ahead, cap, demand, send, field, budget, dq, stream_cap, conn_cap)| Limits {
                read_ahead,
                cap,
                demand,
                send,
                field,
                budget,
                dq,
                stream_cap,
                conn_cap,
            },
        )
}

#[test]
fn random_ops_hold_invariants() {
    // 256 cases unless PROPTEST_CASES says otherwise; failures persist under
    // proptest-regressions/.
    let config = Config {
        source_file: Some(file!()),
        ..Config::default()
    };
    let peer = prop_oneof![Just(None), any::<bool>().prop_map(Some)];
    let setup = (limits(), limits(), peer).prop_map(|(client, server, peer)| Setup {
        client,
        server,
        peer,
    });
    let strategy = (setup, proptest::collection::vec(op(), 1..120));
    let r = TestRunner::new(config).run(&strategy, |(setup, ops)| {
        run_case(&setup, &ops, Log::default()).map_err(TestCaseError::fail)
    });
    if std::env::var_os("H3WIRE_PROPS_STATS").is_some() {
        let names = [
            "peer cases",
            "peer STOP_SENDING",
            "peer RESET_STREAM",
            "raw reserved frame",
            "raw empty DATA",
            "raw forbidden frame",
            "request HEADERS before SETTINGS",
            "datagram before HEADERS",
            "pending datagram observations",
        ];
        for (n, c) in names.iter().zip(&STATS) {
            eprintln!("STATS {n}: {}", c.load(Ordering::Relaxed));
        }
    }
    let Err(e) = r else {
        return;
    };
    let TestError::Fail(why, (setup, ops)) = e else {
        panic!("{e}");
    };
    // Replay the minimal case for its op trace.
    let trace = Log::default();
    let t = trace.clone();
    let replay = std::panic::catch_unwind(AssertUnwindSafe(|| run_case(&setup, &ops, t)));
    let mut h = DefaultHasher::new();
    format!("{setup:?}{ops:?}").hash(&mut h);
    let path = format!(
        "{}/../target/h3wire-async-props-{:016x}.trace",
        env!("CARGO_MANIFEST_DIR"),
        h.finish()
    );
    let mut text = format!("{why}\nreplay: {replay:?}\n{setup:?}\n");
    for line in trace.lock().unwrap().iter() {
        text.push_str(line);
        text.push('\n');
    }
    std::fs::write(&path, text).unwrap();
    panic!("{why}; minimal case: {ops:#?}\nop trace: {path}");
}
