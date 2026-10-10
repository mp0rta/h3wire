// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 mp0rta
//! Upgrade claims and tunnels (spec §4.5): an h3wire-async client and server over
//! `MockNet`, or a `CorePeer` client where raw bytes are needed.

use super::client::drive;
use super::driver::{Out, done, poll_once, spawn, take};
use super::recv::{settle, yield_now};
use crate::__testing::exec::{TestExec, run};
use crate::__testing::{CorePeer, MockNet, MockObs, Side};
use crate::body::RecvBody;
use crate::builder::Builder;
use crate::client::SendRequest;
use crate::error::{BoxError, Error, ErrorKind};
use crate::ext::{ConnInfo, Protocol};
use crate::upgrade::{self, Tunnel};
use bytes::Bytes;
use futures::StreamExt;
use futures::channel::{mpsc, oneshot};
use h3wire::{AbortSource, Config, H3Code, Role, StreamId, UsageError};
use http::{Method, Request, Response};
use http_body::Body;
use std::future::{Future, poll_fn};
use std::pin::{Pin, pin};
use std::task::{Context, Poll};
use tower_service::Service;

const S0: StreamId = StreamId(0);
const S4: StreamId = StreamId(4);

pub(super) type Reply = oneshot::Sender<Response<String>>;
pub(super) type Handed = (Request<RecvBody>, Reply);
type Fut = Pin<Box<dyn Future<Output = Result<Response<String>, BoxError>> + Send>>;

/// A Service that hands each request to the test, with the sender for its response.
#[derive(Clone)]
pub(super) struct Handoff(pub(super) mpsc::UnboundedSender<Handed>);

impl Service<Request<RecvBody>> for Handoff {
    type Response = Response<String>;
    type Error = BoxError;
    type Future = Fut;

    fn poll_ready(&mut self, _: &mut Context<'_>) -> Poll<Result<(), BoxError>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, req: Request<RecvBody>) -> Fut {
        let (tx, rx) = oneshot::channel();
        let _ = self.0.unbounded_send((req, tx));
        Box::pin(async move { rx.await.map_err(|_| "no response".into()) })
    }
}

pub(super) struct Pair {
    pub(super) net: MockNet,
    pub(super) send: SendRequest<String>,
    pub(super) reqs: mpsc::UnboundedReceiver<Handed>,
    pub(super) exec: TestExec,
}

/// An h3wire-async client (built by `cb`) and server (built by `sb`), both spawned.
pub(super) fn pair(cb: &Builder, sb: &Builder) -> Pair {
    let (net, c, s) = MockNet::pair();
    let exec = TestExec::default();
    let (tx, reqs) = mpsc::unbounded();
    spawn(&exec, sb.serve_connection(s, Handoff(tx), exec.clone()));
    let (send, conn) = futures::executor::block_on(cb.handshake(c, exec.clone())).unwrap();
    spawn(&exec, conn);
    Pair {
        net,
        send,
        reqs,
        exec,
    }
}

pub(super) fn plain() -> Pair {
    pair(&Builder::new(), &Builder::new())
}

pub(super) fn connect() -> Request<String> {
    Request::builder()
        .method(Method::CONNECT)
        .uri("a:443")
        .body(String::new())
        .unwrap()
}

pub(super) fn reply(status: u16, body: &str) -> Response<String> {
    Response::builder()
        .status(status)
        .body(body.to_string())
        .unwrap()
}

/// Yield until `pred` holds; every spawned task runs meanwhile.
pub(super) async fn until(mut pred: impl FnMut() -> bool) {
    while !pred() {
        yield_now().await;
    }
}

/// Let every spawned task run to quiescence.
pub(super) async fn quiesce() {
    for _ in 0..64 {
        yield_now().await;
    }
}

pub(super) async fn out<T>(o: &Out<T>) -> T {
    until(|| done(o)).await;
    take(o)
}

/// Send `r`; resolve with the request the server's Service received.
pub(super) async fn request(
    p: &mut Pair,
    r: Request<String>,
) -> (Out<Result<Response<RecvBody>, Error>>, Handed) {
    let resp = spawn(&p.exec, p.send.send_request(r));
    let handed = p.reqs.next().await.expect("a request");
    (resp, handed)
}

/// A client and server tunnel on a plain CONNECT (stream 0).
async fn tunnels(p: &mut Pair) -> (Tunnel, Tunnel) {
    let (resp, (mut req, tx)) = request(p, connect()).await;
    let on = upgrade::on(&mut req);
    drop(req);
    tx.send(reply(200, "")).unwrap();
    let mut resp = out(&resp).await.expect("a response");
    let client = upgrade::on(&mut resp).await.expect("client tunnel");
    (client, on.await.expect("server tunnel"))
}

/// Everything `t` receives until FIN.
async fn read_to_end(t: &mut Tunnel) -> Vec<u8> {
    let mut v = Vec::new();
    while let Some(b) = t.recv().await.expect("no error") {
        v.extend_from_slice(&b);
    }
    v
}

pub(super) fn reset_by(net: &MockNet, side: Side, s: StreamId) -> Option<u64> {
    net.trace().iter().find_map(|o| match *o {
        MockObs::Reset {
            side: x,
            stream,
            code,
        } if x == side && stream == s => Some(code),
        _ => None,
    })
}

pub(super) fn stopped_by(net: &MockNet, side: Side, s: StreamId) -> Option<u64> {
    net.trace().iter().find_map(|o| match *o {
        MockObs::Stop {
            side: x,
            stream,
            code,
        } if x == side && stream == s => Some(code),
        _ => None,
    })
}

pub(super) fn aborted_any(net: &MockNet, s: StreamId) -> bool {
    [Side::Client, Side::Server]
        .iter()
        .any(|&x| reset_by(net, x, s).is_some() || stopped_by(net, x, s).is_some())
}

fn fin_by(net: &MockNet, side: Side, s: StreamId) -> bool {
    net.trace().contains(&MockObs::Fin { side, stream: s })
}

fn is_aborted(e: &Error, code: H3Code, source: AbortSource) -> bool {
    matches!(*e.kind(), ErrorKind::StreamAborted { code: c, source: s, .. } if c == code && s == source)
}

const RC: H3Code = H3Code::REQUEST_CANCELLED;

#[test]
fn extended_connect_tunnel_echo() {
    let mut sb = Builder::new();
    sb.enable_connect_protocol(true);
    let mut p = pair(&Builder::new(), &sb);
    let exec = p.exec.clone();
    run(&exec, async {
        let mut r = connect();
        *r.uri_mut() = "https://a/chat".parse().unwrap();
        r.extensions_mut().insert(Protocol::from_static("echo"));
        let (resp, (mut req, tx)) = request(&mut p, r).await;
        assert_eq!(
            req.extensions().get::<Protocol>(),
            Some(&Protocol::from_static("echo"))
        );
        let on = upgrade::on(&mut req);
        drop(req);
        let echo = spawn(&p.exec, async move {
            let mut t = on.await?;
            while let Some(b) = t.recv().await? {
                t.send(b).await?;
            }
            t.finish()
        });
        tx.send(reply(200, "")).unwrap();
        let mut resp = out(&resp).await.expect("a response");
        assert_eq!(resp.status(), 200);
        assert!(resp.body().is_end_stream(), "the body is detached");
        let mut t = upgrade::on(&mut resp).await.expect("a tunnel");
        t.send(Bytes::from_static(b"hello ")).await.unwrap();
        t.send(Bytes::from_static(b"world")).await.unwrap();
        t.finish().unwrap();
        assert_eq!(read_to_end(&mut t).await, b"hello world");
        out(&echo).await.expect("echo task");
        drop(t);
        quiesce().await;
    });
    assert!(!aborted_any(&p.net, S0), "{:?}", p.net.trace());
    assert!(fin_by(&p.net, Side::Client, S0) && fin_by(&p.net, Side::Server, S0));
}

/// The claim disarms the body's drop guard: dropping the request (and its body) after
/// `on` aborts nothing.
#[test]
fn claim_then_drop_request_keeps_stream() {
    let mut p = plain();
    let exec = p.exec.clone();
    run(&exec, async {
        let (resp, (mut req, tx)) = request(&mut p, connect()).await;
        let on = upgrade::on(&mut req);
        drop(req);
        quiesce().await;
        assert!(!aborted_any(&p.net, S0), "{:?}", p.net.trace());
        tx.send(reply(200, "")).unwrap();
        let mut resp = out(&resp).await.expect("a response");
        let mut c = upgrade::on(&mut resp).await.unwrap();
        let mut s = on.await.unwrap();
        c.send(Bytes::from_static(b"ping")).await.unwrap();
        assert_eq!(s.recv().await.unwrap().unwrap(), "ping");
        s.send(Bytes::from_static(b"pong")).await.unwrap();
        assert_eq!(c.recv().await.unwrap().unwrap(), "pong");
    });
    assert!(!aborted_any(&p.net, S0), "{:?}", p.net.trace());
}

/// After the claim the request body is an ended body; the bytes queued before the claim,
/// and those after, go to the tunnel.
#[test]
fn original_body_detached_after_claim() {
    let (net, c, s) = MockNet::pair();
    let exec = TestExec::default();
    let (tx, mut reqs) = mpsc::unbounded();
    spawn(
        &exec,
        Builder::new().serve_connection(s, Handoff(tx), exec.clone()),
    );
    let mut peer = CorePeer::new(Role::Client, Config::default(), c);
    run(&exec, async {
        let s = peer.open_bidi().await.unwrap();
        let fields = [(":method", "CONNECT"), (":authority", "a:443")];
        peer.send_headers(s, &fields, false).unwrap();
        peer.send_body(s, b"early", false);
        let (mut req, tx) = drive(&mut peer, &mut reqs.next()).await.unwrap();
        let info = req.extensions().get::<ConnInfo>().unwrap().clone();
        // 5 bytes, charged `MIN_CHARGE`.
        peer.run_until(|_| info.__debug_recv_accounting().0 == 64)
            .await;
        let mut on = upgrade::on(&mut req);
        assert!(req.body().is_end_stream());
        let frame = poll_fn(|cx| Pin::new(req.body_mut()).poll_frame(cx)).await;
        assert!(frame.is_none(), "EOF");
        drop(req);
        settle(&mut peer).await;
        assert_eq!(info.__debug_recv_accounting().0, 64, "kept for the tunnel");
        tx.send(reply(200, "")).unwrap();
        let mut t = drive(&mut peer, &mut on).await.expect("a tunnel");
        assert_eq!(
            drive(&mut peer, &mut pin!(t.recv()))
                .await
                .unwrap()
                .unwrap(),
            "early"
        );
        peer.send_body(s, b"late", false);
        assert_eq!(
            drive(&mut peer, &mut pin!(t.recv()))
                .await
                .unwrap()
                .unwrap(),
            "late"
        );
        assert!(super::client::has(&peer.headers(s)[0], ":status", "200"));
    });
    assert!(!aborted_any(&net, S0), "{:?}", net.trace());
    assert!(
        !fin_by(&net, Side::Server, S0),
        "a 2xx to CONNECT has no FIN"
    );
}

#[test]
fn second_on_upgrade_is_not_upgraded() {
    let mut p = plain();
    let exec = p.exec.clone();
    let not_upgraded = |r: Result<Tunnel, Error>| {
        matches!(r.expect_err("second call").kind(), ErrorKind::NotUpgraded)
    };
    run(&exec, async {
        // Not a CONNECT: nothing to take.
        let get = Request::builder().uri("https://a/").body(String::new());
        let (resp, (mut req, tx)) = request(&mut p, get.unwrap()).await;
        assert!(not_upgraded(upgrade::on(&mut req).await));
        drop(req);
        tx.send(reply(200, "")).unwrap();
        let mut resp = out(&resp).await.unwrap();
        assert!(not_upgraded(upgrade::on(&mut resp).await));
        drop(resp);

        let (resp, (mut req, tx)) = request(&mut p, connect()).await;
        let first = upgrade::on(&mut req);
        assert!(not_upgraded(upgrade::on(&mut req).await));
        tx.send(reply(200, "")).unwrap();
        let mut s = first.await.expect("the first call wins");
        let mut resp = out(&resp).await.unwrap();
        let first = upgrade::on(&mut resp);
        assert!(not_upgraded(upgrade::on(&mut resp).await));
        let mut c = first.await.expect("the first call wins");
        c.send(Bytes::from_static(b"x")).await.unwrap();
        assert_eq!(s.recv().await.unwrap().unwrap(), "x");
    });
}

/// A 2xx with nobody holding the claim is aborted with `H3_REQUEST_CANCELLED` right
/// after its HEADERS are queued (the abort may drop them before they are written): the
/// claim never taken (request still held), or gone with the request.
#[test]
fn unclaimed_2xx_aborts_request_cancelled() {
    for hold in [true, false] {
        let mut p = plain();
        let exec = p.exec.clone();
        run(&exec, async {
            let (resp, (req, tx)) = request(&mut p, connect()).await;
            // Held: the unread body is no abandoned reader, so only the 2xx can abort.
            let held = hold.then_some(req);
            tx.send(reply(200, "")).unwrap();
            until(|| reset_by(&p.net, Side::Server, S0).is_some()).await;
            // Either way there is no tunnel.
            let e = match out(&resp).await {
                Err(e) => e,
                Ok(mut resp) => match upgrade::on(&mut resp).await {
                    Ok(mut t) => t.recv().await.expect_err("aborted"),
                    Err(e) => e,
                },
            };
            assert!(is_aborted(&e, RC, AbortSource::Peer), "{e:?}");
            drop(held);
        });
        assert_eq!(reset_by(&p.net, Side::Server, S0), Some(RC.0));
        assert_eq!(stopped_by(&p.net, Side::Server, S0), Some(RC.0));
    }
}

/// The 2xx activated the claim; dropping the `OnUpgrade` before taking the tunnel aborts.
#[test]
fn drop_onupgrade_after_activation_aborts() {
    let mut p = plain();
    let exec = p.exec.clone();
    run(&exec, async {
        let (resp, (mut req, tx)) = request(&mut p, connect()).await;
        let on = upgrade::on(&mut req);
        drop(req);
        tx.send(reply(200, "")).unwrap();
        let mut resp = out(&resp).await.expect("a response");
        quiesce().await;
        assert!(!aborted_any(&p.net, S0), "{:?}", p.net.trace());
        drop(on);
        let mut t = upgrade::on(&mut resp).await.expect("client tunnel");
        let e = t.recv().await.expect_err("aborted");
        assert!(is_aborted(&e, RC, AbortSource::Peer), "{e:?}");
    });
    assert_eq!(reset_by(&p.net, Side::Server, S0), Some(RC.0));
}

/// Client: the response keeps the stream alive while its pending upgrade is inside it (a
/// cloned `Extensions` does not); dropping it, or an untaken `OnUpgrade`, aborts.
#[test]
fn client_drop_response_with_pending_upgrade_aborts() {
    let mut p = plain();
    let exec = p.exec.clone();
    run(&exec, async {
        for s in [S0, S4] {
            let (resp, (mut req, tx)) = request(&mut p, connect()).await;
            let on = upgrade::on(&mut req);
            drop(req);
            tx.send(reply(200, "")).unwrap();
            let mut server = on.await.expect("server tunnel");
            let mut resp = out(&resp).await.expect("a response");
            drop(resp.extensions().clone());
            quiesce().await;
            assert!(!aborted_any(&p.net, s), "{:?}", p.net.trace());
            if s == S0 {
                drop(resp);
            } else {
                let on = upgrade::on(&mut resp);
                drop(resp);
                quiesce().await;
                assert!(!aborted_any(&p.net, s), "the OnUpgrade holds it");
                drop(on);
            }
            let e = server.recv().await.expect_err("aborted");
            assert!(is_aborted(&e, RC, AbortSource::Peer), "{e:?}");
            assert_eq!(reset_by(&p.net, Side::Client, s), Some(RC.0));
        }
    });
}

/// A half dropped after its direction ended does nothing; a receive half dropped before
/// EOF, or a send half before `finish`, aborts the whole request.
#[test]
fn split_halves_dropped_independently() {
    let mut p = plain();
    let exec = p.exec.clone();
    run(&exec, async {
        let (c, s) = tunnels(&mut p).await;
        let (mut cs, cr) = c.split();
        let (mut ss, mut sr) = s.split();
        cs.send(Bytes::from_static(b"a")).await.unwrap();
        cs.finish().unwrap();
        drop(cs); // finished: nothing happens
        assert_eq!(sr.recv().await.unwrap().unwrap(), "a");
        assert_eq!(sr.recv().await.unwrap(), None);
        drop(sr); // at EOF: nothing happens
        ss.send(Bytes::from_static(b"b")).await.unwrap();
        quiesce().await;
        assert!(!aborted_any(&p.net, S0), "{:?}", p.net.trace());
        // Before EOF: the client aborts, the server's send half sees the STOP_SENDING.
        drop(cr);
        let e = loop {
            if let Err(e) = ss.send(Bytes::from_static(b"c")).await {
                break e;
            }
            yield_now().await;
        };
        assert!(
            matches!(e.kind(), ErrorKind::SendStopped { code } if *code == RC),
            "{e:?}"
        );
        assert_eq!(stopped_by(&p.net, Side::Client, S0), Some(RC.0));

        // A send half dropped before `finish`.
        let (resp, (mut req, tx)) = request(&mut p, connect()).await;
        let on = upgrade::on(&mut req);
        drop(req);
        tx.send(reply(200, "")).unwrap();
        let mut resp = out(&resp).await.unwrap();
        let (cs, _cr) = upgrade::on(&mut resp).await.unwrap().split();
        let mut s = on.await.unwrap();
        drop(cs);
        let e = s.recv().await.expect_err("aborted");
        assert!(is_aborted(&e, RC, AbortSource::Peer), "{e:?}");
        assert_eq!(reset_by(&p.net, Side::Client, S4), Some(RC.0));
    });
}

/// `abort` from either half aborts the whole request once; the other half sees
/// `StreamAborted { source: Local }`, the peer `StreamAborted { source: Peer }`.
#[test]
fn abort_from_either_half_after_split() {
    let mut p = plain();
    let exec = p.exec.clone();
    let msg = H3Code::MESSAGE_ERROR;
    run(&exec, async {
        let (c, mut s) = tunnels(&mut p).await;
        let (cs, mut cr) = c.split();
        cs.abort(msg);
        cs.abort(H3Code::INTERNAL_ERROR); // idempotent
        let e = cr.recv().await.expect_err("aborted");
        assert!(is_aborted(&e, msg, AbortSource::Local), "{e:?}");
        let e = s.recv().await.expect_err("aborted");
        assert!(is_aborted(&e, msg, AbortSource::Peer), "{e:?}");
        drop((cs, cr));

        let (c, mut s) = tunnels(&mut p).await;
        let (mut cs, cr) = c.split();
        cr.abort(msg);
        let e = cs
            .send(Bytes::from_static(b"x"))
            .await
            .expect_err("aborted");
        assert!(is_aborted(&e, msg, AbortSource::Local), "{e:?}");
        assert!(cs.finish().is_err());
        let e = s.recv().await.expect_err("aborted");
        assert!(is_aborted(&e, msg, AbortSource::Peer), "{e:?}");
        drop((cs, cr));
        quiesce().await;
    });
    for s in [S0, S4] {
        assert_eq!(reset_by(&p.net, Side::Client, s), Some(msg.0));
        assert_eq!(stopped_by(&p.net, Side::Client, s), Some(msg.0));
    }
    let resets = p
        .net
        .trace()
        .iter()
        .filter(|o| {
            matches!(
                o,
                MockObs::Reset {
                    side: Side::Client,
                    ..
                }
            )
        })
        .count();
    assert_eq!(resets, 2, "one abort per stream");
}

/// A non-2xx answer: no upgrade on either side, the client finishes the empty request,
/// and the response is an ordinary one.
#[test]
fn rejected_connect_finishes_request() {
    let mut p = plain();
    let exec = p.exec.clone();
    run(&exec, async {
        let (resp, (mut req, tx)) = request(&mut p, connect()).await;
        let on = upgrade::on(&mut req);
        drop(req);
        tx.send(reply(403, "nope")).unwrap();
        let e = on.await.expect_err("not upgraded");
        assert!(matches!(e.kind(), ErrorKind::NotUpgraded), "{e:?}");
        let mut resp = out(&resp).await.expect("a response");
        assert_eq!(resp.status(), 403);
        let e = upgrade::on(&mut resp).await.expect_err("not upgraded");
        assert!(matches!(e.kind(), ErrorKind::NotUpgraded), "{e:?}");
        let mut body = resp.into_body();
        let mut got = Vec::new();
        while let Some(f) = poll_fn(|cx| Pin::new(&mut body).poll_frame(cx)).await {
            got.extend_from_slice(&f.unwrap().into_data().unwrap());
        }
        assert_eq!(got, b"nope");
        until(|| fin_by(&p.net, Side::Client, S0)).await;
        quiesce().await;
    });
    assert!(!aborted_any(&p.net, S0), "{:?}", p.net.trace());
    assert!(fin_by(&p.net, Side::Server, S0));
}

#[test]
fn nonempty_2xx_connect_body_aborts_internal() {
    let mut p = plain();
    let exec = p.exec.clone();
    run(&exec, async {
        let (resp, (mut req, tx)) = request(&mut p, connect()).await;
        let on = upgrade::on(&mut req);
        drop(req);
        tx.send(reply(200, "not empty")).unwrap();
        let e = on.await.expect_err("usage");
        assert!(
            matches!(e.kind(), ErrorKind::Usage(UsageError::WrongPhase)),
            "{e:?}"
        );
        let e = out(&resp).await.expect_err("aborted");
        assert!(
            is_aborted(&e, H3Code::INTERNAL_ERROR, AbortSource::Peer),
            "{e:?}"
        );
    });
    assert_eq!(
        reset_by(&p.net, Side::Server, S0),
        Some(H3Code::INTERNAL_ERROR.0)
    );
    assert!(!fin_by(&p.net, Side::Server, S0));
}

/// `send` takes its bytes whole on admission, or not at all: a pending `send` that is
/// dropped queued nothing.
#[test]
fn tunnel_send_cancel_safety() {
    let mut cb = Builder::new();
    cb.send_capacity(8);
    let mut p = pair(&cb, &Builder::new());
    let exec = p.exec.clone();
    run(&exec, async {
        let (c, mut s) = tunnels(&mut p).await;
        let all = spawn(&p.exec, async move { read_to_end(&mut s).await });
        let (mut cs, _cr) = c.split();
        p.net.block_writes(Side::Client, S0, true);
        let mut a = Box::pin(cs.send(Bytes::from_static(b"aaaa")));
        assert!(poll_once(&mut a).await.is_ready(), "admitted: 0 < 8 queued");
        drop(a);
        let mut b = Box::pin(cs.send(Bytes::from_static(b"bbbbbbbb")));
        assert!(poll_once(&mut b).await.is_ready(), "admitted whole: 4 < 8");
        drop(b);
        quiesce().await;
        let mut dropped = Box::pin(cs.send(Bytes::from_static(b"cccc")));
        assert!(poll_once(&mut dropped).await.is_pending(), "12 >= 8 queued");
        drop(dropped);
        let mut d = Box::pin(cs.send(Bytes::from_static(b"dd")));
        assert!(poll_once(&mut d).await.is_pending());
        p.net.block_writes(Side::Client, S0, false);
        d.await.unwrap();
        cs.finish().unwrap();
        assert_eq!(out(&all).await, b"aaaabbbbbbbbdd");
    });
}

/// After the peer's FIN was read the core emits no `StreamAborted` for a local abort; the
/// send side still ends at once with `StreamAborted { code, Local }`.
#[test]
fn abort_after_recv_eof_ends_send_side() {
    let mut p = plain();
    let exec = p.exec.clone();
    let msg = H3Code::MESSAGE_ERROR;
    run(&exec, async {
        let (mut c, mut s) = tunnels(&mut p).await;
        c.finish().unwrap();
        assert_eq!(read_to_end(&mut s).await, b"");
        s.abort(msg);
        let e = s.send(Bytes::from_static(b"x")).await.expect_err("aborted");
        assert!(is_aborted(&e, msg, AbortSource::Local), "{e:?}");
        assert!(s.finish().is_err());
        until(|| reset_by(&p.net, Side::Server, S0).is_some()).await;
        drop((c, s));
        quiesce().await;
    });
    assert_eq!(reset_by(&p.net, Side::Server, S0), Some(msg.0));
}

/// A claimed CONNECT whose request already ended (FIN), then the Service fails: the
/// `OnUpgrade` resolves with the abort, and the entry is reaped.
#[test]
fn claimed_request_ended_then_service_fails() {
    let (net, c, s) = MockNet::pair();
    let exec = TestExec::default();
    let (tx, mut reqs) = mpsc::unbounded();
    let srv = Builder::new().serve_connection(s, Handoff(tx), exec.clone());
    let shared = srv.driver.shared();
    spawn(&exec, srv);
    let mut peer = CorePeer::new(Role::Client, Config::default(), c);
    run(&exec, async {
        let s = peer.open_bidi().await.unwrap();
        let fields = [(":method", "CONNECT"), (":authority", "a:443")];
        peer.send_headers(s, &fields, true).unwrap();
        let (mut req, tx) = drive(&mut peer, &mut reqs.next()).await.unwrap();
        let mut on = upgrade::on(&mut req);
        drop(req);
        peer.run_until(|_| shared.with(|i| i.streams[&s].recv.eof))
            .await;
        drop(tx); // the Service fails: no response
        let e = drive(&mut peer, &mut on).await.expect_err("no tunnel");
        assert!(
            is_aborted(&e, H3Code::INTERNAL_ERROR, AbortSource::Local),
            "{e:?}"
        );
        peer.run_until(|_| shared.with(|i| i.streams.is_empty()))
            .await;
    });
    assert_eq!(
        reset_by(&net, Side::Server, S0),
        Some(H3Code::INTERNAL_ERROR.0)
    );
}

/// Trailers the `http` crate cannot represent (a 64 KiB name) abort the stream with
/// `H3_MESSAGE_ERROR`; the reader sees the abort, not a clean EOF, and the send side ends
/// too. `inject`: the trailers and FIN reach the core in one `recv`, so `Finished` is
/// queued before the trailers are dispatched and the core emits no `StreamAborted`.
fn bad_trailers(inject: bool) {
    let (_net, c, s) = MockNet::pair();
    let exec = TestExec::default();
    let (tx, mut reqs) = mpsc::unbounded();
    let mut sb = Builder::new();
    sb.max_encoded_field_section_size(200_000);
    let srv = sb.serve_connection(s, Handoff(tx), exec.clone());
    let shared = srv.driver.shared();
    spawn(&exec, srv);
    let mut peer = CorePeer::new(Role::Client, Config::default(), c);
    let name = "a".repeat(65_536);
    run(&exec, async {
        let s = peer.open_bidi().await.unwrap();
        let fields = [
            (":method", "POST"),
            (":scheme", "https"),
            (":authority", "a"),
            (":path", "/"),
        ];
        peer.send_headers(s, &fields, false).unwrap();
        peer.send_body(s, b"abc", false);
        let (req, _tx) = drive(&mut peer, &mut reqs.next()).await.unwrap();
        let mut body = req.into_body();
        let f = super::recv::next_frame(&mut peer, &mut body).await;
        assert_eq!(f.unwrap().unwrap().into_data().unwrap(), "abc");
        if inject {
            // HEADERS: QPACK prefix, a literal field line with a literal 65536-byte
            // name (0x27 + 65529 as a 3-bit-prefix integer), value "v".
            let mut block = vec![0x00, 0x00, 0x27, 0xf9, 0xff, 0x03];
            block.extend_from_slice(name.as_bytes());
            block.extend_from_slice(&[0x01, b'v']);
            let mut frame = vec![0x01, 0x80, 0x01, 0x00, 0x08];
            assert_eq!(block.len(), 65_544);
            frame.extend_from_slice(&block);
            shared.with(|i| {
                assert!(i.conn.recv(s, &frame, true).is_ok());
                crate::driver::dispatch_events(i);
            });
        } else {
            peer.send_headers(s, &[(name.as_str(), "v")], true).unwrap();
        }
        let e = super::recv::next_frame(&mut peer, &mut body)
            .await
            .expect("not a clean EOF")
            .expect_err("aborted");
        assert!(
            is_aborted(&e, H3Code::MESSAGE_ERROR, AbortSource::Local),
            "{e:?}"
        );
        assert!(
            shared.with(|i| i.streams[&s].send.done),
            "the send side ended"
        );
    });
}

#[test]
fn unrepresentable_trailers_abort_stream() {
    bad_trailers(false);
    bad_trailers(true);
}

/// A waiting claim whose stream ends by connection close (`reset`: false) or peer RESET
/// (`true`): its `OnUpgrade` reports that cause even when the cancelled task commits
/// first.
fn claim_outlived_by(reset: bool) {
    let (net, c, s) = MockNet::pair();
    let exec = TestExec::default();
    let (tx, mut reqs) = mpsc::unbounded();
    let srv = Builder::new().serve_connection(s, Handoff(tx), exec.clone());
    let shared = srv.driver.shared();
    spawn(&exec, srv);
    let mut peer = CorePeer::new(Role::Client, Config::default(), c);
    let e = run(&exec, async {
        let s = peer.open_bidi().await.unwrap();
        let fields = [(":method", "CONNECT"), (":authority", "a:443")];
        peer.send_headers(s, &fields, false).unwrap();
        let (mut req, _reply) = drive(&mut peer, &mut reqs.next()).await.unwrap();
        let mut on = upgrade::on(&mut req);
        drop(req);
        if reset {
            peer.reset(s, H3Code::REQUEST_CANCELLED);
        } else {
            net.kill_transport(Side::Server, Some(0x10c));
        }
        // The task's `Commit` ran (the Service future is cancelled) before any poll.
        let committed = || shared.with(|i| i.streams.get(&s).is_none_or(|st| !st.recv.task_owned));
        if reset {
            peer.run_until(|_| committed()).await;
        } else {
            until(committed).await;
        }
        poll_once(&mut on).await
    });
    let Poll::Ready(Err(e)) = e else {
        panic!("the OnUpgrade must resolve with an error");
    };
    if reset {
        assert!(is_aborted(&e, RC, AbortSource::Peer), "{e:?}");
    } else {
        let transport =
            matches!(e.kind(), ErrorKind::Transport(t) if t.peer_app_code == Some(0x10c));
        assert!(transport, "{e:?}");
    }
}

#[test]
fn claim_settled_by_close_or_reset() {
    claim_outlived_by(false);
    claim_outlived_by(true);
}

/// Property-test regression: `upgrade::on` called after the request's task already ended
/// without a response (a 2xx with a body), once the body has yielded the abort, must
/// resolve rather than wait for a response that never comes.
#[test]
fn claim_after_task_ended_resolves() {
    let mut p = plain();
    let exec = p.exec.clone();
    let r = run(&exec, async {
        let (_resp, (mut req, tx)) = request(&mut p, connect()).await;
        tx.send(reply(200, "body")).unwrap();
        let e = poll_fn(|cx| Pin::new(req.body_mut()).poll_frame(cx)).await;
        assert!(matches!(e, Some(Err(_))), "{e:?}");
        quiesce().await;
        let mut on = upgrade::on(&mut req);
        poll_once(&mut on).await
    });
    assert!(matches!(r, Poll::Ready(Err(_))), "{r:?}");
}

/// Property-test regression: a claim settled without a tunnel (a non-2xx) was the request
/// body's reader. Once its `OnUpgrade` is gone, the request must still end; here without
/// read-ahead, so nothing else reads the client's FIN.
#[test]
fn failed_claim_does_not_strand_the_request() {
    let mut sb = Builder::new();
    sb.read_ahead(0);
    let mut p = pair(&Builder::new(), &sb);
    let exec = p.exec.clone();
    let left = run(&exec, async {
        let (resp, (mut req, tx)) = request(&mut p, connect()).await;
        let info = req.extensions().get::<ConnInfo>().unwrap().clone();
        let on = upgrade::on(&mut req);
        drop(req);
        tx.send(reply(404, "")).unwrap();
        let e = on.await.expect_err("no tunnel");
        assert!(matches!(e.kind(), ErrorKind::NotUpgraded), "{e:?}");
        let mut resp = out(&resp).await.expect("a response");
        assert_eq!(resp.status(), 404);
        while let Some(f) = poll_fn(|cx| Pin::new(resp.body_mut()).poll_frame(cx)).await {
            f.expect("no error");
        }
        quiesce().await;
        info.__debug_buffers().0
    });
    assert!(left.is_empty(), "streams left: {left:?}");
}
