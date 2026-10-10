// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 mp0rta
use super::driver::{done, poll_once, spawn, take};
use super::recv::{headers_frame, next_frame, settle};
use super::send::{TestBody, finished};
use crate::__testing::exec::{TestExec, run};
use crate::__testing::{CorePeer, MockConn, MockNet, MockObs, Side};
use crate::body::RecvBody;
use crate::builder::Builder;
use crate::client::{ClientConnection, SendRequest};
use crate::datagram::{DatagramSlot, RegisterDatagrams};
use crate::error::{BoxError, DatagramError, Error, ErrorKind};
use crate::ext::Protocol;
use crate::upgrade;
use bytes::Bytes;
use futures::StreamExt;
use h3wire::{AbortSource, Config, H3Code, Role, StreamId, UsageError};
use http::{Method, Request, Response};
use http_body::{Body, Frame};
use std::future::{Future, poll_fn};
use std::pin::Pin;
use std::task::Poll;

const S0: StreamId = StreamId(0);
const S4: StreamId = StreamId(4);
const S8: StreamId = StreamId(8);

type Peer = CorePeer<MockConn>;
type Resp = Result<Response<RecvBody>, Error>;

/// A client (`SendRequest` + connection) on one side of a mock pair, a server `CorePeer`
/// on the other.
pub(super) fn client<B>(
    b: &Builder,
    peer_cfg: Config,
) -> (
    MockNet,
    SendRequest<B>,
    ClientConnection<MockConn>,
    Peer,
    TestExec,
)
where
    B: Body + Send + 'static,
    B::Data: Send,
    B::Error: Into<BoxError>,
{
    let (net, c, s) = MockNet::pair();
    let peer = CorePeer::new(Role::Server, peer_cfg, s);
    let exec = TestExec::default();
    let (send, conn) = futures::executor::block_on(b.handshake(c, exec.clone())).unwrap();
    (net, send, conn, peer, exec)
}

fn req<B>(method: Method, uri: &str, body: B) -> Request<B> {
    Request::builder()
        .method(method)
        .uri(uri)
        .body(body)
        .unwrap()
}

pub(super) fn get(uri: &str) -> Request<String> {
    req(Method::GET, uri, String::new())
}

pub(super) fn has(heads: &[(String, String)], name: &str, value: &str) -> bool {
    heads.iter().any(|(n, v)| n == name && v == value)
}

pub(super) fn seen(p: &Peer, s: StreamId) -> bool {
    !p.headers(s).is_empty()
}

fn status(r: Resp) -> u16 {
    r.expect("a response").status().as_u16()
}

fn err_kind(r: Resp) -> ErrorKind {
    r.expect_err("must fail").kind().clone()
}

/// Poll `f` while stepping `peer` until `f` completes.
pub(super) async fn drive<F: Future + Unpin>(peer: &mut Peer, f: &mut F) -> F::Output {
    poll_fn(|cx| {
        loop {
            if let Poll::Ready(v) = Pin::new(&mut *f).poll(cx) {
                return Poll::Ready(v);
            }
            if peer.poll_step(cx).is_pending() {
                return Poll::Pending;
            }
        }
    })
    .await
}

/// Poll `f` (it must stay pending) while stepping `peer` until `pred` holds.
pub(super) async fn drive_until<F: Future + Unpin>(
    peer: &mut Peer,
    f: &mut F,
    mut pred: impl FnMut(&Peer) -> bool,
) {
    poll_fn(|cx| {
        loop {
            assert!(Pin::new(&mut *f).poll(cx).is_pending(), "completed early");
            if pred(peer) {
                return Poll::Ready(());
            }
            if peer.poll_step(cx).is_pending() {
                return Poll::Pending;
            }
        }
    })
    .await
}

/// The whole body and trailers of `body`.
async fn collect(peer: &mut Peer, body: &mut RecvBody) -> (Vec<u8>, Option<http::HeaderMap>) {
    let mut out = Vec::new();
    let mut trailers = None;
    while let Some(f) = next_frame(peer, body).await {
        match f.expect("no error").into_data() {
            Ok(d) => out.extend_from_slice(&d),
            Err(f) => trailers = f.into_trailers().ok(),
        }
    }
    (out, trailers)
}

#[test]
fn get_and_post_roundtrip() {
    let (_net, mut send, conn, mut peer, exec) =
        client::<String>(&Builder::new(), Config::default());
    let _drv = spawn(&exec, conn);
    run(&exec, async {
        let g = spawn(&exec, send.send_request(get("https://example.com/get?q=1")));
        peer.run_until(|p| finished(p, S0)).await;
        let h = &peer.headers(S0)[0];
        assert!(has(h, ":method", "GET") && has(h, ":scheme", "https"));
        assert!(has(h, ":authority", "example.com") && has(h, ":path", "/get?q=1"));
        assert!(peer.body(S0).is_empty());
        peer.send_headers(S0, &[(":status", "200")], false).unwrap();
        peer.send_body(S0, b"hello", true);
        peer.run_until(|_| done(&g)).await;
        let mut body = take(&g).unwrap().into_body();
        assert_eq!(
            collect(&mut peer, &mut body).await,
            (b"hello".to_vec(), None)
        );

        let post = req(
            Method::POST,
            "https://example.com/post",
            "payload".to_string(),
        );
        let p = spawn(&exec, send.send_request(post));
        peer.run_until(|p| finished(p, S4)).await;
        assert!(has(&peer.headers(S4)[0], ":method", "POST"));
        assert_eq!(peer.body(S4), b"payload");
        peer.send_headers(S4, &[(":status", "201")], false).unwrap();
        peer.send_body(S4, b"made", false);
        settle(&mut peer).await; // the DATA goes out before the trailers are queued
        peer.send_headers(S4, &[("x-t", "1")], true).unwrap();
        peer.run_until(|_| done(&p)).await;
        let resp = take(&p).unwrap();
        assert_eq!(resp.status(), 201);
        let (b, t) = collect(&mut peer, &mut resp.into_body()).await;
        assert_eq!(b, b"made");
        assert_eq!(t.unwrap()["x-t"], "1");
    });
    // Every handle is gone and both directions ended: the entries are reaped.
    assert_eq!(send.shared.with(|i| i.streams.len()), 0);
}

#[test]
fn request_body_continues_without_polling_response() {
    let (_net, mut send, conn, mut peer, exec) =
        client::<TestBody>(&Builder::new(), Config::default());
    let _drv = spawn(&exec, conn);
    // 240 KB in 8 chunks: several rounds of send admission (S = 64 KiB).
    let chunk = [5u8; 30_000];
    let body = TestBody::data(&[&chunk[..]; 8]);
    run(&exec, async {
        let mut resp = Box::pin(send.send_request(req(Method::POST, "https://a/", body)));
        assert!(poll_once(&mut resp).await.is_pending());
        // Never polled again until the whole request is through.
        peer.run_until(|p| finished(p, S0)).await;
        assert_eq!(peer.body(S0).len(), 240_000);
        peer.send_headers(S0, &[(":status", "200")], true).unwrap();
        assert_eq!(status(drive(&mut peer, &mut resp).await), 200);
    });
}

#[test]
fn request_body_sent_before_first_poll() {
    let (_net, mut send, conn, mut peer, exec) =
        client::<TestBody>(&Builder::new(), Config::default());
    let _drv = spawn(&exec, conn);
    let chunk = [6u8; 30_000];
    let body = TestBody::data(&[&chunk[..]; 8]);
    run(&exec, async {
        // Queued by the call itself: the body goes out before the future is ever polled.
        let mut resp = Box::pin(send.send_request(req(Method::POST, "https://a/", body)));
        peer.run_until(|p| finished(p, S0)).await;
        assert_eq!(peer.body(S0).len(), 240_000);
        peer.send_headers(S0, &[(":status", "200")], true).unwrap();
        assert_eq!(status(drive(&mut peer, &mut resp).await), 200);
    });
}

fn extended_connect(enabled: bool) {
    let mut cfg = Config::default();
    cfg.enable_connect_protocol = enabled;
    let (_net, mut send, conn, mut peer, exec) = client::<String>(&Builder::new(), cfg);
    peer.defer_control(true);
    let _drv = spawn(&exec, conn);
    let mut r = req(Method::CONNECT, "https://a/chat", String::new());
    r.extensions_mut()
        .insert(Protocol::from_static("websocket"));
    run(&exec, async {
        let out = spawn(&exec, send.send_request(r));
        settle(&mut peer).await;
        assert!(!done(&out), "waits for the peer's SETTINGS");
        assert!(send.peer_settings().is_none());
        peer.bind_control_now();
        if enabled {
            peer.run_until(|p| seen(p, S0)).await;
            assert!(has(&peer.headers(S0)[0], ":protocol", "websocket"));
            peer.send_headers(S0, &[(":status", "200")], false).unwrap();
            peer.run_until(|_| done(&out)).await;
            assert_eq!(status(take(&out)), 200);
            assert!(send.settings().await.unwrap().enable_connect_protocol);
        } else {
            peer.run_until(|_| done(&out)).await;
            let k = err_kind(take(&out));
            assert!(
                matches!(k, ErrorKind::Usage(UsageError::NotNegotiated)),
                "{k:?}"
            );
            settle(&mut peer).await;
            assert!(!seen(&peer, S0), "nothing sent");
        }
    });
}

#[test]
fn extended_connect_waits_for_settings() {
    extended_connect(true);
    extended_connect(false);
}

#[test]
fn connect_with_nonempty_body_is_usage() {
    let (_net, mut send, conn, mut peer, exec) =
        client::<String>(&Builder::new(), Config::default());
    let _drv = spawn(&exec, conn);
    run(&exec, async {
        let r = req(Method::CONNECT, "a:443", "x".to_string());
        let k = err_kind(send.send_request(r).await);
        assert!(matches!(k, ErrorKind::Usage(_)), "{k:?}");
        settle(&mut peer).await;
        assert!(!seen(&peer, S0), "nothing sent");
    });
}

#[test]
fn request_without_authority_is_usage() {
    let (_net, mut send, conn, mut peer, exec) =
        client::<String>(&Builder::new(), Config::default());
    let _drv = spawn(&exec, conn);
    run(&exec, async {
        let k = err_kind(send.send_request(get("/x")).await);
        assert!(
            matches!(k, ErrorKind::Usage(UsageError::InvalidField)),
            "{k:?}"
        );
        settle(&mut peer).await;
        // No stream was used: the next request (authority from Host) gets stream 0.
        let mut r = get("/y");
        r.headers_mut()
            .insert(http::header::HOST, "example.com".parse().unwrap());
        let _out = spawn(&exec, send.send_request(r));
        peer.run_until(|p| seen(p, S0)).await;
        let h = &peer.headers(S0)[0];
        assert!(has(h, ":authority", "example.com") && has(h, ":path", "/y"));
        assert!(!h.iter().any(|(n, _)| n == "host"));
    });
}

#[test]
fn goaway_makes_ready_fail_and_marks_retryable() {
    let (net, mut send, conn, mut peer, exec) =
        client::<String>(&Builder::new(), Config::default());
    net.max_bidi_streams(Side::Client, 2);
    let _drv = spawn(&exec, conn);
    run(&exec, async {
        let a = spawn(&exec, send.send_request(get("https://a/a")));
        peer.run_until(|p| seen(p, S0)).await; // processed: the cutoff is 4
        net.block_writes(Side::Client, S4, true);
        let b = spawn(&exec, send.send_request(get("https://a/b")));
        let queued = spawn(&exec, send.send_request(get("https://a/q"))); // no credit
        settle(&mut peer).await;
        assert!(!done(&b) && !done(&queued));
        assert!(send.ready().await.is_ok());
        peer.finish_shutdown().unwrap();
        peer.run_until(|_| done(&b)).await;
        let e = take(&b).unwrap_err();
        assert!(e.is_retryable(), "{e:?}");
        assert!(matches!(
            e.kind(),
            ErrorKind::StreamAborted {
                code: H3Code::REQUEST_REJECTED,
                source: AbortSource::GoAway,
                ..
            }
        ));
        // A request still waiting for its stream never starts one.
        peer.run_until(|_| done(&queued)).await;
        let k = err_kind(take(&queued));
        assert!(
            matches!(k, ErrorKind::Usage(UsageError::GoingAway)),
            "{k:?}"
        );
        settle(&mut peer).await;
        let s8 = |o: &MockObs| {
            matches!(
                o,
                MockObs::Reset {
                    stream: StreamId(8),
                    ..
                }
            )
        };
        assert!(!net.trace().iter().any(s8), "no stream opened for it");
        let k = send.ready().await.unwrap_err().kind().clone();
        assert!(
            matches!(k, ErrorKind::Usage(UsageError::GoingAway)),
            "{k:?}"
        );
        let k = err_kind(send.send_request(get("https://a/c")).await);
        assert!(
            matches!(k, ErrorKind::Usage(UsageError::GoingAway)),
            "{k:?}"
        );
        // The request below the cutoff is still served.
        peer.send_headers(S0, &[(":status", "200")], true).unwrap();
        peer.run_until(|_| done(&a)).await;
        assert_eq!(status(take(&a)), 200);
    });
}

#[test]
fn peer_request_rejected_is_retryable() {
    let (_net, mut send, conn, mut peer, exec) =
        client::<String>(&Builder::new(), Config::default());
    let _drv = spawn(&exec, conn);
    run(&exec, async {
        let r = spawn(&exec, send.send_request(get("https://a/")));
        peer.run_until(|p| seen(p, S0)).await;
        peer.reset(S0, H3Code::REQUEST_REJECTED);
        peer.run_until(|_| done(&r)).await;
        let e = take(&r).unwrap_err();
        assert!(e.is_retryable(), "{e:?}");
        assert!(matches!(
            e.kind(),
            ErrorKind::StreamAborted {
                code: H3Code::REQUEST_REJECTED,
                source: AbortSource::Peer,
                ..
            }
        ));
    });
}

#[test]
fn client_graceful_shutdown_waits_in_flight() {
    let (net, mut send, mut conn, mut peer, exec) =
        client::<String>(&Builder::new(), Config::default());
    run(&exec, async {
        let r = spawn(
            &exec,
            send.send_request(req(Method::POST, "https://a/", "abc".into())),
        );
        drive_until(&mut peer, &mut conn, |p| finished(p, S0)).await;
        Pin::new(&mut conn).graceful_shutdown();
        assert!(send.ready().await.is_err(), "new requests are refused");
        assert!(send.send_request(get("https://a/late")).await.is_err());
        for _ in 0..16 {
            drive_until(&mut peer, &mut conn, |_| true).await;
            settle(&mut peer).await;
        }
        assert_eq!(
            net.closed_with(Side::Client),
            None,
            "a request is in flight"
        );
        peer.send_headers(S0, &[(":status", "200")], false).unwrap();
        peer.send_body(S0, b"done", true);
        drive(&mut peer, &mut conn).await.expect("a clean close");
        assert_eq!(net.closed_with(Side::Client), Some(0x100));
        // The response and its body outlive the close.
        peer.run_until(|_| done(&r)).await;
        let mut body = take(&r).unwrap().into_body();
        assert_eq!(collect(&mut peer, &mut body).await.0, b"done");
    });
}

fn informational(one_chunk: bool) {
    let mut b = Builder::new();
    b.read_ahead_cap(0).read_ahead(0);
    let (_net, mut send, conn, mut peer, exec) = client::<String>(&b, Config::default());
    let _drv = spawn(&exec, conn);
    run(&exec, async {
        let r = spawn(&exec, send.send_request(get("https://a/")));
        peer.run_until(|p| finished(p, S0)).await;
        let (h100, h200) = (
            headers_frame(&[(":status", "100")]),
            headers_frame(&[(":status", "200")]),
        );
        if one_chunk {
            peer.send_raw(S0, &[h100, h200].concat());
        } else {
            peer.send_raw(S0, &h100);
            settle(&mut peer).await;
            assert!(!done(&r), "a 1xx is not the response");
            peer.send_raw(S0, &h200);
        }
        peer.run_until(|_| done(&r)).await;
        assert_eq!(status(take(&r)), 200);
    });
}

#[test]
fn send_request_after_informational_with_zero_cap() {
    informational(true);
    informational(false);
}

#[test]
fn dropped_response_future_cancels_request() {
    let (net, mut send, conn, mut peer, exec) =
        client::<String>(&Builder::new(), Config::default());
    let _drv = spawn(&exec, conn);
    run(&exec, async {
        let mut r = Box::pin(send.send_request(get("https://a/")));
        drive_until(&mut peer, &mut r, |p| seen(p, S0)).await;
        drop(r);
        let stop = MockObs::Stop {
            side: Side::Client,
            stream: S0,
            code: H3Code::REQUEST_CANCELLED.0,
        };
        peer.run_until(|_| net.trace().contains(&stop)).await;
        // Never polled: dropping it still cancels.
        let r = send.send_request(get("https://a/b"));
        peer.run_until(|p| seen(p, S4)).await;
        drop(r);
        let stop = MockObs::Stop {
            side: Side::Client,
            stream: S4,
            code: H3Code::REQUEST_CANCELLED.0,
        };
        peer.run_until(|_| net.trace().contains(&stop)).await;
    });
}

#[test]
fn peer_bidi_stream_is_connection_error() {
    let (net, _send, conn, mut peer, exec) = client::<String>(&Builder::new(), Config::default());
    let drv = spawn(&exec, conn);
    run(&exec, async {
        peer.open_bidi().await.unwrap();
        peer.run_until(|_| done(&drv)).await;
    });
    let k = take(&drv).unwrap_err().kind().clone();
    assert!(
        matches!(
            k,
            ErrorKind::Closed {
                code: H3Code::STREAM_CREATION_ERROR,
                by_peer: false
            }
        ),
        "{k:?}"
    );
    assert_eq!(net.closed_with(Side::Client), Some(0x103));
}

/// Live handles of every kind when `fail` strikes: the driver, a live `RecvBody`, a
/// `send_request` waiting for its response, a `Tunnel` waiting to receive, a `Datagrams`
/// waiting to receive, and one `send_request` waiting for stream credit. The datagram
/// and tunnel errors come last in the list (`Datagrams::send` must fail `Closed`).
fn every_handle(
    fail: impl FnOnce(&MockNet, &mut Peer),
) -> (Result<(), Error>, ErrorKind, Vec<ErrorKind>) {
    let (net, mut send, conn, mut peer, exec) =
        client::<String>(&Builder::new(), Config::default());
    net.max_bidi_streams(Side::Client, 3);
    let drv = spawn(&exec, conn);
    let (body, pending, tunnel) = run(&exec, async {
        let mut ra = get("https://a/a");
        ra.extensions_mut().insert(RegisterDatagrams);
        let a = spawn(&exec, send.send_request(ra));
        peer.run_until(|p| seen(p, S0)).await;
        peer.send_headers(S0, &[(":status", "200")], false).unwrap();
        peer.run_until(|_| done(&a)).await;
        let ra = take(&a).unwrap();
        let slot = ra.extensions().get::<DatagramSlot>().unwrap();
        let mut dg = slot.register().expect("datagrams");
        let dgram = spawn(&exec, async move {
            let r = dg.recv().await;
            (r, dg.send(bytes::Bytes::from_static(b"x")))
        });
        let mut rb = ra.into_body();
        let body = spawn(&exec, async move {
            poll_fn(|cx| Pin::new(&mut rb).poll_frame(cx)).await
        });
        let b = spawn(&exec, send.send_request(get("https://a/b")));
        peer.run_until(|p| seen(p, S4)).await;
        let t = spawn(
            &exec,
            send.send_request(req(Method::CONNECT, "a:443", String::new())),
        );
        peer.run_until(|p| seen(p, S8)).await;
        peer.send_headers(S8, &[(":status", "200")], false).unwrap();
        peer.run_until(|_| done(&t)).await;
        let mut resp = take(&t).unwrap();
        let tunnel = spawn(&exec, async move {
            let mut t = upgrade::on(&mut resp).await.expect("a tunnel");
            t.recv().await
        });
        let c = spawn(&exec, send.send_request(get("https://a/c")));
        settle(&mut peer).await;
        assert!(!done(&body) && !done(&b) && !done(&c) && !done(&tunnel) && !done(&drv));
        assert!(!done(&dgram));
        fail(&net, &mut peer);
        let all = |_: &Peer| {
            done(&drv) && done(&body) && done(&b) && done(&c) && done(&tunnel) && done(&dgram)
        };
        peer.run_until(all).await;
        (body, vec![b, c], (tunnel, dgram))
    });
    let (tunnel, dgram) = tunnel;
    let body = take(&body).expect("a frame").unwrap_err().kind().clone();
    let mut pending: Vec<_> = pending.iter().map(|o| err_kind(take(o))).collect();
    let (recv, sent) = take(&dgram);
    assert_eq!(sent, Err(DatagramError::Closed));
    pending.push(recv.expect_err("must fail").kind().clone());
    pending.push(take(&tunnel).expect_err("must fail").kind().clone());
    (take(&drv), body, pending)
}

#[test]
fn connection_error_reaches_every_handle() {
    let (drv, body, pending) = every_handle(|_, peer| {
        // A HEADERS frame header declaring 2^20 bytes.
        peer.send_raw(S4, &[0x01, 0x80, 0x10, 0x00, 0x00]);
    });
    let excessive = |k: &ErrorKind| {
        matches!(
            k,
            ErrorKind::Closed {
                code: H3Code::EXCESSIVE_LOAD,
                by_peer: false
            }
        )
    };
    assert!(excessive(drv.unwrap_err().kind()));
    assert!(excessive(&body), "{body:?}");
    assert!(pending.iter().all(excessive), "{pending:?}");
}

#[test]
fn transport_failure_keeps_cause() {
    let (drv, body, pending) = every_handle(|net, _| net.kill_transport(Side::Client, Some(0x10c)));
    let cause =
        |k: &ErrorKind| matches!(k, ErrorKind::Transport(e) if e.peer_app_code == Some(0x10c));
    assert!(cause(drv.unwrap_err().kind()));
    assert!(cause(&body), "{body:?}");
    assert!(pending.iter().all(cause), "{pending:?}");
}

#[test]
fn peer_no_error_close_is_clean() {
    let (drv, body, pending) = every_handle(|net, _| net.kill_transport(Side::Client, Some(0x100)));
    drv.expect("the peer closed with H3_NO_ERROR");
    // Handles keep the cause (spec §4.7).
    let cause =
        |k: &ErrorKind| matches!(k, ErrorKind::Transport(e) if e.peer_app_code == Some(0x100));
    assert!(cause(&body), "{body:?}");
    assert!(pending.iter().all(cause), "{pending:?}");
}

#[test]
fn peer_transport_no_error_close_is_clean() {
    let (drv, body, pending) = every_handle(|net, _| net.close_transport(Side::Client, 0));
    drv.expect("the peer closed with the transport's NO_ERROR");
    // Handles keep the cause.
    let cause =
        |k: &ErrorKind| matches!(k, ErrorKind::Transport(e) if e.peer_transport_code == Some(0));
    assert!(cause(&body), "{body:?}");
    assert!(pending.iter().all(cause), "{pending:?}");
}

#[test]
fn peer_transport_error_close_is_not_clean() {
    let (drv, _, _) = every_handle(|net, _| net.close_transport(Side::Client, 0xa));
    let k = drv.unwrap_err().kind().clone();
    assert!(
        matches!(&k, ErrorKind::Transport(e) if e.peer_transport_code == Some(0xa)),
        "{k:?}"
    );
}

/// The peer sends whole responses and closes before the client driver read them; the
/// transport still holds the bytes (as quinn does). They are delivered before the
/// close fails the handles: the head, the body, the trailers (decoded only once the
/// head is) and FIN; an unfinished response gets its data, then the close.
#[test]
fn data_held_by_transport_at_peer_close_is_delivered() {
    let (net, mut send, mut conn, mut peer, exec) =
        client::<String>(&Builder::new(), Config::default());
    net.readable_after_close(true);
    run(&exec, async {
        let mut a = Box::pin(send.send_request(get("https://a/a")));
        let mut b = Box::pin(send.send_request(get("https://a/b")));
        drive_until(&mut peer, &mut conn, |p| finished(p, S0) && finished(p, S4)).await;
        peer.send_headers(S0, &[(":status", "200")], false).unwrap();
        peer.send_body(S0, b"done", false);
        settle(&mut peer).await; // the body goes out before the trailers
        peer.send_headers(S0, &[("x-check", "ok")], true).unwrap();
        peer.send_headers(S4, &[(":status", "200")], false).unwrap();
        peer.send_body(S4, b"par", false);
        settle(&mut peer).await; // the client driver is not polled meanwhile
        net.kill_transport(Side::Client, Some(0x100));
        let (ra, rb) = poll_fn(|cx| {
            let _ = Pin::new(&mut conn).poll(cx);
            match (a.as_mut().poll(cx), b.as_mut().poll(cx)) {
                (Poll::Ready(a), Poll::Ready(b)) => Poll::Ready((a, b)),
                _ => Poll::Pending,
            }
        })
        .await;
        let (body, trailers) = collect(&mut peer, ra.expect("a's response").body_mut()).await;
        assert_eq!(body, b"done");
        assert_eq!(trailers.expect("trailers")["x-check"], "ok");
        let mut rb = rb.expect("b's response").into_body();
        assert_eq!(
            next_frame(&mut peer, &mut rb)
                .await
                .unwrap()
                .unwrap()
                .into_data()
                .unwrap(),
            "par"
        );
        let e = next_frame(&mut peer, &mut rb).await.unwrap().unwrap_err();
        assert!(matches!(e.kind(), ErrorKind::Transport(_)), "{e:?}");
        conn.await.expect("the peer closed with H3_NO_ERROR");
    });
}

/// Dropping the last `SendRequest` starts a graceful shutdown: with nothing in flight
/// the driver resolves `Ok` and closes with `H3_NO_ERROR`; a live clone keeps it open.
#[test]
fn dropping_every_sender_closes_idle_connection() {
    let (net, send, conn, mut peer, exec) = client::<String>(&Builder::new(), Config::default());
    let drv = spawn(&exec, conn);
    let clone = send.clone();
    drop(send);
    run(&exec, settle(&mut peer));
    assert!(!done(&drv), "a clone is alive");
    drop(clone);
    run(&exec, settle(&mut peer));
    assert!(done(&drv), "the driver ended");
    take(&drv).expect("a clean close");
    assert_eq!(net.closed_with(Side::Client), Some(0x100));
}

/// With a request in flight, the driver of a client whose senders are all gone waits
/// for it, then closes cleanly.
#[test]
fn dropping_every_sender_waits_in_flight() {
    let (net, mut send, conn, mut peer, exec) =
        client::<String>(&Builder::new(), Config::default());
    let drv = spawn(&exec, conn);
    run(&exec, async {
        let r = spawn(
            &exec,
            send.send_request(req(Method::POST, "https://a/", "abc".into())),
        );
        peer.run_until(|p| finished(p, S0)).await;
        drop(send);
        for _ in 0..4 {
            settle(&mut peer).await;
        }
        assert!(!done(&drv), "a request is in flight");
        assert_eq!(net.closed_with(Side::Client), None);
        peer.send_headers(S0, &[(":status", "200")], false).unwrap();
        peer.send_body(S0, b"done", true);
        peer.run_until(|_| done(&r)).await;
        let mut body = take(&r).unwrap().into_body();
        assert_eq!(collect(&mut peer, &mut body).await.0, b"done");
        for _ in 0..4 {
            settle(&mut peer).await;
        }
        assert!(done(&drv), "the driver ended");
    });
    take(&drv).expect("a clean close");
    assert_eq!(net.closed_with(Side::Client), Some(0x100));
}

/// A request body fed through a channel.
struct ChanBody(futures::channel::mpsc::UnboundedReceiver<Result<Frame<Bytes>, BoxError>>);

impl Body for ChanBody {
    type Data = Bytes;
    type Error = BoxError;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, BoxError>>> {
        self.0.poll_next_unpin(cx)
    }
}

#[derive(Debug)]
struct Boom;

impl std::fmt::Display for Boom {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("boom")
    }
}

impl std::error::Error for Boom {}

/// A failing request body reaches the application as `ErrorKind::Body`, whose source is
/// the body's own error: through `send_request` before the response, through the
/// response's `RecvBody` after it. The peer sees `H3_INTERNAL_ERROR`.
fn request_body_error(after_response: bool) {
    let (net, mut send, conn, mut peer, exec) =
        client::<ChanBody>(&Builder::new(), Config::default());
    let _drv = spawn(&exec, conn);
    let (tx, rx) = futures::channel::mpsc::unbounded();
    tx.unbounded_send(Ok(Frame::data(Bytes::from_static(b"abc"))))
        .unwrap();
    let e = run(&exec, async {
        let post = req(Method::POST, "https://a/", ChanBody(rx));
        let r = spawn(&exec, send.send_request(post));
        peer.run_until(|p| p.body(S0) == b"abc").await;
        let mut body = None;
        if after_response {
            peer.send_headers(S0, &[(":status", "200")], false).unwrap();
            peer.run_until(|_| done(&r)).await;
            body = Some(take(&r).unwrap().into_body());
        }
        tx.unbounded_send(Err(Box::new(Boom))).unwrap();
        match body {
            Some(mut b) => next_frame(&mut peer, &mut b)
                .await
                .expect("an error")
                .unwrap_err(),
            None => {
                peer.run_until(|_| done(&r)).await;
                take(&r).unwrap_err()
            }
        }
    });
    assert!(matches!(e.kind(), ErrorKind::Body(_)), "{e:?}");
    let src = std::error::Error::source(&e).expect("a source");
    assert!(src.downcast_ref::<Boom>().is_some(), "{src:?}");
    let reset = MockObs::Reset {
        side: Side::Client,
        stream: S0,
        code: H3Code::INTERNAL_ERROR.0,
    };
    assert!(net.trace().contains(&reset), "{:?}", net.trace());
}

#[test]
fn request_body_error_is_body_kind() {
    request_body_error(false);
    request_body_error(true);
}

/// `send_capacity(0)` counts as 1: a body is still admitted and sent.
#[test]
fn zero_send_capacity_still_sends() {
    let mut b = Builder::new();
    b.send_capacity(0);
    let (_net, mut send, conn, mut peer, exec) = client::<String>(&b, Config::default());
    let _drv = spawn(&exec, conn);
    run(&exec, async {
        let _r = send.send_request(req(Method::POST, "https://a/", "abc".into()));
        for _ in 0..8 {
            settle(&mut peer).await;
        }
        assert_eq!(peer.body(S0), b"abc");
        assert!(finished(&peer, S0));
    });
}
