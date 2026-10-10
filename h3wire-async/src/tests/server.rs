// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 mp0rta
use super::client::{drive, drive_until, has};
use super::driver::{done, spawn, take};
use super::recv::{headers_frame, settle};
use super::send::finished;
use crate::__testing::exec::{TestExec, run};
use crate::__testing::{Ack, CorePeer, MockConn, MockNet, MockObs, PeerObs, Side};
use crate::body::RecvBody;
use crate::builder::Builder;
use crate::error::{BoxError, ErrorKind};
use crate::ext::ConnInfo;
use crate::server::ServerConnection;
use crate::state::Shared;
use bytes::Bytes;
use futures::StreamExt;
use futures::channel::{mpsc, oneshot};
use h3wire::{AbortSource, Config, Event, H3Code, Role, StreamId};
use http::{HeaderMap, Method, Request, Response};
use http_body::{Body, Frame};
use std::future::{Future, poll_fn};
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker};
use tower_service::Service;

const S0: StreamId = StreamId(0);
const S4: StreamId = StreamId(4);
const S8: StreamId = StreamId(8);
const S12: StreamId = StreamId(12);

type Peer = CorePeer<MockConn>;
type Frm = Result<Frame<Bytes>, BoxError>;
type Fut = Pin<Box<dyn Future<Output = Result<Response<ChanBody>, BoxError>> + Send>>;

/// A response body fed through a channel; it ends when the sender is dropped. An error
/// whose message is "panic" panics instead.
struct ChanBody(mpsc::UnboundedReceiver<Frm>);

impl ChanBody {
    fn new() -> (mpsc::UnboundedSender<Frm>, Self) {
        let (tx, rx) = mpsc::unbounded();
        (tx, ChanBody(rx))
    }

    fn of(chunks: &[&[u8]]) -> Self {
        let (tx, b) = Self::new();
        for c in chunks {
            tx.unbounded_send(Ok(Frame::data(Bytes::copy_from_slice(c))))
                .unwrap();
        }
        b
    }
}

impl Body for ChanBody {
    type Data = Bytes;
    type Error = BoxError;

    fn poll_frame(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Frm>> {
        let r = self.0.poll_next_unpin(cx);
        if let Poll::Ready(Some(Err(e))) = &r {
            assert_ne!(e.to_string(), "panic", "body panic (expected by the test)");
        }
        r
    }
}

fn data(tx: &mpsc::UnboundedSender<Frm>, b: &[u8]) {
    tx.unbounded_send(Ok(Frame::data(Bytes::copy_from_slice(b))))
        .unwrap();
}

/// Closes `poll_ready` while shut; a stored error is returned once by `poll_ready`.
#[derive(Clone, Default)]
struct Gate(Arc<Mutex<GateState>>);

/// Shut, the waiting waker, the error to fail with.
type GateState = (bool, Option<Waker>, Option<BoxError>);

impl Gate {
    fn shut(&self, shut: bool) {
        let mut g = self.0.lock().unwrap();
        g.0 = shut;
        if let Some(w) = g.1.take().filter(|_| !shut) {
            w.wake();
        }
    }
}

/// A Service from a closure.
#[derive(Clone)]
struct Svc<F> {
    f: F,
    gate: Gate,
}

impl<F: FnMut(Request<RecvBody>) -> Fut> Service<Request<RecvBody>> for Svc<F> {
    type Response = Response<ChanBody>;
    type Error = BoxError;
    type Future = Fut;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), BoxError>> {
        let mut g = self.gate.0.lock().unwrap();
        if let Some(e) = g.2.take() {
            return Poll::Ready(Err(e));
        }
        if g.0 {
            g.1 = Some(cx.waker().clone());
            return Poll::Pending;
        }
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, req: Request<RecvBody>) -> Fut {
        (self.f)(req)
    }
}

type Conn<F> = ServerConnection<MockConn, Svc<F>, TestExec>;

struct Server<F> {
    net: MockNet,
    conn: Conn<F>,
    peer: Peer,
    exec: TestExec,
    gate: Gate,
    shared: Shared,
}

/// A server on one side of a mock pair, a client `CorePeer` on the other.
fn server<F>(f: F) -> Server<F>
where
    F: FnMut(Request<RecvBody>) -> Fut + Clone + Send + 'static,
{
    let (net, c, s) = MockNet::pair();
    let peer = CorePeer::new(Role::Client, Config::default(), c);
    let exec = TestExec::default();
    let gate = Gate::default();
    let svc = Svc {
        f,
        gate: gate.clone(),
    };
    let conn = Builder::new().serve_connection(s, svc, exec.clone());
    let shared = conn.driver.shared();
    Server {
        net,
        conn,
        peer,
        exec,
        gate,
        shared,
    }
}

fn req(method: &'static str, path: &'static str) -> [(&'static str, &'static str); 4] {
    [
        (":method", method),
        (":scheme", "https"),
        (":authority", "a"),
        (":path", path),
    ]
}

/// Open a stream and send HEADERS (`end`: no body).
async fn open(peer: &mut Peer, fields: &[(&str, &str)], end: bool) -> StreamId {
    let s = peer.open_bidi().await.unwrap();
    peer.send_headers(s, fields, end).unwrap();
    s
}

fn respond(status: u16, body: ChanBody) -> Result<Response<ChanBody>, BoxError> {
    Ok(Response::builder().status(status).body(body).unwrap())
}

/// The whole body and trailers.
async fn read_all(body: &mut RecvBody) -> (Vec<u8>, Option<HeaderMap>) {
    let mut out = Vec::new();
    let mut trailers = None;
    while let Some(f) = poll_fn(|cx| Pin::new(&mut *body).poll_frame(cx)).await {
        match f.expect("no error").into_data() {
            Ok(d) => out.extend_from_slice(&d),
            Err(f) => trailers = f.into_trailers().ok(),
        }
    }
    (out, trailers)
}

fn aborted(p: &Peer, s: StreamId, code: H3Code) -> bool {
    p.trace().contains(&PeerObs::Event(Event::StreamAborted {
        stream: s,
        code,
        source: AbortSource::Peer,
    }))
}

fn statuses(p: &Peer, s: StreamId) -> Vec<String> {
    p.headers(s)
        .iter()
        .filter_map(|h| {
            h.iter()
                .find(|(n, _)| n == ":status")
                .map(|(_, v)| v.clone())
        })
        .collect()
}

/// Server resets (`stop`: false) or STOP_SENDINGs (`true`) on `s` with `code`.
fn server_sent(net: &MockNet, s: StreamId, code: H3Code, stop: bool) -> bool {
    net.trace().iter().any(|o| match *o {
        MockObs::Reset {
            side: Side::Server,
            stream,
            code: c,
        } => !stop && stream == s && c == code.0,
        MockObs::Stop {
            side: Side::Server,
            stream,
            code: c,
        } => stop && stream == s && c == code.0,
        _ => false,
    })
}

fn server_aborted_any(net: &MockNet, s: StreamId) -> bool {
    net.trace().iter().any(|o| {
        matches!(*o, MockObs::Reset { side: Side::Server, stream, .. }
            | MockObs::Stop { side: Side::Server, stream, .. } if stream == s)
    })
}

/// A body slot the Service takes its response body from.
type Slot = Arc<Mutex<Option<ChanBody>>>;

fn slot(b: ChanBody) -> Slot {
    Arc::new(Mutex::new(Some(b)))
}

#[test]
fn serve_get_post_trailers() {
    let mut s = server(|req: Request<RecvBody>| -> Fut {
        Box::pin(async move {
            let (parts, mut body) = req.into_parts();
            assert!(parts.extensions.get::<ConnInfo>().is_some());
            let (got, trailers) = read_all(&mut body).await;
            let (tx, b) = ChanBody::new();
            if parts.method == Method::GET {
                data(&tx, b"hello");
            } else {
                data(&tx, &got);
                let mut t = HeaderMap::new();
                t.insert("x-echo", trailers.unwrap()["x-t"].clone());
                tx.unbounded_send(Ok(Frame::trailers(t))).unwrap();
            }
            Ok(Response::builder()
                .status(200)
                .header("x-path", parts.uri.path())
                .header("connection", "close")
                .body(b)
                .unwrap())
        })
    });
    let _srv = spawn(&s.exec, s.conn);
    run(&s.exec, async {
        let a = open(&mut s.peer, &req("GET", "/get"), true).await;
        s.peer.run_until(|p| finished(p, a)).await;
        let h = &s.peer.headers(a)[0];
        assert!(has(h, ":status", "200") && has(h, "x-path", "/get"));
        assert!(!h.iter().any(|(n, _)| n == "connection"));
        assert_eq!(s.peer.body(a), b"hello");

        let p = open(&mut s.peer, &req("POST", "/post"), false).await;
        s.peer.send_body(p, b"payload", false);
        settle(&mut s.peer).await; // the DATA goes out before the trailers are queued
        s.peer.send_headers(p, &[("x-t", "1")], true).unwrap();
        s.peer.run_until(|p2| finished(p2, p)).await;
        assert_eq!(s.peer.body(p), b"payload");
        let h = s.peer.headers(p);
        assert!(has(&h[0], ":status", "200") && has(&h[0], "x-path", "/post"));
        assert_eq!(h[1], vec![("x-echo".to_string(), "1".to_string())]);
        settle(&mut s.peer).await;
    });
    // Both requests are over and no handle is left: their entries are reaped.
    assert_eq!(s.shared.with(|i| i.streams.len()), 0);
    assert_eq!(s.shared.with(|i| i.retained.len()), 0);
}

#[test]
fn poll_ready_gates_accept() {
    let mut s = server(|_| -> Fut { Box::pin(async { respond(200, ChanBody::of(&[b"ok"])) }) });
    s.gate.shut(true);
    let _srv = spawn(&s.exec, s.conn);
    run(&s.exec, async {
        settle(&mut s.peer).await;
        assert_eq!(s.net.pending_accepts(Side::Server), 0);
        open(&mut s.peer, &req("GET", "/a"), true).await;
        settle(&mut s.peer).await;
        assert_eq!(s.net.pending_accepts(Side::Server), 1);
        open(&mut s.peer, &req("GET", "/b"), true).await;
        settle(&mut s.peer).await;
        assert_eq!(s.net.pending_accepts(Side::Server), 2);
        assert!(s.peer.headers(S0).is_empty());
        s.gate.shut(false);
        s.peer
            .run_until(|p| finished(p, S0) && finished(p, S4))
            .await;
        assert_eq!(s.net.pending_accepts(Side::Server), 0);
        assert_eq!(s.peer.body(S4), b"ok");
    });
}

#[test]
fn service_panic_aborts_stream_only() {
    let mut s = server(|req: Request<RecvBody>| -> Fut {
        Box::pin(async move {
            if req.uri().path() == "/panic" {
                panic!("service panic (expected by the test)");
            }
            respond(200, ChanBody::of(&[b"ok"]))
        })
    });
    let srv = spawn(&s.exec, s.conn);
    run(&s.exec, async {
        let a = open(&mut s.peer, &req("GET", "/panic"), true).await;
        let b = open(&mut s.peer, &req("GET", "/ok"), true).await;
        s.peer
            .run_until(|p| aborted(p, a, H3Code::INTERNAL_ERROR) && finished(p, b))
            .await;
        assert_eq!(s.peer.body(b), b"ok");
        // The connection lives on.
        let c = open(&mut s.peer, &req("GET", "/ok"), true).await;
        s.peer.run_until(|p| finished(p, c)).await;
    });
    assert!(!done(&srv));
}

#[test]
fn service_error_aborts_internal_error() {
    let mut s = server(|_| -> Fut { Box::pin(async { Err("nope".into()) }) });
    let _srv = spawn(&s.exec, s.conn);
    run(&s.exec, async {
        let a = open(&mut s.peer, &req("GET", "/"), true).await;
        s.peer
            .run_until(|p| aborted(p, a, H3Code::INTERNAL_ERROR))
            .await;
        assert!(s.peer.headers(a).is_empty());
    });
}

fn owned_unread_body(panic: bool) {
    let mut s = server(move |req: Request<RecvBody>| -> Fut {
        Box::pin(async move {
            let _unread = req.into_body();
            if panic {
                panic!("service panic (expected by the test)");
            }
            Err("nope".into())
        })
    });
    let _srv = spawn(&s.exec, s.conn);
    run(&s.exec, async {
        let a = open(&mut s.peer, &req("POST", "/"), false).await;
        s.peer.send_body(a, b"abc", false);
        s.peer
            .run_until(|p| aborted(p, a, H3Code::INTERNAL_ERROR))
            .await;
        settle(&mut s.peer).await;
        assert!(!aborted(&s.peer, a, H3Code::REQUEST_CANCELLED));
    });
    assert!(server_sent(&s.net, S0, H3Code::INTERNAL_ERROR, true));
    assert!(!server_sent(&s.net, S0, H3Code::REQUEST_CANCELLED, true));
    assert!(!server_sent(&s.net, S0, H3Code::REQUEST_CANCELLED, false));
}

#[test]
fn failure_with_owned_unread_body_is_internal_error() {
    owned_unread_body(true);
    owned_unread_body(false);
}

#[test]
fn service_failure_after_100_continue_is_internal_error() {
    let mut s = server(|req: Request<RecvBody>| -> Fut {
        Box::pin(async move {
            let (got, _) = read_all(&mut req.into_body()).await;
            assert_eq!(got, b"abc");
            Err("after continue".into())
        })
    });
    let _srv = spawn(&s.exec, s.conn);
    run(&s.exec, async {
        let mut fields = req("POST", "/").to_vec();
        fields.push(("expect", "100-continue"));
        let a = open(&mut s.peer, &fields, false).await;
        s.peer.run_until(|p| !p.headers(a).is_empty()).await;
        s.peer.send_body(a, b"abc", true);
        s.peer
            .run_until(|p| aborted(p, a, H3Code::INTERNAL_ERROR))
            .await;
        assert_eq!(statuses(&s.peer, a), ["100"]);
    });
}

fn body_failure_after_final_headers(err: &str) {
    let (tx, body) = ChanBody::new();
    let body = slot(body);
    let mut s = server(move |_| -> Fut {
        let b = body.lock().unwrap().take().unwrap();
        Box::pin(async move { respond(200, b) })
    });
    let _srv = spawn(&s.exec, s.conn);
    run(&s.exec, async {
        data(&tx, b"part");
        let a = open(&mut s.peer, &req("GET", "/"), true).await;
        s.peer.run_until(|p| p.body(a) == b"part").await;
        tx.unbounded_send(Err(err.into())).unwrap();
        s.peer
            .run_until(|p| aborted(p, a, H3Code::INTERNAL_ERROR))
            .await;
        assert_eq!(statuses(&s.peer, a), ["200"]);
    });
}

/// A body error, or a panic inside the body pipe (only the unwinding guard sees that one:
/// the final HEADERS are already out).
#[test]
fn response_body_error_after_final_headers_is_internal_error() {
    body_failure_after_final_headers("boom");
    body_failure_after_final_headers("panic");
}

/// The request body is dropped unfinished: once the complete response went out, reading
/// stops with `H3_REQUEST_CANCELLED`; the response is not reset.
#[test]
fn dropped_body_after_response_is_request_cancelled() {
    let (tx, body) = ChanBody::new();
    let body = slot(body);
    let mut s = server(move |req: Request<RecvBody>| -> Fut {
        let b = body.lock().unwrap().take().unwrap();
        // The request body is dropped, unfinished, as the Service future completes.
        Box::pin(async move {
            let _unfinished = req.into_body();
            respond(200, b)
        })
    });
    let _srv = spawn(&s.exec, s.conn);
    run(&s.exec, async {
        data(&tx, b"x");
        let a = open(&mut s.peer, &req("POST", "/"), false).await;
        s.peer.send_body(a, b"abc", false);
        s.peer.run_until(|p| p.body(a) == b"x").await;
        assert_eq!(statuses(&s.peer, a), ["200"]);
        drop(tx); // the response ends: the task ends
        let rc = H3Code::REQUEST_CANCELLED;
        s.peer
            .run_until(|p| finished(p, a) || aborted(p, a, rc))
            .await;
        assert!(finished(&s.peer, a), "the response was reset");
        assert_eq!(s.peer.body(a), b"x");
        s.peer
            .run_until(|_| server_sent(&s.net, S0, rc, true))
            .await;
    });
    assert!(!server_sent(&s.net, S0, H3Code::REQUEST_CANCELLED, false));
    assert!(!server_sent(&s.net, S0, H3Code::INTERNAL_ERROR, false));
}

/// A GET whose FIN is still in flight when its Service drops the request (seen on quinn):
/// the complete response is not reset; only reading stops (RFC 9114 §4.1).
#[test]
fn ignored_request_body_keeps_complete_response() {
    let mut s = server(|_| -> Fut { Box::pin(async { respond(200, ChanBody::of(&[b"ok"])) }) });
    let _srv = spawn(&s.exec, s.conn);
    run(&s.exec, async {
        let a = open(&mut s.peer, &req("GET", "/"), false).await;
        let rc = H3Code::REQUEST_CANCELLED;
        s.peer
            .run_until(|p| finished(p, a) || aborted(p, a, rc))
            .await;
        assert!(finished(&s.peer, a), "the response was reset");
        assert_eq!(s.peer.body(a), b"ok");
        s.peer.send_body(a, b"", true); // the late FIN
        settle(&mut s.peer).await;
    });
    assert!(!server_sent(&s.net, S0, H3Code::REQUEST_CANCELLED, false));
    assert!(server_sent(&s.net, S0, H3Code::REQUEST_CANCELLED, true));
    assert_eq!(s.shared.with(|i| i.streams.len()), 0, "reaped");
}

/// The Service hands its request body out of the task and responds; the body is dropped
/// after the task ended, before the complete response was written (seen on quinn): the
/// response is not reset; only reading stops (RFC 9114 §4.1).
#[test]
fn body_dropped_after_task_keeps_complete_response() {
    let kept: Arc<Mutex<Option<RecvBody>>> = Arc::default();
    let k = kept.clone();
    let mut s = server(move |req: Request<RecvBody>| -> Fut {
        *k.lock().unwrap() = Some(req.into_body());
        Box::pin(async { respond(200, ChanBody::of(&[b"ok"])) })
    });
    s.net.block_writes(Side::Server, S0, true);
    let shared = s.shared.clone();
    let _srv = spawn(&s.exec, s.conn);
    run(&s.exec, async {
        let a = open(&mut s.peer, &req("POST", "/"), false).await;
        settle(&mut s.peer).await;
        // The task ended with its complete response queued but unwritten; the body lives.
        shared.with(|i| {
            let st = &i.streams[&a];
            assert!(st.final_sent && !st.recv.task_owned && !st.send.done);
        });
        drop(kept.lock().unwrap().take());
        settle(&mut s.peer).await;
        s.net.block_writes(Side::Server, a, false);
        let rc = H3Code::REQUEST_CANCELLED;
        s.peer
            .run_until(|p| finished(p, a) || aborted(p, a, rc))
            .await;
        assert!(finished(&s.peer, a), "the response was reset");
        assert_eq!(s.peer.body(a), b"ok");
        s.peer.send_body(a, b"", true); // the late FIN
        settle(&mut s.peer).await;
    });
    assert!(!server_sent(&s.net, S0, H3Code::REQUEST_CANCELLED, false));
    assert!(server_sent(&s.net, S0, H3Code::REQUEST_CANCELLED, true));
    assert_eq!(s.shared.with(|i| i.streams.len()), 0, "reaped");
}

#[test]
fn stop_sending_keeps_service_reading() {
    let got = Arc::new(Mutex::new(Vec::new()));
    let g = got.clone();
    let mut s = server(move |req: Request<RecvBody>| -> Fut {
        let g = g.clone();
        Box::pin(async move {
            let mut body = req.into_body();
            while let Some(f) = poll_fn(|cx| Pin::new(&mut body).poll_frame(cx)).await {
                let d = f.unwrap().into_data().unwrap();
                g.lock().unwrap().extend_from_slice(&d);
            }
            g.lock().unwrap().extend_from_slice(b"|eof");
            respond(200, ChanBody::of(&[b"late"]))
        })
    });
    let _srv = spawn(&s.exec, s.conn);
    let got = |b: &[u8]| *got.lock().unwrap() == b;
    run(&s.exec, async {
        let a = open(&mut s.peer, &req("POST", "/"), false).await;
        s.peer.send_body(a, b"abc", false);
        s.peer.run_until(|_| got(b"abc")).await;
        s.peer.stop_sending(a, H3Code::REQUEST_CANCELLED);
        s.peer
            .run_until(|_| server_sent(&s.net, a, H3Code::REQUEST_CANCELLED, false))
            .await;
        s.peer.send_body(a, b"def", true);
        s.peer.run_until(|_| got(b"abcdef|eof")).await;
        settle(&mut s.peer).await;
    });
    // The server never stopped reading, and the Service's late response is no failure.
    assert!(!server_sent(&s.net, S0, H3Code::REQUEST_CANCELLED, true));
    assert!(!server_sent(&s.net, S0, H3Code::INTERNAL_ERROR, true));
    assert!(!server_sent(&s.net, S0, H3Code::INTERNAL_ERROR, false));
    assert_eq!(s.shared.with(|i| i.streams.len()), 0, "reaped");
}

#[test]
fn peer_reset_cancels_service() {
    let alive = Arc::new(());
    let a2 = alive.clone();
    let mut s = server(move |_| -> Fut {
        let held = a2.clone();
        Box::pin(async move {
            let _held = held;
            std::future::pending().await
        })
    });
    let _srv = spawn(&s.exec, s.conn);
    run(&s.exec, async {
        let a = open(&mut s.peer, &req("POST", "/"), false).await;
        s.peer.run_until(|_| Arc::strong_count(&alive) == 3).await;
        s.peer.reset(a, H3Code::REQUEST_CANCELLED);
        // The Service future (one clone) is dropped; the closure keeps the other.
        s.peer.run_until(|_| Arc::strong_count(&alive) == 2).await;
        settle(&mut s.peer).await;
    });
    assert!(server_sent(&s.net, S0, H3Code::REQUEST_CANCELLED, false));
    assert!(!server_sent(&s.net, S0, H3Code::INTERNAL_ERROR, false));
    assert_eq!(s.shared.with(|i| i.streams.len()), 0, "reaped");
}

#[test]
fn expect_100_continue() {
    let mut s = server(|req: Request<RecvBody>| -> Fut {
        Box::pin(async move {
            let mut body = req.into_body();
            // Polled twice before any data: 100 still goes out once.
            assert!(
                poll_fn(|cx| Poll::Ready(Pin::new(&mut body).poll_frame(cx)))
                    .await
                    .is_pending()
            );
            let (got, _) = read_all(&mut body).await;
            respond(200, ChanBody::of(&[&got]))
        })
    });
    let _srv = spawn(&s.exec, s.conn);
    run(&s.exec, async {
        let mut fields = req("POST", "/").to_vec();
        fields.push(("expect", "100-continue"));
        let a = open(&mut s.peer, &fields, false).await;
        s.peer.run_until(|p| !p.headers(a).is_empty()).await;
        assert_eq!(statuses(&s.peer, a), ["100"]);
        s.peer.send_body(a, b"abc", true);
        s.peer.run_until(|p| finished(p, a)).await;
        assert_eq!(statuses(&s.peer, a), ["100", "200"]);
        assert_eq!(s.peer.body(a), b"abc");
    });
}

#[test]
fn no_content_responses_drop_body() {
    let mut s = server(|req: Request<RecvBody>| -> Fut {
        let status = if req.uri().path() == "/204" { 204 } else { 200 };
        Box::pin(async move { respond(status, ChanBody::of(&[b"ignored"])) })
    });
    let _srv = spawn(&s.exec, s.conn);
    run(&s.exec, async {
        let a = open(&mut s.peer, &req("HEAD", "/"), true).await;
        let b = open(&mut s.peer, &req("GET", "/204"), true).await;
        s.peer.run_until(|p| finished(p, a) && finished(p, b)).await;
        assert_eq!(statuses(&s.peer, a), ["200"]);
        assert_eq!(statuses(&s.peer, b), ["204"]);
        assert!(s.peer.body(a).is_empty() && s.peer.body(b).is_empty());
        settle(&mut s.peer).await;
    });
    assert!(!server_aborted_any(&s.net, S0) && !server_aborted_any(&s.net, S4));
}

/// `Owns::Both`: the request ending does not cancel a task still sending its response.
#[test]
fn response_continues_after_request_eof() {
    let (tx, body) = ChanBody::new();
    let body = slot(body);
    let mut s = server(move |req: Request<RecvBody>| -> Fut {
        let b = body.lock().unwrap().take().unwrap();
        Box::pin(async move {
            read_all(&mut req.into_body()).await;
            respond(200, b)
        })
    });
    let _srv = spawn(&s.exec, s.conn);
    run(&s.exec, async {
        data(&tx, b"one");
        let a = open(&mut s.peer, &req("POST", "/"), false).await;
        s.peer.send_body(a, b"req", true);
        s.peer.run_until(|p| p.body(a) == b"one").await;
        settle(&mut s.peer).await;
        data(&tx, b"two");
        drop(tx);
        s.peer.run_until(|p| finished(p, a)).await;
        assert_eq!(s.peer.body(a), b"onetwo");
    });
    assert!(!server_aborted_any(&s.net, S0));
}

#[test]
fn graceful_shutdown_holes_and_reordering() {
    let mut s = server(|_| -> Fut { Box::pin(async { respond(200, ChanBody::of(&[b"ok"])) }) });
    s.net.ack_mode(Ack::Manual);
    let get = req("GET", "/");
    let (net, peer, conn) = (&s.net, &mut s.peer, &mut s.conn);
    run(&s.exec, async {
        for want in [S0, S4, S8] {
            assert_eq!(peer.open_bidi().await.unwrap(), want);
        }
        // HEADERS on 4 are queued but held back; 0 and 8 go out.
        net.block_writes(Side::Client, S4, true);
        for id in [S0, S4, S8] {
            peer.send_headers(id, &get, true).unwrap();
        }
        settle(peer).await;
        Pin::new(&mut *conn).graceful_shutdown();
        // 8 arrived before the cutoff: processed, so the cutoff is 12.
        drive_until(peer, conn, |p| {
            finished(p, S0)
                && finished(p, S8)
                && p.trace()
                    .contains(&PeerObs::Event(Event::GoAway { id: 12 }))
        })
        .await;
        // Opened after the cutoff (raw: the peer's core refuses after GOAWAY): rejected.
        assert_eq!(peer.open_bidi().await.unwrap(), S12);
        peer.send_raw(S12, &headers_frame(&get));
        drive_until(peer, conn, |_| {
            server_sent(net, S12, H3Code::REQUEST_REJECTED, false)
        })
        .await;
        // The hole below the cutoff is still served.
        net.block_writes(Side::Client, S4, false);
        drive_until(peer, conn, |p| finished(p, S4)).await;
        assert_eq!(peer.body(S4), b"ok");
        for _ in 0..16 {
            drive_until(peer, conn, |_| true).await;
            settle(peer).await;
        }
        assert_eq!(net.closed_with(Side::Server), None, "not acknowledged yet");
        net.ack_all();
        drive(peer, conn).await.expect("a clean close");
    });
    assert_eq!(s.net.closed_with(Side::Server), Some(0x100));
}

/// A stream the peer opened (the transport hands it out, as quinn does for a lower id
/// implied by a higher one) but never sent a byte on is not waited for (spec §4.2).
#[test]
fn graceful_shutdown_skips_unused_hole() {
    let mut s = server(|_| -> Fut { Box::pin(async { respond(200, ChanBody::of(&[b"ok"])) }) });
    s.net.ack_mode(Ack::Manual);
    let get = req("GET", "/");
    let (net, peer, conn) = (&s.net, &mut s.peer, &mut s.conn);
    run(&s.exec, async {
        assert_eq!(peer.open_bidi().await.unwrap(), S0); // never used
        let b = open(peer, &get, true).await;
        drive_until(peer, conn, |p| finished(p, b)).await;
        Pin::new(&mut *conn).graceful_shutdown();
        let goaway = PeerObs::Event(Event::GoAway { id: 8 });
        drive_until(peer, conn, |p| p.trace().contains(&goaway)).await;
        assert_eq!(net.closed_with(Side::Server), None, "not acknowledged yet");
        net.ack_all();
        drive(peer, conn).await.expect("a clean close");
    });
    assert_eq!(s.net.closed_with(Side::Server), Some(0x100));
}

/// A Service that holds its request body until `drop_tx` fires, drops it, then waits
/// forever on something unrelated; `alive` gains a clone while its future lives.
fn body_holder(
    alive: &Arc<()>,
) -> (
    oneshot::Sender<()>,
    impl FnMut(Request<RecvBody>) -> Fut + Clone + Send + 'static,
) {
    let a2 = alive.clone();
    let (drop_tx, drop_rx) = oneshot::channel::<()>();
    let drop_rx = Arc::new(Mutex::new(Some(drop_rx)));
    let f = move |req: Request<RecvBody>| -> Fut {
        let held = a2.clone();
        let rx = drop_rx.lock().unwrap().take().unwrap();
        Box::pin(async move {
            let _held = held;
            let body = req.into_body();
            let _ = rx.await;
            drop(body);
            std::future::pending().await
        })
    };
    (drop_tx, f)
}

/// No reader remains: a Service that dropped its unread body (with bytes queued) and then
/// waits on something unrelated is cancelled once the response side ends too; the queued
/// bytes are released at the drop, later body bytes are not queued, and the entry is
/// reaped.
#[test]
fn abandoned_body_then_unrelated_wait_is_cancelled() {
    let alive = Arc::new(());
    let (drop_tx, f) = body_holder(&alive);
    let mut s = server(f);
    let info = ConnInfo::new(s.shared.clone());
    let _srv = spawn(&s.exec, s.conn);
    run(&s.exec, async {
        let a = open(&mut s.peer, &req("POST", "/"), false).await;
        s.peer.send_body(a, b"abc", false);
        s.peer
            .run_until(|_| info.__debug_recv_accounting().0 == 3)
            .await;
        drop_tx.send(()).unwrap();
        s.peer
            .run_until(|_| info.__debug_recv_accounting() == (0, 0, 0))
            .await;
        // Read, but nobody will consume it: dropped, not queued.
        s.peer.send_body(a, b"more", false);
        settle(&mut s.peer).await;
        assert_eq!(info.__debug_recv_accounting(), (0, 0, 0));
        assert_eq!(Arc::strong_count(&alive), 3, "still running");
        s.peer.stop_sending(a, H3Code::REQUEST_CANCELLED);
        s.peer.send_body(a, b"def", true);
        s.peer.run_until(|_| Arc::strong_count(&alive) == 2).await;
        s.peer
            .run_until(|_| s.shared.with(|i| i.streams.is_empty()))
            .await;
    });
    assert_eq!(info.__debug_recv_accounting(), (0, 0, 0));
}

/// A body dropped after FIN with its trailers untaken also leaves no reader: the task is
/// cancelled once the response side ends, the entry is reaped, and nothing is aborted
/// with `H3_REQUEST_CANCELLED` (the request had ended).
#[test]
fn body_dropped_at_eof_with_trailers_then_unrelated_wait_is_cancelled() {
    let alive = Arc::new(());
    let (drop_tx, f) = body_holder(&alive);
    let mut s = server(f);
    let _srv = spawn(&s.exec, s.conn);
    let eof = |sh: &Shared| sh.with(|i| i.streams.get(&S0).is_some_and(|st| st.recv.eof));
    run(&s.exec, async {
        let a = open(&mut s.peer, &req("POST", "/"), false).await;
        s.peer.send_body(a, b"abc", false);
        settle(&mut s.peer).await; // the DATA goes out before the trailers are queued
        s.peer.send_headers(a, &[("x-t", "1")], true).unwrap();
        s.peer.run_until(|_| eof(&s.shared)).await;
        drop_tx.send(()).unwrap();
        settle(&mut s.peer).await;
        assert_eq!(Arc::strong_count(&alive), 3, "still running");
        s.peer.stop_sending(a, H3Code::REQUEST_CANCELLED);
        s.peer.run_until(|_| Arc::strong_count(&alive) == 2).await;
        s.peer
            .run_until(|_| s.shared.with(|i| i.streams.is_empty()))
            .await;
    });
    assert!(!server_sent(&s.net, S0, H3Code::REQUEST_CANCELLED, true));
}

/// `poll_ready` fails: the connection closes with `H3_INTERNAL_ERROR`, and the output
/// carries the Service's error as its source.
#[test]
fn poll_ready_error_closes_internal_error() {
    let mut s = server(|_| -> Fut { Box::pin(async { respond(200, ChanBody::of(&[])) }) });
    s.gate.0.lock().unwrap().2 = Some(Box::new(std::io::Error::other("not ready")));
    let srv = spawn(&s.exec, s.conn);
    run(&s.exec, async {
        s.peer.run_until(|_| done(&srv)).await;
    });
    let e = take(&srv).unwrap_err();
    assert!(
        matches!(
            e.kind(),
            ErrorKind::Closed {
                code: H3Code::INTERNAL_ERROR,
                by_peer: false
            }
        ),
        "{e:?}"
    );
    let src = std::error::Error::source(&e).expect("the Service's error");
    let io = src.downcast_ref::<std::io::Error>().expect("its type");
    assert_eq!(io.to_string(), "not ready");
    assert_eq!(s.net.closed_with(Side::Server), Some(0x102));
}

/// The test peer, like the driver, reads what the transport still holds before it
/// treats a close as final: a response written before the close is seen whole.
#[test]
fn core_peer_reads_held_data_at_close() {
    let mut s = server(|_| -> Fut { Box::pin(async { respond(200, ChanBody::of(&[b"ok"])) }) });
    s.net.readable_after_close(true);
    let get = req("GET", "/");
    let (net, peer, conn) = (&s.net, &mut s.peer, &mut s.conn);
    run(&s.exec, async {
        let b = open(peer, &get, true).await;
        let fin = |side| MockObs::Fin { side, stream: b };
        peer.run_until(|_| net.trace().contains(&fin(Side::Client)))
            .await;
        // Only the server runs until its response is written; the peer does not read.
        let fin = fin(Side::Server);
        poll_fn(|cx| {
            let _ = Pin::new(&mut *conn).poll(cx);
            if net.trace().contains(&fin) {
                Poll::Ready(())
            } else {
                Poll::Pending
            }
        })
        .await;
        net.kill_transport(Side::Client, Some(0x100));
        settle(peer).await;
        assert!(finished(peer, b), "{:?}", peer.trace());
        assert_eq!(peer.body(b), b"ok");
    });
}
