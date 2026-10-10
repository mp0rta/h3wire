// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 mp0rta
//! The quinn loopback suite (spec §5.2): h3wire-async over real quinn on 127.0.0.1.

mod support;

use bytes::Bytes;
use h3wire_async::__testing::{CorePeer, PeerObs};
use h3wire_async::body::RecvBody;
use h3wire_async::core::{AbortSource, Config, Event, H3Code, Role, StreamId, UsageError};
use h3wire_async::rt::TokioExecutor;
use h3wire_async::upgrade::{self, Tunnel};
use h3wire_async::{Builder, Error, ErrorKind};
use h3wire_quinn::QuinnConnection;
use http::{HeaderMap, HeaderValue, Method, Request, Response};
use http_body::Frame;
use http_body_util::BodyExt;
use std::time::Instant;
use support::*;
use tokio::sync::oneshot;

const S0: StreamId = StreamId(0);
const S4: StreamId = StreamId(4);
const S8: StreamId = StreamId(8);
const S12: StreamId = StreamId(12);
const RC: H3Code = H3Code::REQUEST_CANCELLED;

fn is_aborted(e: &Error, code: H3Code, source: AbortSource) -> bool {
    matches!(e.kind(), ErrorKind::StreamAborted { code: c, source: s, .. } if *c == code && *s == source)
}

/// The peer aborted the stream with `code`.
fn peer_aborted(e: &Error, code: H3Code) -> bool {
    is_aborted(e, code, AbortSource::Peer)
}

fn peer_saw_abort(p: &Peer, s: StreamId, code: H3Code) -> bool {
    p.trace().contains(&PeerObs::Event(Event::StreamAborted {
        stream: s,
        code,
        source: AbortSource::Peer,
    }))
}

/// A CorePeer client and an h3wire-async server serving `service`.
async fn peer_client<S>(service: S) -> (Peer, Server, Conns)
where
    S: tower_service::Service<
            Request<RecvBody>,
            Response = Response<BoxBody>,
            Error = h3wire_async::BoxError,
        > + Clone
        + Send
        + 'static,
    S::Future: Send + 'static,
{
    let conns = connect().await;
    let server = spawn_server(conns.server.clone(), &Builder::new(), service);
    let peer = CorePeer::new(
        Role::Client,
        Config::default(),
        QuinnConnection::new(conns.client.clone()),
    );
    (peer, server, conns)
}

/// A CONNECT answered 2xx: the client's and the server's tunnel.
async fn tunnels(p: &mut Pair, reqs: &mut Reqs, host: &str) -> (Tunnel, Tunnel) {
    let resp = tokio::spawn(p.send.send_request(connect_req(host)));
    let (mut req, reply) = reqs.recv().await.unwrap();
    let on = upgrade::on(&mut req);
    reply.send(support::reply(200, empty())).unwrap();
    let mut resp = resp.await.unwrap().unwrap();
    assert_eq!(resp.status(), 200);
    let client = upgrade::on(&mut resp).await.unwrap();
    (client, on.await.unwrap())
}

type Reqs = tokio::sync::mpsc::UnboundedReceiver<Handed>;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn get_post_large_bodies_hashed() {
    with_timeout(async {
        let big = pattern(16 << 20);
        let want = sha256(&big);
        let b = big.clone();
        let mut p = pair(Svc(move |req: Request<RecvBody>| -> Fut {
            let big = b.clone();
            Box::pin(async move {
                let post = req.method() == Method::POST;
                let (body, _) = collect(req.into_body()).await?;
                Ok(Response::new(if post {
                    full(sha256(&body))
                } else {
                    chunked(big)
                }))
            })
        }))
        .await;
        let start = Instant::now();
        let mut s2 = p.send.clone();
        let (got, posted) = tokio::join!(
            async {
                let r = p.send.send_request(get("/big")).await.unwrap();
                collect(r.into_body()).await.unwrap().0
            },
            async {
                let req = request(Method::POST, "/hash", chunked(big));
                let r = s2.send_request(req).await.unwrap();
                collect(r.into_body()).await.unwrap().0
            },
        );
        eprintln!(
            "get_post_large_bodies_hashed: 2 x 16 MiB in {:?}",
            start.elapsed()
        );
        assert_eq!(got.len(), 16 << 20);
        assert_eq!(sha256(&got), want);
        assert_eq!(posted, want.as_bytes());
    })
    .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn trailers_both_ways() {
    with_timeout(async {
        let mut p = pair(Svc(|req: Request<RecvBody>| -> Fut {
            Box::pin(async move {
                let (body, trailers) = collect(req.into_body()).await?;
                let t = trailers.expect("request trailers");
                let mut out = HeaderMap::new();
                out.insert("x-echo", t["x-req"].clone());
                out.insert("x-len", HeaderValue::from(body.len()));
                Ok(Response::new(frames(vec![
                    Frame::data(Bytes::from_static(b"response")),
                    Frame::trailers(out),
                ])))
            })
        }))
        .await;
        let mut t = HeaderMap::new();
        t.insert("x-req", HeaderValue::from_static("tr-1"));
        let body = frames(vec![
            Frame::data(Bytes::from_static(b"request")),
            Frame::trailers(t),
        ]);
        let r = p
            .send
            .send_request(request(Method::POST, "/", body))
            .await
            .unwrap();
        let (body, trailers) = collect(r.into_body()).await.unwrap();
        assert_eq!(body, "response");
        let t = trailers.expect("response trailers");
        assert_eq!(t["x-echo"], "tr-1");
        assert_eq!(t["x-len"], "7");
    })
    .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn expect_100_continue() {
    with_timeout(async {
        let echo = Svc(|req: Request<RecvBody>| -> Fut {
            Box::pin(async move {
                let (body, _) = collect(req.into_body()).await?;
                Ok(Response::new(full(body)))
            })
        });
        // A raw client sees the 100 before it sends the body.
        let (mut peer, _server, _conns) = peer_client(echo.clone()).await;
        let mut fields = req_fields("POST", "/");
        fields.push(("expect", "100-continue"));
        let a = peer.open_bidi().await.unwrap();
        peer.send_headers(a, &fields, false).unwrap();
        peer.run_until(|p| !p.headers(a).is_empty()).await;
        assert_eq!(statuses(&peer, a), ["100"]);
        peer.send_body(a, b"abc", true);
        peer.run_until(|p| finished(p, a)).await;
        assert_eq!(statuses(&peer, a), ["100", "200"]);
        assert_eq!(peer.body(a), b"abc");

        // The h3wire-async client skips the 100 and resolves at the final response.
        let mut p = pair(echo).await;
        let mut req = request(Method::POST, "/", full("def"));
        req.headers_mut()
            .insert("expect", HeaderValue::from_static("100-continue"));
        let r = p.send.send_request(req).await.unwrap();
        assert_eq!(r.status(), 200);
        assert_eq!(collect(r.into_body()).await.unwrap().0, "def");
    })
    .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn stress_1000_concurrent() {
    with_timeout(async {
        let p = pair(Svc(|req: Request<RecvBody>| -> Fut {
            Box::pin(async move { Ok(Response::new(full(req.uri().path().to_owned()))) })
        }))
        .await;
        let start = Instant::now();
        let mut set = tokio::task::JoinSet::new();
        for i in 0..1000 {
            let mut send = p.send.clone();
            set.spawn(async move {
                let path = format!("/{i}");
                let r = send.send_request(get(&path)).await.unwrap();
                assert_eq!(collect(r.into_body()).await.unwrap().0, path);
            });
        }
        while let Some(r) = set.join_next().await {
            r.unwrap();
        }
        let t = start.elapsed();
        eprintln!(
            "stress_1000_concurrent: 1000 requests in {t:?} ({:.0} req/s)",
            1000.0 / t.as_secs_f64()
        );
    })
    .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn graceful_shutdown_delivers_in_flight() {
    with_timeout(async {
        let (svc, mut reqs) = handoff();
        let mut p = pair(svc).await;
        // A response body in flight.
        let (rtx, rbody) = chan();
        let a = tokio::spawn(p.send.send_request(get("/a")));
        let (_req_a, reply_a) = reqs.recv().await.unwrap();
        reply_a.send(Response::new(rbody)).unwrap();
        data(&rtx, b"one");
        let mut body_a = a.await.unwrap().unwrap().into_body();
        let f = body_a.frame().await.unwrap().unwrap();
        assert_eq!(f.into_data().unwrap(), "one");
        // A request body in flight.
        let (qtx, qbody) = chan();
        data(&qtx, b"req-one");
        let b = tokio::spawn(p.send.send_request(request(Method::POST, "/b", qbody)));
        let (req_b, reply_b) = reqs.recv().await.unwrap();
        let mut body_b = req_b.into_body();
        let f = body_b.frame().await.unwrap().unwrap();
        assert_eq!(f.into_data().unwrap(), "req-one");

        p.server.shutdown().await;
        // The client learns of the GOAWAY: no new requests.
        let e = loop {
            match p.send.ready().await {
                Ok(()) => tokio::task::yield_now().await,
                Err(e) => break e,
            }
        };
        assert!(
            matches!(e.kind(), ErrorKind::Usage(UsageError::GoingAway)),
            "{e:?}"
        );
        // Both bodies still complete.
        data(&rtx, b"two");
        drop(rtx);
        data(&qtx, b"req-two");
        drop(qtx);
        assert_eq!(collect(body_a).await.unwrap().0, "two");
        assert_eq!(collect(body_b).await.unwrap().0, "req-two");
        reply_b.send(reply(200, full("done"))).unwrap();
        let r = b.await.unwrap().unwrap();
        assert_eq!(collect(r.into_body()).await.unwrap().0, "done");
        // Both ends close cleanly once everything is acknowledged.
        p.server.done.await.unwrap().expect("server: a clean close");
        p.client.await.unwrap().expect("client: a clean close");
    })
    .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn goaway_retryable() {
    with_timeout(async {
        let conns = connect().await;
        let mut peer = CorePeer::new(
            Role::Server,
            Config::default(),
            QuinnConnection::new(conns.server.clone()),
        );
        let (mut send, conn) =
            h3wire_quinn::client::<BoxBody, _>(conns.client.clone(), &Builder::new(), TokioExecutor)
                .await
                .unwrap();
        let _client = tokio::spawn(conn);
        let a = tokio::spawn(send.send_request(get("/a")));
        peer.run_until(|p| !p.headers(S0).is_empty()).await; // processed: the cutoff is 4
        // B's stream is open at the client once its body is first polled. The peer is
        // not stepped meanwhile, so B is unprocessed when the cutoff goes out.
        let (opened, is_open) = oneshot::channel();
        let body = Probe(Some(opened)).boxed_unsync();
        let b = tokio::spawn(send.send_request(request(Method::POST, "/b", body)));
        is_open.await.unwrap();
        peer.finish_shutdown().unwrap();
        let e = drive(&mut peer, b).await.unwrap().unwrap_err();
        assert!(e.is_retryable(), "{e:?}");
        assert!(
            matches!(e.kind(), ErrorKind::StreamAborted { code, .. } if *code == H3Code::REQUEST_REJECTED),
            "{e:?}"
        );
        let e = send.ready().await.unwrap_err();
        assert!(
            matches!(e.kind(), ErrorKind::Usage(UsageError::GoingAway)),
            "{e:?}"
        );
        // The request below the cutoff is still served.
        peer.send_headers(S0, &[(":status", "200")], true).unwrap();
        let r = drive(&mut peer, a).await.unwrap().unwrap();
        assert_eq!(r.status(), 200);
    })
    .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn upgrade_claim_drop_matrix() {
    with_timeout(async {
        let (svc, mut reqs) = handoff();
        let mut p = pair(svc).await;

        // Server: 2xx sent -> the tunnel. The original body, kept after the claim, is at
        // EOF and the tunnel gets every byte.
        let resp = tokio::spawn(p.send.send_request(connect_req("s-2xx")));
        let (mut req, reply) = reqs.recv().await.unwrap();
        let on = upgrade::on(&mut req);
        reply.send(support::reply(200, empty())).unwrap();
        let mut resp = resp.await.unwrap().unwrap();
        let mut ct = upgrade::on(&mut resp).await.unwrap();
        ct.send(Bytes::from_static(b"ping")).await.unwrap();
        ct.finish().unwrap();
        let mut st = on.await.unwrap();
        let (b, t) = collect(req.into_body()).await.unwrap();
        assert!(b.is_empty() && t.is_none(), "the original body is at EOF");
        assert_eq!(read_to_end(&mut st).await.unwrap(), b"ping");
        st.send(Bytes::from_static(b"pong")).await.unwrap();
        st.finish().unwrap();
        assert_eq!(read_to_end(&mut ct).await.unwrap(), b"pong");

        // Server: non-2xx sent -> NotUpgraded; an ordinary response.
        let resp = tokio::spawn(p.send.send_request(connect_req("s-403")));
        let (mut req, reply) = reqs.recv().await.unwrap();
        let on = upgrade::on(&mut req);
        reply.send(support::reply(403, full("no"))).unwrap();
        let r = resp.await.unwrap().unwrap();
        assert_eq!(r.status(), 403);
        assert_eq!(collect(r.into_body()).await.unwrap().0, "no");
        let e = on.await.unwrap_err();
        assert!(matches!(e.kind(), ErrorKind::NotUpgraded), "{e:?}");

        // Server: OnUpgrade dropped before the final response -> the claim is released;
        // a non-2xx is then an ordinary response.
        let resp = tokio::spawn(p.send.send_request(connect_req("s-release")));
        let (mut req, reply) = reqs.recv().await.unwrap();
        drop(upgrade::on(&mut req));
        reply.send(support::reply(404, full("gone"))).unwrap();
        let r = resp.await.unwrap().unwrap();
        assert_eq!(r.status(), 404);
        assert_eq!(collect(r.into_body()).await.unwrap().0, "gone");

        // Server: 2xx with no live OnUpgrade (dropped, or never claimed) -> aborted with
        // H3_REQUEST_CANCELLED right after the HEADERS.
        for claim in [true, false] {
            let resp = tokio::spawn(p.send.send_request(connect_req("s-unheld")));
            let (mut req, reply) = reqs.recv().await.unwrap();
            if claim {
                drop(upgrade::on(&mut req));
            }
            reply.send(support::reply(200, empty())).unwrap();
            client_sees_cancel(resp.await.unwrap()).await;
        }

        // Server: OnUpgrade dropped after activation, before the Tunnel is taken.
        let resp = tokio::spawn(p.send.send_request(connect_req("s-untaken")));
        let (mut req, reply) = reqs.recv().await.unwrap();
        let on = upgrade::on(&mut req);
        reply.send(support::reply(200, empty())).unwrap();
        let resp = resp.await.unwrap();
        // The client has the 2xx, so it went out: the claim is active.
        drop(on);
        client_sees_cancel(resp).await;

        // Client: the response dropped with the pending upgrade inside.
        let (resp, mut st) = server_tunnel(&mut p, &mut reqs, "c-drop-resp").await;
        drop(resp);
        server_sees_cancel(&mut st).await;

        // Client: an OnUpgrade taken out, then dropped.
        let (mut resp, mut st) = server_tunnel(&mut p, &mut reqs, "c-drop-on").await;
        drop(upgrade::on(&mut resp));
        server_sees_cancel(&mut st).await;

        // Client: the Tunnel dropped before both directions ended.
        let (mut resp, mut st) = server_tunnel(&mut p, &mut reqs, "c-drop-tunnel").await;
        let ct = upgrade::on(&mut resp).await.unwrap();
        drop(ct);
        server_sees_cancel(&mut st).await;

        // The connection is unaffected.
        let r = tokio::spawn(p.send.send_request(get("/after")));
        let (_, reply) = reqs.recv().await.unwrap();
        reply.send(support::reply(200, full("ok"))).unwrap();
        assert_eq!(r.await.unwrap().unwrap().status(), 200);
    })
    .await
}

/// The client of a CONNECT the server aborted with `H3_REQUEST_CANCELLED` right after
/// its 2xx: either the reset overtook the HEADERS, or the tunnel fails.
async fn client_sees_cancel(resp: Result<Response<RecvBody>, Error>) {
    let e = match resp {
        Ok(mut resp) => {
            assert_eq!(resp.status(), 200);
            let mut t = upgrade::on(&mut resp).await.unwrap();
            t.recv().await.expect_err("aborted")
        }
        Err(e) => e,
    };
    assert!(peer_aborted(&e, RC), "{e:?}");
}

/// A CONNECT answered 2xx: the client's response (upgrade untaken) and the server's tunnel.
async fn server_tunnel(p: &mut Pair, reqs: &mut Reqs, host: &str) -> (Response<RecvBody>, Tunnel) {
    let resp = tokio::spawn(p.send.send_request(connect_req(host)));
    let (mut req, reply) = reqs.recv().await.unwrap();
    let on = upgrade::on(&mut req);
    reply.send(support::reply(200, empty())).unwrap();
    let resp = resp.await.unwrap().unwrap();
    assert_eq!(resp.status(), 200);
    (resp, on.await.unwrap())
}

async fn server_sees_cancel(st: &mut Tunnel) {
    let e = st.recv().await.expect_err("aborted");
    assert!(peer_aborted(&e, RC), "{e:?}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rejected_connect_both_stay_connected() {
    with_timeout(async {
        let (svc, mut reqs) = handoff();
        let mut p = pair(svc).await;
        // Unclaimed: the server reads the request to its end, which the client's FIN
        // after the non-2xx provides.
        let resp = tokio::spawn(p.send.send_request(connect_req("a")));
        let (req, reply) = reqs.recv().await.unwrap();
        reply.send(support::reply(403, full("nope"))).unwrap();
        let r = resp.await.unwrap().unwrap();
        assert_eq!(r.status(), 403);
        assert_eq!(collect(r.into_body()).await.unwrap().0, "nope");
        assert_eq!(collect(req.into_body()).await.unwrap().0, "");
        // Claimed: the settled claim drains the request.
        let resp = tokio::spawn(p.send.send_request(connect_req("b")));
        let (mut req, reply) = reqs.recv().await.unwrap();
        let on = upgrade::on(&mut req);
        drop(req);
        reply.send(support::reply(403, empty())).unwrap();
        assert_eq!(resp.await.unwrap().unwrap().status(), 403);
        assert!(matches!(
            on.await.unwrap_err().kind(),
            ErrorKind::NotUpgraded
        ));
        // Both endpoints are still connected.
        let r = tokio::spawn(p.send.send_request(get("/next")));
        let (_, reply) = reqs.recv().await.unwrap();
        reply.send(support::reply(200, full("ok"))).unwrap();
        let r = r.await.unwrap().unwrap();
        assert_eq!(collect(r.into_body()).await.unwrap().0, "ok");
        // Nothing is left waiting: a graceful shutdown completes.
        p.server.shutdown().await;
        p.server.done.await.unwrap().expect("server: a clean close");
        p.client.await.unwrap().expect("client: a clean close");
    })
    .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn split_halves_dropped_independently() {
    with_timeout(async {
        let (svc, mut reqs) = handoff();
        let mut p = pair(svc).await;
        let (c, s) = tunnels(&mut p, &mut reqs, "a").await;
        let (mut cs, mut cr) = c.split();
        let (mut ss, mut sr) = s.split();
        cs.send(Bytes::from_static(b"a")).await.unwrap();
        cs.finish().unwrap();
        drop(cs); // finished: nothing happens
        assert_eq!(sr.recv().await.unwrap().unwrap(), "a");
        assert_eq!(sr.recv().await.unwrap(), None);
        drop(sr); // at EOF: nothing happens
        ss.send(Bytes::from_static(b"b")).await.unwrap();
        assert_eq!(cr.recv().await.unwrap().unwrap(), "b");
        // Before EOF: the client aborts; the server's send half sees the STOP_SENDING.
        drop(cr);
        let e = loop {
            if let Err(e) = ss.send(Bytes::from_static(b"c")).await {
                break e;
            }
            tokio::task::yield_now().await;
        };
        assert!(
            matches!(e.kind(), ErrorKind::SendStopped { code } if *code == RC),
            "{e:?}"
        );

        // A send half dropped before `finish`: the server's receive half sees the reset.
        let (c, mut s) = tunnels(&mut p, &mut reqs, "b").await;
        let (cs, _cr) = c.split();
        drop(cs);
        let e = s.recv().await.expect_err("aborted");
        assert!(peer_aborted(&e, RC), "{e:?}");
    })
    .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn stop_sending_with_unread_request_body() {
    with_timeout(async {
        let (svc, mut reqs) = handoff();
        let (mut peer, _server, _conns) = peer_client(svc).await;
        let a = peer.open_bidi().await.unwrap();
        peer.send_headers(a, &req_fields("POST", "/"), false).unwrap();
        peer.send_body(a, b"abc", false);
        // The request's task holds its body unread while it waits for `reply`.
        let (req, reply) = drive(&mut peer, reqs.recv()).await.unwrap();
        peer.stop_sending(a, RC);
        // Barrier: STOP_SENDING goes out before b's HEADERS, and the server handles a's
        // send-side token in the same pass that accepts b, before it can answer b.
        let b = peer.open_bidi().await.unwrap();
        peer.send_headers(b, &req_fields("GET", "/b"), true).unwrap();
        let (_, reply_b) = drive(&mut peer, reqs.recv()).await.unwrap();
        reply_b.send(support::reply(200, empty())).unwrap();
        peer.run_until(|p| finished(p, b)).await;
        assert!(!reply.is_closed(), "the request's task was not cancelled");
        // Reception continues.
        let mut body = req.into_body();
        let f = drive(&mut peer, body.frame()).await.unwrap().unwrap();
        assert_eq!(f.into_data().unwrap(), "abc");
        assert!(!reply.is_closed(), "the request's task was not cancelled");
        peer.send_body(a, b"def", true);
        let (got, _) = drive(&mut peer, collect(body)).await.unwrap();
        assert_eq!(got, "def");
        // Both directions are over now: the task may be cancelled (spec §4.6), and a
        // late response is no failure.
        let _ = reply.send(support::reply(200, full("late")));
        let stopped = |o: &PeerObs| matches!(o, PeerObs::Event(Event::SendStopped { stream, .. }) if *stream == a);
        assert!(!peer.trace().iter().any(stopped), "the server never stopped reading");
    })
    .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn peer_reset_cancels_service() {
    with_timeout(async {
        let (svc, mut reqs) = handoff();
        let (mut peer, _server, _conns) = peer_client(svc).await;
        let a = peer.open_bidi().await.unwrap();
        peer.send_headers(a, &req_fields("POST", "/"), false)
            .unwrap();
        let (req, mut reply) = drive(&mut peer, reqs.recv()).await.unwrap();
        peer.reset(a, RC);
        // The whole stream ends: the request's task (the Service future) is dropped,
        drive(&mut peer, reply.closed()).await;
        // its body fails, and the response direction is reset too.
        let e = collect(req.into_body()).await.unwrap_err();
        assert!(peer_aborted(&e, RC), "{e:?}");
        peer.run_until(|p| peer_saw_abort(p, a, RC)).await;
    })
    .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn shutdown_reordered_headers() {
    with_timeout(async {
        // The response on 0 waits for `release`, so the server cannot drain (and close)
        // before 4's late HEADERS arrive; a hole never sent on is not waited for.
        let (started_tx, started) = oneshot::channel::<()>();
        let (release, held) = oneshot::channel::<()>();
        let held = std::sync::Arc::new(std::sync::Mutex::new(Some((started_tx, held))));
        let svc = Svc(move |req: Request<RecvBody>| -> Fut {
            let held = (req.uri().path() == "/held").then(|| held.lock().unwrap().take());
            Box::pin(async move {
                if let Some(Some((started, h))) = held {
                    let _ = started.send(());
                    h.await?;
                }
                Ok(Response::new(full("ok")))
            })
        });
        let (mut peer, mut server, _conns) = peer_client(svc).await;
        for want in [S0, S4, S8] {
            assert_eq!(peer.open_bidi().await.unwrap(), want);
        }
        // HEADERS on 0 and 8; those on 4 are held back. Stream 8 opens 4 at the server.
        let get = req_fields("GET", "/");
        peer.send_headers(S0, &req_fields("GET", "/held"), true)
            .unwrap();
        peer.send_headers(S8, &get, true).unwrap();
        drive(&mut peer, started).await.unwrap();
        peer.run_until(|p| finished(p, S8)).await;
        server.shutdown().await;
        // Queued before the peer reads any GOAWAY (its core then refuses new requests),
        // so they reach the server during its shutdown.
        peer.send_headers(S4, &get, true).unwrap();
        // 8 was processed before the cutoff, so the cutoff is 12.
        let goaway12 = PeerObs::Event(Event::GoAway { id: 12 });
        peer.run_until(|p| p.trace().contains(&goaway12)).await;
        // Opened after the cutoff (raw: the peer's core refuses after GOAWAY): rejected.
        assert_eq!(peer.open_bidi().await.unwrap(), S12);
        peer.send_raw(S12, &headers_frame(&get));
        let rejected = PeerObs::Reset {
            stream: S12,
            code: H3Code::REQUEST_REJECTED.0,
        };
        peer.run_until(|p| p.trace().contains(&rejected)).await;
        // The request below the cutoff that arrived during the shutdown is served.
        peer.run_until(|p| finished(p, S4)).await;
        assert_eq!(peer.body(S4), b"ok");
        release.send(()).unwrap();
        peer.run_until(|p| finished(p, S0)).await;
        drive(&mut peer, &mut server.done)
            .await
            .unwrap()
            .expect("a clean close");
    })
    .await
}

/// quinn hands out stream 4 once 8 arrives (implicitly opened); the peer never sends on
/// it, and graceful shutdown still closes (spec §4.2: holes are not waited for).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn shutdown_skips_unused_hole() {
    with_timeout(async {
        let ok = Svc(|_| -> Fut { Box::pin(async { Ok(Response::new(full("ok"))) }) });
        let (mut peer, mut server, conns) = peer_client(ok).await;
        for want in [S0, S4, S8] {
            assert_eq!(peer.open_bidi().await.unwrap(), want);
        }
        let get = req_fields("GET", "/");
        peer.send_headers(S0, &get, true).unwrap();
        peer.send_headers(S8, &get, true).unwrap();
        peer.run_until(|p| finished(p, S0) && finished(p, S8)).await;
        server.shutdown().await;
        drive(&mut peer, &mut server.done)
            .await
            .unwrap()
            .expect("a clean close");
        // The peer sees the close: H3_NO_ERROR.
        match conns.client.closed().await {
            quinn::ConnectionError::ApplicationClosed(c) => {
                assert_eq!(c.error_code.into_inner(), H3Code::NO_ERROR.0)
            }
            e => panic!("{e:?}"),
        }
    })
    .await
}
