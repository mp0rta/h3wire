// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 mp0rta
//! The MASQUE boundary suite (spec §5.3): CONNECT-UDP (RFC 9298) over h3wire-async and
//! quinn, with a test-only capsule parser. Public API only, plus a `CorePeer` client
//! where raw control is needed. The ordering variants (datagrams before HEADERS or
//! before registration) run on the mock (Task 9).

#[path = "support/capsule.rs"]
mod capsule;
mod support;

use bytes::Bytes;
use capsule::{Capsule, CapsuleParser, DATAGRAM, capsule, connect_udp_request, udp_path};
use h3wire_async::__testing::{CorePeer, PeerObs};
use h3wire_async::body::RecvBody;
use h3wire_async::core::{AbortSource, Config, Event, H3Code, Role, StreamId, varint};
use h3wire_async::datagram::{DatagramSlot, Datagrams};
use h3wire_async::ext::{ConnInfo, Protocol};
use h3wire_async::upgrade::{self, OnUpgrade, Tunnel};
use h3wire_async::{Builder, DatagramError, Error, ErrorKind};
use h3wire_quinn::QuinnConnection;
use http::{Method, Request};
use support::*;
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinHandle;

const MSG: H3Code = H3Code::MESSAGE_ERROR;
const RC: H3Code = H3Code::REQUEST_CANCELLED;
const TARGET: &str = "192.0.2.1";

type Reqs = mpsc::UnboundedReceiver<Handed>;

fn aborted(e: &Error, code: H3Code, source: AbortSource) -> bool {
    matches!(e.kind(), ErrorKind::StreamAborted { code: c, source: s, .. } if *c == code && *s == source)
}

/// Loopback endpoints with a fixed path MTU (no PMTU discovery): a stable datagram limit.
async fn conns() -> Conns {
    connect_with(|t| {
        t.mtu_discovery_config(None);
    })
    .await
}

/// A server accepting Extended CONNECT.
fn server_builder() -> Builder {
    let mut b = Builder::new();
    b.enable_connect_protocol(true);
    b
}

/// An h3wire-async client and a `Handoff` server.
async fn masque(sb: &Builder) -> (Pair, Reqs) {
    let (svc, reqs) = handoff();
    (pair_with(conns().await, sb, svc).await, reqs)
}

/// A `Handoff` server and a `CorePeer` client advertising `H3_DATAGRAM = dgram`, after
/// the server's SETTINGS (Extended CONNECT needs them).
async fn peer_masque(sb: &Builder, dgram: bool) -> (Peer, Reqs, Server, Conns) {
    let conns = conns().await;
    let (svc, reqs) = handoff();
    let server = spawn_server(conns.server.clone(), sb, svc);
    let mut cfg = Config::default();
    cfg.h3_datagram = dgram;
    let mut peer = CorePeer::new(
        Role::Client,
        cfg,
        QuinnConnection::new(conns.client.clone()),
    );
    peer.run_until(|p| p.core().peer_settings().is_some()).await;
    (peer, reqs, server, conns)
}

/// The peer opens a CONNECT-UDP to `TARGET:443` (no FIN).
async fn peer_connect_udp(peer: &mut Peer) -> StreamId {
    let path = udp_path(TARGET, 443);
    let fields = [
        (":method", "CONNECT"),
        (":protocol", "connect-udp"),
        (":scheme", "https"),
        (":authority", "localhost"),
        (":path", path.as_str()),
        ("capsule-protocol", "?1"),
    ];
    let s = peer.open_bidi().await.unwrap();
    peer.send_headers(s, &fields, false).unwrap();
    s
}

/// Server: check a CONNECT-UDP request to `TARGET:443`, then register datagrams and
/// claim the tunnel, both before the response.
fn accept(req: &mut Request<RecvBody>) -> (Datagrams, OnUpgrade) {
    assert_eq!(req.method(), Method::CONNECT);
    assert_eq!(
        req.extensions().get::<Protocol>(),
        Some(&Protocol::from_static("connect-udp"))
    );
    assert_eq!(req.uri().path(), udp_path(TARGET, 443));
    assert_eq!(req.headers()["capsule-protocol"], "?1");
    let d = req
        .extensions()
        .get::<DatagramSlot>()
        .expect("a slot")
        .register()
        .expect("the handle");
    (d, upgrade::on(req))
}

fn info(req: &Request<RecvBody>) -> ConnInfo {
    req.extensions().get::<ConnInfo>().unwrap().clone()
}

/// The ends of one CONNECT-UDP accepted with 200: client tunnel and datagrams, server
/// tunnel and datagrams. Both SETTINGS have arrived.
struct Udp {
    ct: Tunnel,
    cd: Datagrams,
    st: Tunnel,
    sd: Datagrams,
}

async fn open(p: &mut Pair, reqs: &mut Reqs) -> Udp {
    let resp = tokio::spawn(p.send.send_request(connect_udp_request::<BoxBody>(
        "localhost",
        TARGET,
        443,
    )));
    let (mut req, reply) = reqs.recv().await.unwrap();
    let (sd, on) = accept(&mut req);
    let info = info(&req);
    reply.send(support::reply(200, empty())).unwrap();
    let mut resp = resp.await.unwrap().unwrap();
    assert_eq!(resp.status(), 200);
    let cd = resp
        .extensions()
        .get::<DatagramSlot>()
        .unwrap()
        .register()
        .unwrap();
    let ct = upgrade::on(&mut resp).await.unwrap();
    let st = on.await.unwrap();
    info.settings().await.unwrap(); // the client's SETTINGS: the server may send datagrams
    Udp { ct, cd, st, sd }
}

/// The context ID of an HTTP datagram payload (RFC 9298 §4).
fn context_id(d: &[u8]) -> Option<u64> {
    varint::decode(d).map(|(v, _)| v)
}

/// A context-ID-0 datagram payload.
fn udp(payload: &[u8]) -> Bytes {
    [&[0][..], payload].concat().into()
}

/// The server side of a MASQUE proxy, in one task over one `select!` loop: it echoes
/// context-ID-0 datagrams (others are dropped) and DATAGRAM capsules. At the tunnel's
/// EOF it finishes, or aborts with `H3_MESSAGE_ERROR` if a capsule was truncated.
fn proxy(st: Tunnel, mut sd: Datagrams) -> JoinHandle<Result<(), Error>> {
    tokio::spawn(async move {
        let (mut tx, mut rx) = st.split();
        let mut parser = CapsuleParser::default();
        let mut dgrams = true;
        loop {
            tokio::select! {
                d = sd.recv(), if dgrams => match d? {
                    Some(d) if context_id(&d) == Some(0) => {
                        let _ = sd.send(d); // unreliable: a refusal is a loss
                    }
                    Some(_) => {}
                    None => dgrams = false,
                },
                b = rx.recv() => match b? {
                    Some(b) => {
                        for c in parser.feed(b) {
                            tx.send(capsule(c.ty, &c.payload).into()).await?;
                        }
                    }
                    None => {
                        if parser.finish().is_err() {
                            rx.abort(MSG);
                        } else {
                            tx.finish()?;
                        }
                        return Ok(());
                    }
                },
            }
        }
    })
}

/// Send `payload` as a DATAGRAM capsule on `t` and check its echo.
async fn capsule_echo(t: &mut Tunnel, parser: &mut CapsuleParser, payload: &[u8]) {
    t.send(capsule(DATAGRAM, payload).into()).await.unwrap();
    let mut got = Vec::new();
    while got.is_empty() {
        got = parser.feed(t.recv().await.unwrap().expect("the echo"));
    }
    let want = Capsule {
        ty: DATAGRAM,
        payload: Bytes::copy_from_slice(payload),
    };
    assert_eq!(got, [want]);
}

/// Send `payload` as a context-ID-0 datagram and check its echo.
async fn dgram_echo(d: &mut Datagrams, payload: &[u8]) {
    d.send(udp(payload)).unwrap();
    assert_eq!(d.recv().await.unwrap().unwrap(), udp(payload));
}

/// [`dgram_echo`] on a loaded connection, where datagrams are lost (loopback drops
/// hundreds of packets under a flood; QUIC retransmits only stream data): sent again
/// while no echo arrived within 100 ms; echoes of other datagrams are skipped.
async fn dgram_echo_lossy(d: &mut Datagrams, payload: &[u8]) {
    loop {
        d.send(udp(payload)).unwrap();
        let echo = tokio::time::timeout(std::time::Duration::from_millis(100), async {
            while d.recv().await.unwrap().unwrap() != udp(payload) {}
        });
        if echo.await.is_ok() {
            return;
        }
    }
}

/// Finish the client's side and check that the proxy finishes cleanly.
async fn close(mut ct: Tunnel, proxy: JoinHandle<Result<(), Error>>) {
    ct.finish().unwrap();
    assert_eq!(read_to_end(&mut ct).await.unwrap(), b"");
    proxy.await.unwrap().unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn context_id_zero_datagram_echo() {
    with_timeout(async {
        let (mut p, mut reqs) = masque(&server_builder()).await;
        let Udp { ct, mut cd, st, sd } = open(&mut p, &mut reqs).await;
        // QSID 0 takes one byte of the transport's limit.
        let limit = p.conns.client.max_datagram_size().unwrap();
        assert_eq!(cd.max_payload(), Some(limit - 1));
        let proxy = proxy(st, sd);
        // Context IDs 2 and 100 (a two-byte varint) are not UDP payloads: dropped.
        cd.send(Bytes::from_static(b"\x02x")).unwrap();
        cd.send(Bytes::from_static(b"\x40\x64y")).unwrap();
        dgram_echo(&mut cd, b"ping").await;
        dgram_echo(&mut cd, b"pong").await;
        close(ct, proxy).await;
    })
    .await
}

/// Several tunnels at once; their QSIDs cross the one-byte varint boundary (stream id
/// 256, QSID 64), which costs the datagram limit one more byte (four bytes:
/// `qsid_four_byte_varint`).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_tunnels() {
    with_timeout(async {
        const N: usize = 70; // stream ids 0..=276
        let (mut p, mut reqs) = masque(&server_builder()).await;
        let limit = p.conns.client.max_datagram_size().unwrap();
        let mut tunnels = Vec::new();
        for _ in 0..N {
            let Udp { ct, cd, st, sd } = open(&mut p, &mut reqs).await;
            tunnels.push((ct, cd, proxy(st, sd)));
        }
        let short = tunnels
            .iter()
            .filter(|t| t.1.max_payload() == Some(limit - 1))
            .count();
        let long = tunnels
            .iter()
            .filter(|t| t.1.max_payload() == Some(limit - 2))
            .count();
        assert_eq!((short, long), (64, N - 64));
        // Datagram echoes one at a time: the client's outgoing queue (64, drop-oldest)
        // would drop a burst from N tunnels.
        for (i, t) in tunnels.iter_mut().enumerate() {
            dgram_echo(&mut t.1, format!("d{i}").as_bytes()).await;
        }
        // Capsule echoes on every tunnel at once.
        let mut set = tokio::task::JoinSet::new();
        for (i, (mut ct, _cd, proxy)) in tunnels.into_iter().enumerate() {
            set.spawn(async move {
                let mut parser = CapsuleParser::default();
                for k in 0..3 {
                    let msg = format!("tunnel {i} capsule {k} {}", "x".repeat(i * 100));
                    capsule_echo(&mut ct, &mut parser, msg.as_bytes()).await;
                }
                close(ct, proxy).await;
            });
        }
        while let Some(r) = set.join_next().await {
            r.unwrap();
        }
    })
    .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn no_negotiation() {
    with_timeout(async {
        let (mut peer, mut reqs, _server, _conns) = peer_masque(&server_builder(), false).await;
        let s = peer_connect_udp(&mut peer).await;
        let (mut req, reply) = drive(&mut peer, reqs.recv()).await.unwrap();
        // We advertised H3_DATAGRAM, so the slot is there.
        let (sd, on) = accept(&mut req);
        let info = info(&req);
        reply.send(support::reply(200, empty())).unwrap();
        let mut st = drive(&mut peer, on).await.unwrap();
        let settings = drive(&mut peer, info.settings()).await.unwrap();
        assert!(!settings.h3_datagram);
        assert_eq!(sd.send(udp(b"x")), Err(DatagramError::Unsupported));
        assert_eq!(sd.max_payload(), None);
        // The tunnel works: a capsule there and back.
        let c = capsule(DATAGRAM, b"over the stream");
        peer.send_body(s, &c, false);
        let mut parser = CapsuleParser::default();
        let mut got = Vec::new();
        while got.is_empty() {
            let b = drive(&mut peer, st.recv()).await.unwrap().unwrap();
            got = parser.feed(b);
        }
        assert_eq!(got[0].payload, "over the stream");
        st.send(capsule(DATAGRAM, &got[0].payload).into())
            .await
            .unwrap();
        st.finish().unwrap();
        peer.run_until(|p| p.body(s) == c).await;
        assert_eq!(statuses(&peer, s), ["200"]);
    })
    .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rejected_connect_registered_drops_silently() {
    with_timeout(async {
        // A raw client sends a datagram after the 403: the registered handle takes it or
        // drops it, and nothing is aborted.
        let (mut peer, mut reqs, _server, _conns) = peer_masque(&server_builder(), true).await;
        let s = peer_connect_udp(&mut peer).await;
        let (mut req, reply) = drive(&mut peer, reqs.recv()).await.unwrap();
        let (mut sd, on) = accept(&mut req);
        reply.send(support::reply(403, full("no"))).unwrap();
        peer.run_until(|p| finished(p, s)).await;
        assert_eq!(statuses(&peer, s), ["403"]);
        assert!(matches!(
            on.await.unwrap_err().kind(),
            ErrorKind::NotUpgraded
        ));
        peer.send_datagram(s, &udp(b"late")).unwrap();
        peer.send_body(s, b"", true);
        while let Some(d) = drive(&mut peer, sd.recv()).await.expect("no abort") {
            assert_eq!(d, udp(b"late"));
        }
        assert_eq!(sd.send(udp(b"x")), Err(DatagramError::Closed));
        let abort = |o: &PeerObs| match o {
            PeerObs::Reset { stream, .. } => *stream == s,
            PeerObs::Event(Event::StreamAborted { stream, .. })
            | PeerObs::Event(Event::SendStopped { stream, .. }) => *stream == s,
            _ => false,
        };
        assert!(!peer.trace().iter().any(abort), "{:?}", peer.trace());

        // The h3wire-async client: the 403 still carries the handle; it is closed.
        let (mut p, mut reqs) = masque(&server_builder()).await;
        let resp = tokio::spawn(p.send.send_request(connect_udp_request::<BoxBody>(
            "localhost",
            TARGET,
            443,
        )));
        let (mut req, reply) = reqs.recv().await.unwrap();
        let (mut sd, _on) = accept(&mut req);
        reply.send(support::reply(403, empty())).unwrap();
        let resp = resp.await.unwrap().unwrap();
        assert_eq!(resp.status(), 403);
        let mut cd = resp
            .extensions()
            .get::<DatagramSlot>()
            .unwrap()
            .register()
            .unwrap();
        assert_eq!(cd.send(udp(b"x")), Err(DatagramError::Closed));
        assert_eq!(cd.recv().await.unwrap(), None);
        assert_eq!(sd.recv().await.unwrap(), None);
    })
    .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn pending_queue_overflow() {
    with_timeout(async {
        let mut b = server_builder();
        b.pending_datagrams_per_stream(3, 1 << 20);
        let (mut peer, mut reqs, _server, _conns) = peer_masque(&b, true).await;
        // A is not registered yet; B is, and serves as a barrier.
        let a = peer_connect_udp(&mut peer).await;
        let (mut req_a, _reply_a) = drive(&mut peer, reqs.recv()).await.unwrap();
        let b = peer_connect_udp(&mut peer).await;
        let (mut req_b, _reply_b) = drive(&mut peer, reqs.recv()).await.unwrap();
        let (mut db, _on_b) = accept(&mut req_b);
        for m in ["0", "1", "2", "3", "4"] {
            peer.send_datagram(a, &udp(m.as_bytes())).unwrap();
        }
        peer.send_datagram(b, &udp(b"barrier")).unwrap();
        // Datagrams are routed in arrival order: A's five are pending once B's arrives.
        assert_eq!(
            drive(&mut peer, db.recv()).await.unwrap().unwrap(),
            udp(b"barrier")
        );
        // The three newest were kept.
        let (mut da, _on_a) = accept(&mut req_a);
        for m in ["2", "3", "4"] {
            let d = drive(&mut peer, da.recv()).await.unwrap().unwrap();
            assert_eq!(d, udp(m.as_bytes()));
        }
        peer.send_datagram(a, &udp(b"5")).unwrap();
        assert_eq!(
            drive(&mut peer, da.recv()).await.unwrap().unwrap(),
            udp(b"5")
        );
    })
    .await
}

/// `d` refuses one byte over `max_payload` (the transport's limit minus QSID 0's one
/// byte) and delivers exactly `max_payload` to `peer`.
async fn limit_edge(d: &Datagrams, peer: &mut Datagrams, conn: &quinn::Connection) {
    let n = d.max_payload().unwrap();
    assert_eq!(n, conn.max_datagram_size().unwrap() - 1);
    let big = Bytes::from(vec![7; n + 1]);
    assert_eq!(d.send(big.clone()), Err(DatagramError::TooLarge));
    d.send(big.slice(..n)).unwrap();
    assert_eq!(peer.recv().await.unwrap().unwrap(), big.slice(..n));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn too_large() {
    with_timeout(async {
        let (mut p, mut reqs) = masque(&server_builder()).await;
        let Udp {
            ct: _ct,
            mut cd,
            st: _st,
            mut sd,
        } = open(&mut p, &mut reqs).await;
        limit_edge(&cd, &mut sd, &p.conns.client).await;
        limit_edge(&sd, &mut cd, &p.conns.server).await;
    })
    .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn datagrams_after_close() {
    with_timeout(async {
        let (mut p, mut reqs) = masque(&server_builder()).await;
        // The request ends normally: both handles are closed and end cleanly.
        let Udp {
            mut ct,
            mut cd,
            mut st,
            mut sd,
        } = open(&mut p, &mut reqs).await;
        ct.finish().unwrap();
        assert_eq!(read_to_end(&mut st).await.unwrap(), b"");
        st.finish().unwrap();
        assert_eq!(read_to_end(&mut ct).await.unwrap(), b"");
        for d in [&mut cd, &mut sd] {
            assert_eq!(d.send(udp(b"x")), Err(DatagramError::Closed));
            assert_eq!(d.max_payload(), None);
            assert_eq!(d.recv().await.unwrap(), None);
        }

        // The connection closes: receiving fails, sending is closed.
        let Udp {
            ct: _ct,
            mut cd,
            st: _st,
            mut sd,
        } = open(&mut p, &mut reqs).await;
        p.conns.server.close(quinn::VarInt::from_u32(0x100), b""); // H3_NO_ERROR
        for d in [&mut cd, &mut sd] {
            d.recv().await.expect_err("closed");
            assert_eq!(d.send(udp(b"x")), Err(DatagramError::Closed));
            assert_eq!(d.max_payload(), None);
        }
    })
    .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn capsules_split_and_coalesced() {
    with_timeout(async {
        let (mut peer, mut reqs, _server, _conns) = peer_masque(&server_builder(), true).await;
        let s = peer_connect_udp(&mut peer).await;
        let (mut req, reply) = drive(&mut peer, reqs.recv()).await.unwrap();
        let (sd, on) = accept(&mut req);
        reply.send(support::reply(200, empty())).unwrap();
        let proxy = proxy(drive(&mut peer, on).await.unwrap(), sd);
        // Small capsules, an empty one, and one of 40,000 bytes (a four-byte length,
        // more than one read at the server).
        let big = pattern(40_000);
        let mut wire = Vec::new();
        for p in [&b"a"[..], b"bb", b"", &big, b"c", &[0x55; 64]] {
            wire.extend(capsule(DATAGRAM, p));
        }
        // DATA frames of 1, 3, 2 and 4093 bytes in turn: frame boundaries land inside
        // varints and payloads, and a frame holds several capsules.
        let mut rest = &wire[..];
        for size in [1, 3, 2, 4093].into_iter().cycle() {
            if rest.is_empty() {
                break;
            }
            let n = size.min(rest.len());
            peer.send_body(s, &rest[..n], false);
            rest = &rest[n..];
        }
        peer.send_body(s, b"", true);
        // Every capsule comes back, in order (canonical encoding: the same bytes).
        peer.run_until(|p| finished(p, s)).await;
        assert_eq!(peer.body(s), wire);
        proxy.await.unwrap().unwrap();
    })
    .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn unknown_capsules_skipped() {
    with_timeout(async {
        let (mut p, mut reqs) = masque(&server_builder()).await;
        let Udp {
            mut ct,
            cd: _cd,
            st,
            sd,
        } = open(&mut p, &mut reqs).await;
        let proxy = proxy(st, sd);
        let mut first = capsule(0x2a, b"unknown");
        first.extend(capsule(DATAGRAM, b"one"));
        first.extend(capsule(0x4040, b"")); // a four-byte type, empty
        first.extend(capsule(varint::MAX, &[1; 3])); // an eight-byte type
        // 100 KiB to skip, over several reads.
        first.extend(capsule(0x3f, &pattern(100 << 10)));
        ct.send(first.into()).await.unwrap();
        ct.send(capsule(DATAGRAM, b"two").into()).await.unwrap();
        ct.finish().unwrap();
        let mut want = capsule(DATAGRAM, b"one");
        want.extend(capsule(DATAGRAM, b"two"));
        assert_eq!(read_to_end(&mut ct).await.unwrap(), want);
        proxy.await.unwrap().unwrap();
    })
    .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn truncated_capsule_aborts_message_error() {
    with_timeout(async {
        let (mut p, mut reqs) = masque(&server_builder()).await;
        let a = open(&mut p, &mut reqs).await;
        let b = open(&mut p, &mut reqs).await;
        let (proxy_a, proxy_b) = (proxy(a.st, a.sd), proxy(b.st, b.sd));
        let (mut ct, mut cd) = (a.ct, a.cd);
        // One complete DATA frame, then FIN: a whole capsule and one whose length says
        // 10 but only 3 bytes follow.
        let mut wire = capsule(DATAGRAM, b"ok");
        wire.extend([0x00, 0x0a, b'x', b'y', b'z']);
        ct.send(wire.into()).await.unwrap();
        ct.finish().unwrap();
        // The proxy aborts with H3_MESSAGE_ERROR (its echo of "ok" may or may not arrive).
        let echo = capsule(DATAGRAM, b"ok");
        let mut got = Vec::new();
        let e = loop {
            match ct.recv().await {
                Ok(Some(b)) => got.extend_from_slice(&b),
                Ok(None) => panic!("a clean end"),
                Err(e) => break e,
            }
        };
        assert!(aborted(&e, MSG, AbortSource::Peer), "{e:?}");
        assert!(echo.starts_with(&got), "{got:?}");
        let e = cd.recv().await.expect_err("aborted");
        assert!(aborted(&e, MSG, AbortSource::Peer), "{e:?}");
        proxy_a.await.unwrap().unwrap();
        // The other tunnel keeps echoing.
        let (mut ct, mut cd) = (b.ct, b.cd);
        capsule_echo(&mut ct, &mut CapsuleParser::default(), b"still here").await;
        dgram_echo(&mut cd, b"still here").await;
        close(ct, proxy_b).await;
    })
    .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn peer_reset_mid_tunnel() {
    with_timeout(async {
        let (mut peer, mut reqs, _server, _conns) = peer_masque(&server_builder(), true).await;
        let s = peer_connect_udp(&mut peer).await;
        let (mut req, reply) = drive(&mut peer, reqs.recv()).await.unwrap();
        let (mut sd, on) = accept(&mut req);
        reply.send(support::reply(200, empty())).unwrap();
        let mut st = drive(&mut peer, on).await.unwrap();
        // Mid-tunnel: a capsule and a datagram have arrived.
        let c = capsule(DATAGRAM, b"mid");
        peer.send_body(s, &c, false);
        assert_eq!(drive(&mut peer, st.recv()).await.unwrap().unwrap(), c);
        peer.send_datagram(s, &udp(b"mid")).unwrap();
        assert_eq!(
            drive(&mut peer, sd.recv()).await.unwrap().unwrap(),
            udp(b"mid")
        );
        peer.reset(s, RC);
        // The tunnel and the datagrams fail; the response direction is reset too.
        let e = drive(&mut peer, st.recv()).await.expect_err("reset");
        assert!(aborted(&e, RC, AbortSource::Peer), "{e:?}");
        let e = sd.recv().await.expect_err("reset");
        assert!(aborted(&e, RC, AbortSource::Peer), "{e:?}");
        assert_eq!(sd.send(udp(b"x")), Err(DatagramError::Closed));
        st.send(Bytes::from_static(b"x"))
            .await
            .expect_err("aborted");
        let reset = PeerObs::Event(Event::StreamAborted {
            stream: s,
            code: RC,
            source: AbortSource::Peer,
        });
        peer.run_until(|p| p.trace().contains(&reset)).await;
    })
    .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn stalled_reader_other_tunnel_progresses() {
    with_timeout(async {
        let (mut p, mut reqs) = masque(&server_builder()).await;
        let a = open(&mut p, &mut reqs).await;
        let b = open(&mut p, &mut reqs).await;
        let (proxy_a, proxy_b) = (proxy(a.st, a.sd), proxy(b.st, b.sd));
        // A's client never reads, so its echo backs up into the proxy, which then stops
        // reading A. 8 MiB is far more than A's stream can hold unread (quinn's stream
        // windows, 1.25 MB each way, plus h3wire's 64 KiB queues): A's writer blocks.
        let (mut tx, mut rx) = a.ct.split();
        let chunk = Bytes::from(capsule(DATAGRAM, &pattern(16_000)));
        let total = (8 << 20) / chunk.len() * chunk.len();
        let (full, filling) = oneshot::channel();
        let c = chunk.clone();
        let writer = tokio::spawn(async move {
            let (chunk, mut full) = (c, Some(full));
            for k in 0..total / chunk.len() {
                tx.send(chunk.clone()).await.unwrap();
                if k * chunk.len() >= 1 << 20 {
                    if let Some(f) = full.take() {
                        let _ = f.send(());
                    }
                }
            }
            tx.finish().unwrap();
            tx
        });
        filling.await.unwrap(); // 1 MiB of A is in flight
        let (mut ct, mut cd) = (b.ct, b.cd);
        let mut parser = CapsuleParser::default();
        for i in 0..20 {
            let msg = format!("b {i}");
            capsule_echo(&mut ct, &mut parser, msg.as_bytes()).await;
            dgram_echo_lossy(&mut cd, msg.as_bytes()).await;
        }
        assert!(!writer.is_finished(), "A's writer is blocked");
        close(ct, proxy_b).await;
        // Reading A unblocks it: every byte comes back.
        let mut n = 0;
        while let Some(b) = rx.recv().await.unwrap() {
            assert!(
                chunk
                    .iter()
                    .cycle()
                    .skip(n % chunk.len())
                    .zip(&b)
                    .all(|(x, y)| x == y)
            );
            n += b.len();
        }
        assert_eq!(n, total);
        writer.await.unwrap();
        proxy_a.await.unwrap().unwrap();
    })
    .await
}

/// QSID 16384 (stream id 65,536) takes four bytes of the datagram limit.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn qsid_four_byte_varint() {
    with_timeout(async {
        let (svc, mut reqs) = handoff();
        let mut p = pair_with(conns().await, &server_builder(), svc).await;
        // GETs use up stream ids 0..=65,532; CONNECTs go to the test.
        let (tx, mut connects) = mpsc::unbounded_channel();
        tokio::spawn(async move {
            while let Some((req, reply)) = reqs.recv().await {
                if req.method() == Method::GET {
                    // `req` outlives the request's task: a complete response stays whole.
                    let _ = reply.send(support::reply(200, empty()));
                } else {
                    let _ = tx.send((req, reply));
                }
            }
        });
        let mut set = tokio::task::JoinSet::new();
        for _ in 0..16_384 {
            let r = p.send.send_request(get("/"));
            set.spawn(async move { assert_eq!(r.await.unwrap().status(), 200) });
        }
        while let Some(r) = set.join_next().await {
            r.unwrap();
        }
        let limit = p.conns.client.max_datagram_size().unwrap();
        let Udp { ct, mut cd, st, sd } = open(&mut p, &mut connects).await;
        assert_eq!(cd.max_payload(), Some(limit - 4));
        let proxy = proxy(st, sd);
        dgram_echo(&mut cd, b"far").await;
        close(ct, proxy).await;
    })
    .await
}
