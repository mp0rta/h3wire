// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 mp0rta
//! HTTP datagrams (spec §3.4): registration, routing and the `Datagrams` handle. An
//! h3wire-async server with a `CorePeer` client where raw control is needed, or an
//! h3wire-async pair.

use super::client::{client, drive, get, seen};
use super::driver::{done, poll_once, spawn, take};
use super::recv::yield_now;
use super::upgrade::{
    Handed, Handoff, aborted_any, connect, out, plain, reply, request, reset_by, stopped_by, until,
};
use crate::__testing::exec::{TestExec, run};
use crate::__testing::{CorePeer, MockConn, MockNet, MockObs, PeerObs, Side};
use crate::builder::Builder;
use crate::datagram::{DatagramSlot, Datagrams, RegisterDatagrams};
use crate::error::{DatagramError, ErrorKind};
use crate::ext::ConnInfo;
use crate::upgrade;
use bytes::Bytes;
use futures::StreamExt;
use futures::channel::mpsc;
use h3wire::{Config, H3Code, Role, StreamId};
use http::Response;
use http_body::Body;
use std::future::{Future, poll_fn};
use std::pin::{Pin, pin};
use std::task::Poll;

type Peer = CorePeer<MockConn>;
type Reqs = mpsc::UnboundedReceiver<Handed>;

const CONNECT: [(&str, &str); 2] = [(":method", "CONNECT"), (":authority", "a:443")];
const POST: [(&str, &str); 4] = [
    (":method", "POST"),
    (":scheme", "https"),
    (":authority", "a"),
    (":path", "/"),
];
const DG: u64 = H3Code::DATAGRAM_ERROR.0;

fn peer_cfg(h3_datagram: bool) -> Config {
    let mut c = Config::default();
    c.h3_datagram = h3_datagram;
    c
}

/// A server built by `b` (spawned), and a client `CorePeer` advertising
/// `H3_DATAGRAM = dgram`.
fn server(b: &Builder, dgram: bool) -> (MockNet, ConnInfo, Peer, Reqs, TestExec) {
    let (net, c, s) = MockNet::pair();
    let exec = TestExec::default();
    let (tx, reqs) = mpsc::unbounded();
    let srv = b.serve_connection(s, Handoff(tx), exec.clone());
    let info = ConnInfo::new(srv.driver.shared());
    spawn(&exec, srv);
    let peer = CorePeer::new(Role::Client, peer_cfg(dgram), c);
    (net, info, peer, reqs, exec)
}

/// The peer opens a request with `fields` (no FIN); the request the Service received.
async fn open(peer: &mut Peer, reqs: &mut Reqs, fields: &[(&str, &str)]) -> (StreamId, Handed) {
    let s = peer.open_bidi().await.unwrap();
    peer.send_headers(s, fields, false).unwrap();
    (s, drive(peer, &mut reqs.next()).await.expect("a request"))
}

fn slot<T>(m: &http::Request<T>) -> DatagramSlot {
    m.extensions()
        .get::<DatagramSlot>()
        .expect("a slot")
        .clone()
}

fn resp_slot<T>(m: &Response<T>) -> Option<DatagramSlot> {
    m.extensions().get::<DatagramSlot>().cloned()
}

/// Step the peer and let every task run until `pred` holds.
async fn wait(peer: &mut Peer, mut pred: impl FnMut(&Peer) -> bool) {
    for _ in 0..10_000 {
        if pred(peer) {
            return;
        }
        poll_fn(|cx| {
            while peer.poll_step(cx).is_ready() {}
            Poll::Ready(())
        })
        .await;
        yield_now().await;
    }
    panic!("condition not reached: {:?}", peer.trace());
}

/// The next datagram of `d`, stepping the peer meanwhile.
async fn next(peer: &mut Peer, d: &mut Datagrams) -> Option<Bytes> {
    drive(peer, &mut pin!(d.recv())).await.expect("no error")
}

fn peer_got(p: &Peer, s: StreamId, len: usize) -> bool {
    p.trace().contains(&PeerObs::Datagram { stream: s, len })
}

/// `side` aborted `s` with `H3_DATAGRAM_ERROR` (RESET_STREAM, or STOP_SENDING alone when
/// its send side was already over).
fn dg_abort(net: &MockNet, side: Side, s: StreamId) -> bool {
    reset_by(net, side, s) == Some(DG) || stopped_by(net, side, s) == Some(DG)
}

fn negotiated(peer: &mut Peer) -> impl Future<Output = ()> + '_ {
    wait(peer, |p| p.core().peer_settings().is_some())
}

#[test]
fn registered_echo() {
    let mut p = plain();
    let exec = p.exec.clone();
    run(&exec, async {
        let mut r = connect();
        r.extensions_mut().insert(RegisterDatagrams);
        let (resp, (mut req, tx)) = request(&mut p, r).await;
        let mut sd = slot(&req).register().expect("server handle");
        let on = upgrade::on(&mut req);
        tx.send(reply(200, "")).unwrap();
        let resp = out(&resp).await.expect("a response");
        let mut cd = resp_slot(&resp).unwrap().register().expect("client handle");
        until(|| cd.max_payload().is_some() && sd.max_payload().is_some()).await;
        cd.send(Bytes::from_static(b"ping")).unwrap();
        let got = sd.recv().await.unwrap().unwrap();
        assert_eq!(got, "ping");
        sd.send(got).unwrap();
        assert_eq!(cd.recv().await.unwrap().unwrap(), "ping");
        drop((on, req, resp));
    });
    assert!(!aborted_any(&p.net, StreamId(0)), "{:?}", p.net.trace());
}

#[test]
fn not_yet_open_dropped() {
    let (_net, info, mut peer, mut reqs, exec) = server(&Builder::new(), true);
    run(&exec, async {
        negotiated(&mut peer).await;
        let s = peer.open_bidi().await.unwrap();
        // Queued in the peer's core; the datagram goes out first.
        peer.send_headers(s, &CONNECT, false).unwrap();
        peer.send_datagram(s, b"early").unwrap();
        for _ in 0..64 {
            yield_now().await; // the server routes it: NotYetOpen
        }
        let (req, _tx) = drive(&mut peer, &mut reqs.next()).await.unwrap();
        assert_eq!(info.__debug_datagram_accounting(), (0, 0, 0));
        let mut d = slot(&req).register().unwrap();
        peer.send_datagram(s, b"late").unwrap();
        assert_eq!(next(&mut peer, &mut d).await.unwrap(), "late");
    });
}

#[test]
fn pending_until_registration() {
    let (net, info, mut peer, mut reqs, exec) = server(&Builder::new(), true);
    run(&exec, async {
        let (s, (req, _tx)) = open(&mut peer, &mut reqs, &CONNECT).await;
        negotiated(&mut peer).await;
        for m in ["a", "bb", "ccc"] {
            peer.send_datagram(s, m.as_bytes()).unwrap();
        }
        until(|| info.__debug_datagram_accounting() == (0, 3, 6)).await;
        let mut d = slot(&req).register().unwrap();
        assert_eq!(info.__debug_datagram_accounting(), (3, 0, 0));
        for m in ["a", "bb", "ccc"] {
            assert_eq!(next(&mut peer, &mut d).await.unwrap(), m);
        }
        assert!(!aborted_any(&net, s), "{:?}", net.trace());
    });
}

/// Server, unregistered: a datagram pending at the final response, or one arriving
/// after it, aborts the request with `H3_DATAGRAM_ERROR`.
fn unregistered_server(pending: bool) {
    let (net, info, mut peer, mut reqs, exec) = server(&Builder::new(), true);
    run(&exec, async {
        let (s, (req, tx)) = open(&mut peer, &mut reqs, &POST).await;
        negotiated(&mut peer).await;
        if pending {
            peer.send_datagram(s, b"x").unwrap();
            until(|| info.__debug_datagram_accounting() == (0, 1, 1)).await;
        }
        tx.send(reply(200, "ok")).unwrap();
        if !pending {
            wait(&mut peer, |p| seen(p, s)).await;
            peer.send_datagram(s, b"x").unwrap();
        }
        wait(&mut peer, |_| dg_abort(&net, Side::Server, s)).await;
        assert_eq!(info.__debug_datagram_accounting(), (0, 0, 0));
        drop(req);
    });
}

/// Client, unregistered: a datagram pending when the final response arrives aborts.
fn unregistered_client() {
    let (net, mut send, conn, mut peer, exec) = client::<String>(&Builder::new(), peer_cfg(true));
    let info = ConnInfo::new(send.shared.clone());
    run(&exec, async {
        spawn(&exec, conn);
        let resp = spawn(&exec, send.send_request(get("https://a/")));
        let s = StreamId(0);
        wait(&mut peer, |p| {
            seen(p, s) && p.core().peer_settings().is_some()
        })
        .await;
        peer.send_datagram(s, b"x").unwrap();
        until(|| info.__debug_datagram_accounting() == (0, 1, 1)).await;
        peer.send_headers(s, &[(":status", "200")], false).unwrap();
        wait(&mut peer, |_| done(&resp)).await;
        let resp = take(&resp).expect("a response");
        assert!(resp_slot(&resp).is_none(), "not registered");
        wait(&mut peer, |_| dg_abort(&net, Side::Client, s)).await;
    });
}

#[test]
fn unregistered_final_response_aborts_datagram_error() {
    unregistered_server(true);
    unregistered_server(false);
    unregistered_client();
}

#[test]
fn registered_rejected_connect_drops_silently() {
    let (net, _info, mut peer, mut reqs, exec) = server(&Builder::new(), true);
    run(&exec, async {
        let (s, (req, tx)) = open(&mut peer, &mut reqs, &CONNECT).await;
        let mut d = slot(&req).register().unwrap();
        tx.send(reply(403, "")).unwrap();
        wait(&mut peer, |p| {
            seen(p, s) && p.core().peer_settings().is_some()
        })
        .await;
        peer.send_datagram(s, b"late").unwrap();
        assert_eq!(next(&mut peer, &mut d).await.unwrap(), "late");
        peer.send_body(s, b"", true);
        assert_eq!(next(&mut peer, &mut d).await, None, "the request ended");
        drop(req);
        drop(d);
        wait(&mut peer, |_| true).await;
        assert!(!aborted_any(&net, s), "{:?}", net.trace());
    });
}

#[test]
fn pending_overflow_evicts_oldest() {
    let mut b = Builder::new();
    // Per stream: 3 datagrams; per connection: 4 bytes (each datagram is 1 byte).
    b.pending_datagrams_per_stream(3, 1 << 20)
        .pending_datagrams_per_conn(100, 4);
    let (net, info, mut peer, mut reqs, exec) = server(&b, true);
    run(&exec, async {
        let (s0, (r0, _t0)) = open(&mut peer, &mut reqs, &CONNECT).await;
        let (s4, (r4, _t4)) = open(&mut peer, &mut reqs, &CONNECT).await;
        negotiated(&mut peer).await;
        for m in ["0", "1", "2", "3", "4"] {
            peer.send_datagram(s0, m.as_bytes()).unwrap();
        }
        until(|| info.__debug_datagram_accounting() == (0, 3, 3)).await;
        for m in ["a", "b"] {
            peer.send_datagram(s4, m.as_bytes()).unwrap();
        }
        until(|| info.__debug_datagram_accounting() == (0, 4, 4)).await;
        let mut d0 = slot(&r0).register().unwrap();
        let mut d4 = slot(&r4).register().unwrap();
        for m in ["3", "4"] {
            assert_eq!(next(&mut peer, &mut d0).await.unwrap(), m);
        }
        for m in ["a", "b"] {
            assert_eq!(next(&mut peer, &mut d4).await.unwrap(), m);
        }
        assert!(!aborted_any(&net, s0) && !aborted_any(&net, s4));
    });
}

#[test]
fn send_before_settings_not_negotiated() {
    let (_net, _info, mut peer, mut reqs, exec) = server(&Builder::new(), true);
    peer.defer_control(true);
    run(&exec, async {
        let (s, (req, _tx)) = open(&mut peer, &mut reqs, &CONNECT).await;
        // The slot is there although the peer's SETTINGS are still pending.
        let d = slot(&req).register().unwrap();
        let x = || Bytes::from_static(b"x");
        assert_eq!(d.send(x()), Err(DatagramError::NotNegotiated));
        assert_eq!(d.max_payload(), None);
        peer.bind_control_now();
        wait(&mut peer, |_| d.max_payload().is_some()).await;
        assert_eq!(d.max_payload(), Some(1199));
        d.send(x()).unwrap();
        wait(&mut peer, |p| peer_got(p, s, 1)).await;
    });
}

#[test]
fn peer_h3_datagram_zero_unsupported() {
    let (_net, info, mut peer, mut reqs, exec) = server(&Builder::new(), false);
    run(&exec, async {
        let (_s, (req, _tx)) = open(&mut peer, &mut reqs, &CONNECT).await;
        let d = slot(&req).register().unwrap();
        until(|| info.peer_settings().is_some()).await;
        assert_eq!(
            d.send(Bytes::from_static(b"x")),
            Err(DatagramError::Unsupported)
        );
        assert_eq!(d.max_payload(), None);
    });
}

#[test]
fn too_large_after_limit_shrinks() {
    let (net, _info, mut peer, mut reqs, exec) = server(&Builder::new(), true);
    run(&exec, async {
        let (s, (req, _tx)) = open(&mut peer, &mut reqs, &CONNECT).await;
        let d = slot(&req).register().unwrap();
        wait(&mut peer, |_| d.max_payload().is_some()).await;
        let n = |n: usize| Bytes::from(vec![7; n]);
        assert_eq!(d.max_payload(), Some(1199));
        d.send(n(1199)).unwrap();
        assert_eq!(d.send(n(1200)), Err(DatagramError::TooLarge));
        wait(&mut peer, |p| peer_got(p, s, 1199)).await;
        net.set_max_datagram_size(Side::Server, Some(100));
        // Accepted against the limit of the driver's last pass, then refused by the
        // transport: lost, like any datagram.
        d.send(n(500)).unwrap();
        wait(&mut peer, |_| d.max_payload() == Some(99)).await;
        assert_eq!(d.send(n(100)), Err(DatagramError::TooLarge));
        d.send(n(99)).unwrap();
        wait(&mut peer, |p| peer_got(p, s, 99)).await;
        assert!(!peer_got(&peer, s, 500));
        assert!(!aborted_any(&net, s));
    });
}

#[test]
fn qsid_varint_boundaries() {
    for (s, prefix) in [(StreamId(256), 2), (StreamId(65_536), 4)] {
        let (net, _info, mut peer, mut reqs, exec) = server(&Builder::new(), true);
        net.skip_bidi(Side::Client, s.0 / 4);
        run(&exec, async {
            let (id, (req, _tx)) = open(&mut peer, &mut reqs, &CONNECT).await;
            assert_eq!(id, s);
            let mut d = slot(&req).register().unwrap();
            wait(&mut peer, |_| d.max_payload().is_some()).await;
            assert_eq!(d.max_payload(), Some(1200 - prefix));
            d.send(Bytes::from_static(b"0123456789")).unwrap();
            wait(&mut peer, |p| peer_got(p, s, 10)).await;
            let len = 10 + prefix;
            assert!(
                net.trace().contains(&MockObs::Datagram {
                    side: Side::Server,
                    len
                }),
                "{prefix}-byte prefix"
            );
            peer.send_datagram(s, b"back").unwrap();
            assert_eq!(next(&mut peer, &mut d).await.unwrap(), "back");
        });
    }
}

#[test]
fn datagrams_after_close() {
    let (net, _info, mut peer, mut reqs, exec) = server(&Builder::new(), true);
    run(&exec, async {
        let x = || Bytes::from_static(b"x");
        // The request ends: a rejected CONNECT, then the peer's FIN.
        let (s, (req, tx)) = open(&mut peer, &mut reqs, &CONNECT).await;
        let mut d = slot(&req).register().unwrap();
        wait(&mut peer, |_| d.max_payload().is_some()).await;
        tx.send(reply(403, "")).unwrap();
        wait(&mut peer, |p| seen(p, s)).await;
        assert_eq!(d.send(x()), Err(DatagramError::Closed));
        peer.send_body(s, b"", true);
        assert_eq!(next(&mut peer, &mut d).await, None);
        drop(req);
        // The connection closes.
        let (_s, (req, _tx)) = open(&mut peer, &mut reqs, &CONNECT).await;
        let mut d = slot(&req).register().unwrap();
        net.kill_transport(Side::Server, Some(0x10c));
        let e = drive(&mut peer, &mut pin!(d.recv()))
            .await
            .expect_err("closed");
        assert!(
            matches!(e.kind(), ErrorKind::Transport(t) if t.peer_app_code == Some(0x10c)),
            "{e:?}"
        );
        assert_eq!(d.send(x()), Err(DatagramError::Closed));
        assert_eq!(d.max_payload(), None);
    });
}

#[test]
fn datagram_receive_never_blocks_driver() {
    let (_net, c, s) = MockNet::pair();
    let exec = TestExec::default();
    let (tx, mut reqs) = mpsc::unbounded();
    let mut b = Builder::new();
    b.work_budget(8);
    let mut srv = b.serve_connection(s, Handoff(tx), exec.clone());
    let info = ConnInfo::new(srv.driver.shared());
    let mut peer = CorePeer::new(Role::Client, peer_cfg(true), c);
    run(&exec, async {
        /// Poll `f`, stepping the peer and polling the server, until `f` completes.
        async fn go<F: Future + Unpin>(
            peer: &mut Peer,
            srv: &mut (impl Future + Unpin),
            f: &mut F,
        ) -> F::Output {
            poll_fn(|cx| {
                loop {
                    if let Poll::Ready(v) = Pin::new(&mut *f).poll(cx) {
                        return Poll::Ready(v);
                    }
                    assert!(Pin::new(&mut *srv).poll(cx).is_pending());
                    if peer.poll_step(cx).is_pending() {
                        return Poll::Pending;
                    }
                }
            })
            .await
        }
        let s = peer.open_bidi().await.unwrap();
        peer.send_headers(s, &POST, false).unwrap();
        let (req, _tx) = go(&mut peer, &mut srv, &mut reqs.next()).await.unwrap();
        let mut d = slot(&req).register().unwrap();
        while d.max_payload().is_none() || peer.core().peer_settings().is_none() {
            go(&mut peer, &mut srv, &mut pin!(yield_now())).await;
        }
        for n in 0..200u8 {
            peer.send_datagram(s, &[n]).unwrap();
        }
        // One pass routes at most the work budget.
        assert!(poll_once(&mut srv).await.is_pending());
        let q = info.__debug_datagram_accounting().0;
        assert!(q > 0 && q <= 8, "{q}");
        // Nobody reads the handle, yet the request body flows.
        peer.send_body(s, b"abc", false);
        let mut body = req.into_body();
        let f = go(
            &mut peer,
            &mut srv,
            &mut poll_fn(|cx| Pin::new(&mut body).poll_frame(cx)),
        )
        .await;
        let data = f.unwrap().unwrap().into_data().unwrap();
        assert_eq!(data, "abc");
        for _ in 0..64 {
            go(&mut peer, &mut srv, &mut pin!(yield_now())).await; // >= 25 passes of 8
        }
        assert_eq!(info.__debug_datagram_accounting().0, 64);
        // Drop-oldest: the last 64 of 200 are kept.
        let first = go(&mut peer, &mut srv, &mut pin!(d.recv())).await;
        assert_eq!(first.unwrap().unwrap(), &[136u8][..]);
        drop(body);
    });
}

#[test]
fn slot_clone_single_registration() {
    let mut p = plain();
    let exec = p.exec.clone();
    run(&exec, async {
        // Server: the first `register` of any clone wins.
        let mut r = get("https://a/");
        r.extensions_mut().insert(RegisterDatagrams);
        let (resp, (req, tx)) = request(&mut p, r).await;
        let (a, b) = (slot(&req), slot(&req));
        assert!(a.register().is_some());
        assert!(b.register().is_none() && a.register().is_none());
        tx.send(reply(200, "")).unwrap();
        // Client: registered at send; the handle comes back in the response.
        let resp = out(&resp).await.expect("a response");
        let (a, b) = (resp_slot(&resp).unwrap(), resp_slot(&resp).unwrap());
        assert!(b.register().is_some());
        assert!(a.register().is_none() && b.register().is_none());
        // Without `RegisterDatagrams` there is no slot.
        let (resp, (_req, tx)) = request(&mut p, get("https://a/")).await;
        tx.send(reply(200, "")).unwrap();
        assert!(resp_slot(&out(&resp).await.unwrap()).is_none());
        drop(req);
    });
}
