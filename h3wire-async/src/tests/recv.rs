// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 mp0rta
use super::driver::{done, setup, spawn, take};
use crate::__testing::exec::{TestExec, run};
use crate::__testing::{CorePeer, MockConn, MockNet, MockObs, PeerObs, Side};
use crate::body::RecvBody;
use crate::builder::Builder;
use crate::error::{Error, ErrorKind};
use crate::ext::ConnInfo;
use crate::state::{Dir, Shared};
use bytes::Bytes;
use h3wire::{AbortSource, Config, Event, FieldRef, H3Code, Role, StreamId};
use http_body::{Body, Frame};
use std::future::poll_fn;
use std::pin::Pin;
use std::task::Poll;

const D: usize = 16_384;
const REQ: [(&str, &str); 4] = [
    (":method", "POST"),
    (":scheme", "https"),
    (":authority", "a"),
    (":path", "/"),
];

fn zero_cap() -> Builder {
    let mut b = Builder::new();
    b.read_ahead_cap(0).read_ahead(0);
    b
}

/// A HEADERS frame (static-table QPACK) for `fields`.
fn headers_frame(fields: &[(&str, &str)]) -> Vec<u8> {
    let f: Vec<FieldRef> = fields
        .iter()
        .map(|(n, v)| FieldRef::new(n.as_bytes(), v.as_bytes()))
        .collect();
    let mut block = Vec::new();
    h3wire::qpack::encoder::encode_field_section(&f, &mut block);
    let mut out = Vec::new();
    h3wire::frame::encode_header(0x01, block.len() as u64, &mut out);
    out.extend_from_slice(&block);
    out
}

fn data_frame(payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    h3wire::frame::encode_header(0x00, payload.len() as u64, &mut out);
    out.extend_from_slice(payload);
    out
}

async fn yield_now() {
    let mut yielded = false;
    poll_fn(|cx| {
        if yielded {
            return Poll::Ready(());
        }
        yielded = true;
        cx.waker().wake_by_ref();
        Poll::Pending
    })
    .await
}

/// Step the peer and give the driver task a bounded number of turns.
async fn settle(peer: &mut CorePeer<MockConn>) {
    for _ in 0..64 {
        poll_fn(|cx| {
            while peer.poll_step(cx).is_ready() {}
            Poll::Ready(())
        })
        .await;
        yield_now().await;
    }
}

fn has_head(sh: &Shared, s: StreamId) -> bool {
    sh.with(|i| i.streams.get(&s).is_some_and(|st| st.head.is_some()))
}

/// What Tasks 6–7 do on delivery: release the head, wake the stream, hand out the body.
fn take_body(sh: &Shared, s: StreamId) -> RecvBody {
    sh.with(|i| {
        let b = i.streams.get_mut(&s).unwrap().head.take().unwrap();
        i.conn.release(b);
        i.mark_ready(s, Dir::Recv);
    });
    RecvBody::new(sh.clone(), s)
}

/// The next frame of `body`, stepping `peer` while it pends.
async fn next_frame(
    peer: &mut CorePeer<MockConn>,
    body: &mut RecvBody,
) -> Option<Result<Frame<Bytes>, Error>> {
    poll_fn(|cx| {
        loop {
            if let Poll::Ready(f) = Pin::new(&mut *body).poll_frame(cx) {
                return Poll::Ready(f);
            }
            if peer.poll_step(cx).is_pending() {
                return Poll::Pending;
            }
        }
    })
    .await
}

fn data(f: Option<Result<Frame<Bytes>, Error>>) -> Bytes {
    f.expect("a frame")
        .expect("no error")
        .into_data()
        .expect("DATA")
}

/// A server driver with a request on `s` whose head was discovered; returns the body.
struct Server {
    net: MockNet,
    peer: CorePeer<MockConn>,
    shared: Shared,
    info: ConnInfo,
    exec: TestExec,
}

fn server(b: &Builder) -> Server {
    let (net, driver, peer) = setup(Role::Server, b, Config::default());
    let shared = driver.shared();
    let info = ConnInfo::new(shared.clone());
    let exec = TestExec::default();
    let _ = spawn(&exec, driver);
    Server {
        net,
        peer,
        shared,
        info,
        exec,
    }
}

#[test]
fn body_and_trailers_delivered() {
    let Server {
        mut peer,
        shared,
        exec,
        ..
    } = server(&Builder::new());
    run(&exec, async {
        let s = peer.open_bidi().await.unwrap();
        peer.send_headers(s, &REQ, false).unwrap();
        peer.send_body(s, b"hello", false);
        peer.send_body(s, b" world", false);
        settle(&mut peer).await;
        peer.send_headers(s, &[("x-t", "1")], true).unwrap();
        peer.run_until(|_| has_head(&shared, s)).await;
        let mut body = take_body(&shared, s);
        let mut got = Vec::new();
        let trailers = loop {
            match next_frame(&mut peer, &mut body).await.unwrap().unwrap() {
                f if f.is_data() => got.extend_from_slice(&f.into_data().unwrap()),
                f => break f.into_trailers().unwrap(),
            }
        };
        assert_eq!(got, b"hello world");
        assert_eq!(trailers["x-t"], "1");
        assert!(next_frame(&mut peer, &mut body).await.is_none());
        assert!(body.is_end_stream());
    });
}

#[test]
fn trailers_only_completion() {
    let Server {
        mut peer,
        shared,
        exec,
        ..
    } = server(&Builder::new());
    run(&exec, async {
        let s = peer.open_bidi().await.unwrap();
        peer.send_headers(s, &REQ, false).unwrap();
        peer.send_headers(s, &[("x-t", "1")], true).unwrap();
        peer.run_until(|_| has_head(&shared, s)).await;
        let mut body = take_body(&shared, s);
        let ended = |sh: &Shared| {
            sh.with(|i| i.streams[&s].recv.eof && i.streams[&s].recv.trailers.is_some())
        };
        peer.run_until(|_| ended(&shared)).await;
        assert!(!body.is_end_stream());
        let t = next_frame(&mut peer, &mut body).await.unwrap().unwrap();
        assert_eq!(t.into_trailers().unwrap()["x-t"], "1");
        assert!(next_frame(&mut peer, &mut body).await.is_none());
        assert!(body.is_end_stream());
    });
}

#[test]
fn read_ahead_bounded_without_demand() {
    let Server {
        mut peer,
        shared,
        info,
        exec,
        ..
    } = server(&Builder::new());
    run(&exec, async {
        let s = peer.open_bidi().await.unwrap();
        peer.send_headers(s, &REQ, false).unwrap();
        for _ in 0..16 {
            peer.send_body(s, &[7; 65_536], false);
        }
        peer.run_until(|_| has_head(&shared, s)).await;
        let _body = take_body(&shared, s);
        let mut max = 0;
        for _ in 0..64 {
            settle(&mut peer).await;
            max = max.max(info.__debug_recv_accounting().0);
        }
        assert_eq!(max, 65_536, "read-ahead fills, and no further");
    });
}

fn informational_then_final(one_chunk: bool) {
    let (_net, mut driver, mut peer) = setup(Role::Client, &zero_cap(), Config::default());
    let shared = driver.shared();
    let get = [
        (":method", "GET"),
        (":scheme", "https"),
        (":authority", "a"),
        (":path", "/"),
    ];
    let s = driver.open_request(&get, true);
    let exec = TestExec::default();
    let _ = spawn(&exec, driver);
    let discovering = |sh: &Shared| sh.with(|i| i.streams[&s].discovering);
    run(&exec, async {
        peer.run_until(|p| !p.headers(s).is_empty()).await;
        let (h100, h200) = (
            headers_frame(&[(":status", "100")]),
            headers_frame(&[(":status", "200")]),
        );
        if one_chunk {
            peer.send_raw(s, &[h100, h200].concat());
        } else {
            peer.send_raw(s, &h100);
            settle(&mut peer).await;
            assert!(discovering(&shared), "a 1xx does not end discovery");
            assert!(!has_head(&shared, s));
            peer.send_raw(s, &h200);
        }
        peer.run_until(|_| has_head(&shared, s)).await;
    });
    assert!(!discovering(&shared));
    shared.with(|i| {
        let head = i.streams[&s].head.unwrap();
        let h = i.conn.headers(head).unwrap();
        let status = h.all().find(|f| f.name == b":status").unwrap();
        assert_eq!(status.value, b"200");
    });
}

#[test]
fn informational_then_final_with_zero_cap() {
    informational_then_final(true);
    informational_then_final(false);
}

#[test]
fn coalesced_headers_and_data_with_zero_cap() {
    let Server {
        mut peer,
        shared,
        info,
        exec,
        ..
    } = server(&zero_cap());
    let discovery = 65_536 + 16;
    run(&exec, async {
        let s = peer.open_bidi().await.unwrap();
        let chunk = [headers_frame(&REQ), data_frame(&[9; 32_768])].concat();
        peer.send_raw(s, &chunk);
        peer.run_until(|_| has_head(&shared, s)).await;
        settle(&mut peer).await;
        let (queued, _, retained) = info.__debug_recv_accounting();
        assert_eq!(queued, 0, "nothing is fed without a budget");
        assert!(retained > 32_768 && retained <= discovery, "{retained}");
        let mut body = take_body(&shared, s);
        let mut got = 0;
        while got < 32_768 {
            let b = data(next_frame(&mut peer, &mut body).await);
            assert!(b.len() <= D);
            assert!(info.__debug_recv_accounting().0 <= D);
            got += b.len();
        }
        assert_eq!(got, 32_768);
    });
}

#[test]
fn aggregate_cap_and_reservations() {
    const CAP: usize = 262_144;
    let mut b = Builder::new();
    b.read_ahead_cap(CAP);
    let Server {
        mut peer,
        shared,
        info,
        exec,
        ..
    } = server(&b);
    run(&exec, async {
        let mut ids = Vec::new();
        for _ in 0..32 {
            let s = peer.open_bidi().await.unwrap();
            peer.send_headers(s, &REQ, false).unwrap();
            for _ in 0..4 {
                peer.send_body(s, &[1; 65_536], false);
            }
            ids.push(s);
        }
        peer.run_until(|_| ids.iter().all(|&s| has_head(&shared, s)))
            .await;
        let mut bodies: Vec<RecvBody> = ids.iter().map(|&s| take_body(&shared, s)).collect();
        let mut got = [0usize; 3];
        poll_fn(|cx| {
            loop {
                let mut moved = false;
                for (k, body) in bodies[..3].iter_mut().enumerate() {
                    while let Poll::Ready(Some(Ok(f))) = Pin::new(&mut *body).poll_frame(cx) {
                        got[k] += f.into_data().unwrap().len();
                        moved = true;
                    }
                }
                let (queued, reservations, _) = info.__debug_recv_accounting();
                assert!(reservations <= 3);
                assert!(queued <= CAP + D * 3, "queued {queued}");
                if got.iter().all(|&g| g == 4 * 65_536) {
                    return Poll::Ready(());
                }
                if peer.poll_step(cx).is_pending() && !moved {
                    return Poll::Pending;
                }
            }
        })
        .await;
        drop(bodies);
    });
}

#[test]
fn reservation_held_after_consumer_cancel() {
    let Server {
        mut peer,
        shared,
        info,
        exec,
        ..
    } = server(&zero_cap());
    run(&exec, async {
        let s = peer.open_bidi().await.unwrap();
        peer.send_headers(s, &REQ, false).unwrap();
        peer.send_body(s, &[3; 65_536], false);
        peer.run_until(|_| has_head(&shared, s)).await;
        let mut body = take_body(&shared, s);
        // One poll that pends, then the consumer goes away but keeps the handle.
        let first = poll_fn(|cx| Poll::Ready(Pin::new(&mut body).poll_frame(cx))).await;
        assert!(first.is_pending());
        settle(&mut peer).await;
        let held = info.__debug_recv_accounting();
        assert_eq!(held.1, 1, "the reservation is held");
        assert!(held.0 > 0 && held.0 <= D, "{held:?}");
        settle(&mut peer).await;
        assert_eq!(
            info.__debug_recv_accounting(),
            held,
            "no read without consumption"
        );
        let mut got = 0;
        while got < held.0 {
            got += data(next_frame(&mut peer, &mut body).await).len();
        }
        let (queued, reservations, _) = info.__debug_recv_accounting();
        assert_eq!(
            (queued, reservations),
            (0, 0),
            "consumed: reservation cleared"
        );
    });
}

#[test]
fn paused_bytes_and_fin_preserved() {
    let Server {
        mut peer,
        shared,
        info,
        exec,
        ..
    } = server(&Builder::new());
    run(&exec, async {
        let s = peer.open_bidi().await.unwrap();
        peer.send_headers(s, &REQ, false).unwrap();
        peer.send_body(s, b"abc", false);
        settle(&mut peer).await;
        peer.send_headers(s, &[("x-t", "1")], true).unwrap();
        settle(&mut peer).await;
        // The head is still unreleased: the trailers pause the stream.
        shared.with(|i| {
            let r = &i.streams[&s].recv;
            assert!(!r.eof && r.trailers.is_none());
        });
        let (queued, _, retained) = info.__debug_recv_accounting();
        assert_eq!(queued, 3);
        assert!(retained > 0, "the paused trailers are retained");
        let mut body = take_body(&shared, s);
        assert_eq!(&data(next_frame(&mut peer, &mut body).await)[..], b"abc");
        let t = next_frame(&mut peer, &mut body).await.unwrap().unwrap();
        assert_eq!(t.into_trailers().unwrap()["x-t"], "1");
        assert!(next_frame(&mut peer, &mut body).await.is_none(), "FIN kept");
        assert!(body.is_end_stream());
    });
}

#[test]
fn drop_body_early_aborts_request_cancelled() {
    let Server {
        net,
        mut peer,
        shared,
        exec,
        ..
    } = server(&Builder::new());
    run(&exec, async {
        let s = peer.open_bidi().await.unwrap();
        peer.send_headers(s, &REQ, false).unwrap();
        peer.send_body(s, &[5; 100], false);
        peer.run_until(|_| has_head(&shared, s)).await;
        drop(take_body(&shared, s));
        let aborted = PeerObs::Event(Event::StreamAborted {
            stream: s,
            code: H3Code::REQUEST_CANCELLED,
            source: AbortSource::Peer,
        });
        peer.run_until(|p| p.trace().contains(&aborted)).await;
        let t = net.trace();
        let code = 0x10c;
        assert!(t.contains(&MockObs::Reset {
            side: Side::Server,
            stream: s,
            code
        }));
        assert!(t.contains(&MockObs::Stop {
            side: Side::Server,
            stream: s,
            code
        }));
    });
}

#[test]
fn zero_copy_slices() {
    let Server {
        mut peer,
        shared,
        exec,
        ..
    } = server(&Builder::new());
    run(&exec, async {
        let s = peer.open_bidi().await.unwrap();
        let chunk = [
            headers_frame(&REQ),
            data_frame(&[1; 100]),
            data_frame(&[2; 100]),
        ]
        .concat();
        peer.send_raw(s, &chunk);
        peer.run_until(|_| has_head(&shared, s)).await;
        let mut body = take_body(&shared, s);
        let a = data(next_frame(&mut peer, &mut body).await);
        let b = data(next_frame(&mut peer, &mut body).await);
        assert_eq!((&a[..], &b[..]), (&[1; 100][..], &[2; 100][..]));
        // Both are slices of the one transport chunk: b starts after a and b's 3-byte
        // frame header.
        assert_eq!(b.as_ptr() as usize, a.as_ptr() as usize + 100 + 3);
    });
}

#[test]
fn connection_close_fails_pending_body() {
    let Server {
        net,
        mut peer,
        shared,
        exec,
        ..
    } = server(&Builder::new());
    run(&exec, async {
        let s = peer.open_bidi().await.unwrap();
        peer.send_headers(s, &REQ, false).unwrap();
        peer.run_until(|_| has_head(&shared, s)).await;
        let mut body = take_body(&shared, s);
        // A task of its own: only the body's waker re-polls it.
        let out = spawn(&exec, async move {
            poll_fn(|cx| Pin::new(&mut body).poll_frame(cx)).await
        });
        settle(&mut peer).await;
        assert!(!done(&out));
        net.kill_transport(Side::Server, Some(0x10c));
        poll_fn(|_| {
            if done(&out) {
                Poll::Ready(())
            } else {
                Poll::Pending
            }
        })
        .await;
        let e = take(&out).unwrap().unwrap_err();
        assert!(matches!(e.kind(), ErrorKind::Transport(_)), "{e:?}");
    });
}

#[test]
fn cap_room_wakes_held_back_streams() {
    let mut b = Builder::new();
    b.read_ahead_cap(65_536);
    let Server {
        mut peer,
        shared,
        exec,
        ..
    } = server(&b);
    let queued = |sh: &Shared, s: StreamId| sh.with(|i| i.streams[&s].recv.queued);
    run(&exec, async {
        let mut ids = Vec::new();
        for _ in 0..2 {
            let s = peer.open_bidi().await.unwrap();
            peer.send_headers(s, &REQ, false).unwrap();
            peer.send_body(s, &[4; 65_536], false);
            ids.push(s);
        }
        peer.run_until(|_| ids.iter().all(|&s| has_head(&shared, s)))
            .await;
        let mut bodies: Vec<RecvBody> = ids.iter().map(|&s| take_body(&shared, s)).collect();
        settle(&mut peer).await;
        // The cap went to one stream; the other one waits for room.
        let (full, held) = if queued(&shared, ids[0]) == 65_536 {
            (0, 1)
        } else {
            (1, 0)
        };
        assert_eq!(queued(&shared, ids[held]), 0);
        let mut got = 0;
        while got < 65_536 {
            got += data(next_frame(&mut peer, &mut bodies[full]).await).len();
        }
        settle(&mut peer).await;
        assert_eq!(
            queued(&shared, ids[held]),
            65_536,
            "read-ahead resumed without demand"
        );
    });
}
