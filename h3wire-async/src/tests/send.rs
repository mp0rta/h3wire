// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 mp0rta
use super::driver::{done, setup, spawn, take};
use super::recv::{REQ, settle};
use crate::__testing::exec::{TestExec, run};
use crate::__testing::{Ack, CorePeer, MockConn, MockNet, MockObs, PeerObs, Side};
use crate::body::spawn_body_pipe;
use crate::builder::Builder;
use crate::error::BoxError;
use crate::rt::{Cancelable, Executor, Owns};
use crate::state::Shared;
use bytes::Bytes;
use h3wire::{AbortSource, Config, Event, H3Code, Role, StreamId};
use http::HeaderMap;
use http_body::{Body, Frame};
use std::collections::VecDeque;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::task::{Context, Poll};

const S: usize = 65_536;

/// A scripted body: `frames` in order, always ready; then the end, or (with `stall`)
/// pending forever. `repeat` makes it an endless always-ready body. Counts polls; sets
/// `dropped` when dropped.
#[derive(Default)]
pub(super) struct TestBody {
    frames: VecDeque<Result<Frame<Bytes>, BoxError>>,
    repeat: Option<Bytes>,
    stall: bool,
    polls: Arc<AtomicUsize>,
    dropped: DropFlag,
}

impl TestBody {
    pub(super) fn data(chunks: &[&[u8]]) -> Self {
        TestBody {
            frames: chunks
                .iter()
                .map(|c| Ok(Frame::data(Bytes::copy_from_slice(c))))
                .collect(),
            ..TestBody::default()
        }
    }

    fn trailers(mut self, name: &'static str, value: &'static str) -> Self {
        let mut t = HeaderMap::new();
        t.insert(name, value.parse().unwrap());
        self.frames.push_back(Ok(Frame::trailers(t)));
        self
    }
}

impl Body for TestBody {
    type Data = Bytes;
    type Error = BoxError;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        _: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, BoxError>>> {
        self.polls.fetch_add(1, Ordering::SeqCst);
        if let Some(r) = &self.repeat {
            return Poll::Ready(Some(Ok(Frame::data(r.clone()))));
        }
        match self.frames.pop_front() {
            Some(f) => Poll::Ready(Some(f)),
            None if self.stall => Poll::Pending,
            None => Poll::Ready(None),
        }
    }
}

#[derive(Default)]
struct DropFlag(Arc<AtomicBool>);
impl Drop for DropFlag {
    fn drop(&mut self) {
        self.0.store(true, Ordering::SeqCst);
    }
}

/// A client driver (spawned) with request streams opened on it, and a server `CorePeer`.
struct Client {
    net: MockNet,
    peer: CorePeer<MockConn>,
    shared: Shared,
    exec: TestExec,
    ids: Vec<StreamId>,
}

fn client(streams: usize, net_setup: impl FnOnce(&MockNet)) -> Client {
    let (net, mut driver, peer) = setup(Role::Client, &Builder::new(), Config::default());
    net_setup(&net);
    let ids = (0..streams)
        .map(|_| driver.open_request(&REQ, false))
        .collect();
    let shared = driver.shared();
    let exec = TestExec::default();
    let _ = spawn(&exec, driver);
    Client {
        net,
        peer,
        shared,
        exec,
        ids,
    }
}

fn queued(sh: &Shared, s: StreamId) -> (usize, usize) {
    sh.with(|i| {
        let q = &i.streams[&s].send;
        (q.queued, q.queue.len())
    })
}

fn fins(net: &MockNet, s: StreamId) -> usize {
    net.trace()
        .iter()
        .filter(|o| matches!(o, MockObs::Fin { side: Side::Client, stream } if *stream == s))
        .count()
}

pub(super) fn finished(p: &CorePeer<MockConn>, s: StreamId) -> bool {
    p.trace().contains(&PeerObs::Event(Event::Finished(s)))
}

/// Frame types and body lengths the peer saw on `s`, in order.
fn frames(p: &CorePeer<MockConn>, s: StreamId) -> (Vec<u64>, Vec<usize>) {
    let mut tys = Vec::new();
    let mut lens = Vec::new();
    for o in p.trace() {
        match *o {
            PeerObs::Frame { stream, ty } if stream == s => tys.push(ty),
            PeerObs::Body { stream, len } if stream == s => lens.push(len),
            _ => {}
        }
    }
    (tys, lens)
}

fn flag() -> Arc<AtomicBool> {
    Arc::new(AtomicBool::new(false))
}

fn set(f: &Arc<AtomicBool>) -> bool {
    f.load(Ordering::SeqCst)
}

#[test]
fn send_capacity_bound() {
    let mut c = client(1, |_| {});
    let s = c.ids[0];
    c.net.block_writes(Side::Client, s, true);
    let body = TestBody {
        repeat: Some(Bytes::from(vec![1; 8_192])),
        ..TestBody::default()
    };
    let polls = body.polls.clone();
    run(&c.exec, async {
        spawn_body_pipe(c.shared.clone(), s, body, &c.exec, Owns::Send);
        settle(&mut c.peer).await;
        let (q, _) = queued(&c.shared, s);
        assert!((S..=S + 8_192).contains(&q), "queued {q}");
        let n = polls.load(Ordering::SeqCst);
        assert!(n > 0);
        settle(&mut c.peer).await;
        assert_eq!(
            polls.load(Ordering::SeqCst),
            n,
            "not polled while not admitted"
        );
        assert_eq!(queued(&c.shared, s).0, q);
    });
}

#[test]
fn oversized_chunk_accepted_whole() {
    let mut c = client(1, |_| {});
    let s = c.ids[0];
    c.net.block_writes(Side::Client, s, true);
    let big: Vec<u8> = (0..200_000u32).map(|n| n as u8).collect();
    let body = TestBody::data(&[&big]);
    run(&c.exec, async {
        spawn_body_pipe(c.shared.clone(), s, body, &c.exec, Owns::Send);
        settle(&mut c.peer).await;
        assert_eq!(
            queued(&c.shared, s),
            (200_000, 1),
            "admitted whole, not split"
        );
        c.net.block_writes(Side::Client, s, false);
        c.peer.run_until(|p| finished(p, s)).await;
    });
    assert_eq!(c.peer.body(s), big);
    assert_eq!(frames(&c.peer, s), (vec![0x01, 0x00], vec![200_000]));
    assert_eq!(fins(&c.net, s), 1);
}

#[test]
fn partial_writes_fully_accounted() {
    let mut c = client(2, |n| n.max_write(Some(1)));
    let (s, s2) = (c.ids[0], c.ids[1]);
    let payload: Vec<u8> = (0..300u32).map(|n| n as u8).collect();
    let body = TestBody::data(&[&payload[..100], &payload[100..]]).trailers("x-t", "1");
    run(&c.exec, async {
        spawn_body_pipe(c.shared.clone(), s, body, &c.exec, Owns::Send);
        c.peer.run_until(|p| finished(p, s)).await;
        // Every accepted byte was reported: the next body goes out normally.
        spawn_body_pipe(
            c.shared.clone(),
            s2,
            TestBody::data(&[b"z"]),
            &c.exec,
            Owns::Send,
        );
        c.peer.run_until(|p| finished(p, s2)).await;
    });
    assert_eq!(c.peer.body(s), payload);
    let heads = c.peer.headers(s);
    assert_eq!(heads.len(), 2);
    assert_eq!(heads[1], vec![("x-t".to_string(), "1".to_string())]);
    assert_eq!(fins(&c.net, s), 1);
    assert_eq!(c.peer.body(s2), b"z");
    assert_eq!(fins(&c.net, s2), 1);
}

#[test]
fn empty_chunks_are_skipped() {
    let mut c = client(1, |_| {});
    let s = c.ids[0];
    let body = TestBody::data(&[b"", b"ab", b"", b"c", b""]);
    run(&c.exec, async {
        spawn_body_pipe(c.shared.clone(), s, body, &c.exec, Owns::Send);
        c.peer.run_until(|p| finished(p, s)).await;
        settle(&mut c.peer).await;
    });
    assert_eq!(frames(&c.peer, s), (vec![0x01, 0x00, 0x00], vec![2, 1]));
    assert_eq!(fins(&c.net, s), 1);
}

#[test]
fn trailers_sent_as_headers() {
    let mut c = client(1, |_| {});
    let s = c.ids[0];
    let body = TestBody::data(&[b"abc"]).trailers("x-t", "1");
    run(&c.exec, async {
        spawn_body_pipe(c.shared.clone(), s, body, &c.exec, Owns::Send);
        c.peer.run_until(|p| finished(p, s)).await;
        settle(&mut c.peer).await;
    });
    assert_eq!(frames(&c.peer, s), (vec![0x01, 0x00, 0x01], vec![3]));
    assert_eq!(
        c.peer.headers(s)[1],
        vec![("x-t".to_string(), "1".to_string())]
    );
    assert_eq!(fins(&c.net, s), 1);
}

#[test]
fn client_body_error_aborts_internal_error() {
    let mut c = client(1, |_| {});
    let s = c.ids[0];
    let mut body = TestBody::data(&[b"abc"]);
    body.frames.push_back(Err("boom".into()));
    let aborted = PeerObs::Event(Event::StreamAborted {
        stream: s,
        code: H3Code::INTERNAL_ERROR,
        source: AbortSource::Peer,
    });
    run(&c.exec, async {
        spawn_body_pipe(c.shared.clone(), s, body, &c.exec, Owns::Send);
        c.peer.run_until(|p| p.trace().contains(&aborted)).await;
    });
    assert!(c.net.trace().contains(&MockObs::Reset {
        side: Side::Client,
        stream: s,
        code: 0x102
    }));
    assert_eq!(fins(&c.net, s), 0);
}

/// Spawn a task owning `owns` of `s` that never completes; `true` once it is dropped.
fn spawn_owner(sh: &Shared, exec: &TestExec, s: StreamId, owns: Owns) -> Arc<AtomicBool> {
    let f = flag();
    let guard = DropFlag(f.clone());
    let token = sh.with(|i| i.cancel_token(s, owns));
    let fut = async move {
        let _g = guard;
        std::future::pending::<()>().await
    };
    exec.execute(Box::pin(Cancelable::new(Box::pin(fut), token)));
    f
}

#[test]
fn stop_sending_cancels_send_owning_task_only() {
    let mut c = client(1, |_| {});
    let s = c.ids[0];
    let body = TestBody {
        stall: true,
        ..TestBody::default()
    };
    let pipe_dropped = body.dropped.0.clone();
    let polls = body.polls.clone();
    run(&c.exec, async {
        spawn_body_pipe(c.shared.clone(), s, body, &c.exec, Owns::Send);
        let both = spawn_owner(&c.shared, &c.exec, s, Owns::Both);
        c.peer.run_until(|p| !p.headers(s).is_empty()).await;
        settle(&mut c.peer).await;
        // The pipe waits inside the body: only the token can end it.
        assert!(polls.load(Ordering::SeqCst) > 0 && !set(&pipe_dropped));
        c.peer.stop_sending(s, H3Code::REQUEST_CANCELLED);
        c.peer.run_until(|_| set(&pipe_dropped)).await;
        settle(&mut c.peer).await;
        assert!(!set(&both), "the receive side is still live");
        // The response ends the receive side too.
        c.peer.send_headers(s, &[(":status", "200")], true).unwrap();
        c.peer.run_until(|_| set(&both)).await;
    });
    assert!(c.net.trace().contains(&MockObs::Reset {
        side: Side::Client,
        stream: s,
        code: 0x10c
    }));
}

#[test]
fn ack_tracked_after_finish() {
    let mut c = client(1, |n| n.ack_mode(Ack::Manual));
    let s = c.ids[0];
    let acked = |sh: &Shared| sh.with(|i| i.streams[&s].send.acked);
    run(&c.exec, async {
        spawn_body_pipe(
            c.shared.clone(),
            s,
            TestBody::data(&[b"abc"]),
            &c.exec,
            Owns::Send,
        );
        c.peer.run_until(|p| finished(p, s)).await;
        settle(&mut c.peer).await;
        assert_eq!(fins(&c.net, s), 1);
        assert!(!acked(&c.shared), "FIN sent but not acknowledged");
        c.net.ack_all();
        c.peer.run_until(|_| acked(&c.shared)).await;
    });
}

#[test]
fn cancel_on_connection_close() {
    let mut c = client(1, |_| {});
    let s = c.ids[0];
    let body = TestBody {
        stall: true,
        ..TestBody::default()
    };
    let pipe_dropped = body.dropped.0.clone();
    let polls = body.polls.clone();
    run(&c.exec, async {
        spawn_body_pipe(c.shared.clone(), s, body, &c.exec, Owns::Send);
        let both = spawn_owner(&c.shared, &c.exec, s, Owns::Both);
        settle(&mut c.peer).await;
        assert!(polls.load(Ordering::SeqCst) > 0);
        assert!(!set(&pipe_dropped) && !set(&both));
        c.net.kill_transport(Side::Client, None);
        c.peer.run_until(|_| set(&pipe_dropped) && set(&both)).await;
        // A token taken after the close fires at once.
        let token = c.shared.with(|i| i.cancel_token(s, Owns::Both));
        let late = spawn(
            &c.exec,
            Cancelable::new(Box::pin(std::future::pending()), token),
        );
        c.peer.run_until(|_| done(&late)).await;
        take(&late);
    });
}

/// Another thread aborts `s` between a transport write and its accounting (the core has
/// reaped the stream by then): the driver must not panic, write nothing more of that
/// frame, and the abort must reach the peer.
fn abort_between_write_and_accounting(mid_body: bool) {
    let mut c = client(1, |n| n.max_write(Some(1)));
    let s = c.ids[0];
    let aborted = PeerObs::Event(Event::StreamAborted {
        stream: s,
        code: H3Code::REQUEST_CANCELLED,
        source: AbortSource::Peer,
    });
    let abort = {
        let sh = c.shared.clone();
        move || {
            sh.with(|i| {
                i.conn.abort(s, H3Code::REQUEST_CANCELLED).unwrap();
                i.wake_driver();
            })
        }
    };
    if !mid_body {
        // The first write on `s` is HEADERS: the `sent` path.
        c.net.on_write(Side::Client, s, abort.clone());
    }
    run(&c.exec, async {
        spawn_body_pipe(
            c.shared.clone(),
            s,
            TestBody::data(&[&[7; 4_000]]),
            &c.exec,
            Owns::Send,
        );
        if mid_body {
            // DATA prefix seen: the next write is payload, the `data_written` path.
            c.peer.run_until(|p| frames(p, s).0.len() == 2).await;
            c.net.on_write(Side::Client, s, abort);
        }
        for _ in 0..4 {
            settle(&mut c.peer).await;
        }
    });
    assert!(
        c.peer.trace().contains(&aborted),
        "driver survived; abort reached the peer"
    );
    let t = c.net.trace();
    let reset = t
        .iter()
        .position(
            |o| matches!(o, MockObs::Reset { side: Side::Client, stream, .. } if *stream == s),
        )
        .expect("RESET_STREAM sent");
    let writes_after = t[reset..]
        .iter()
        .filter(|o| matches!(o, MockObs::Write { side: Side::Client, stream, .. } if *stream == s))
        .count();
    assert_eq!(writes_after, 0);
    assert!(c.peer.body(s).len() < 4_000);
    assert_eq!(fins(&c.net, s), 0);
}

#[test]
fn concurrent_abort_between_write_and_accounting() {
    abort_between_write_and_accounting(false);
    abort_between_write_and_accounting(true);
}
