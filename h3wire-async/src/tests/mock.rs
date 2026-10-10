// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 mp0rta
use crate::__testing::exec::{TestExec, run};
use crate::__testing::mock::{MockRecv, MockSend};
use crate::__testing::{Ack, MockConn, MockNet, MockObs, Side};
use crate::builder::Builder;
use crate::quic::{
    Connection, ReadError, RecvStream, SendDatagramError, SendStream, WriteError, Written,
};
use bytes::Bytes;
use futures::task::{ArcWake, noop_waker, waker};
use h3wire::StreamId;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::task::{Context, Poll};

fn poll<T>(f: impl FnOnce(&mut Context<'_>) -> Poll<T>) -> Poll<T> {
    let w = noop_waker();
    f(&mut Context::from_waker(&w))
}

fn ready<T>(f: impl FnOnce(&mut Context<'_>) -> Poll<T>) -> T {
    match poll(f) {
        Poll::Ready(v) => v,
        Poll::Pending => panic!("unexpected Pending"),
    }
}

fn b(s: &'static str) -> Bytes {
    Bytes::from_static(s.as_bytes())
}

type Halves = (MockSend, MockRecv);

/// Client opens a bidi stream and the server accepts it.
fn bidi(c: &mut MockConn, s: &mut MockConn) -> (Halves, Halves) {
    let a = ready(|cx| c.poll_open_bidi(cx)).unwrap();
    let p = ready(|cx| s.poll_accept_bidi(cx)).unwrap();
    (a, p)
}

#[test]
fn mock_streams_roundtrip() {
    let (_net, mut c, mut s) = MockNet::pair();
    let ((mut cs, _cr), (_ss, mut sr)) = bidi(&mut c, &mut s);
    assert_eq!(cs.id(), StreamId(0));
    assert_eq!(sr.id(), StreamId(0));
    let mut bufs = [b("hello"), b(" "), b("world")];
    let w = ready(|cx| cs.poll_write_chunks(cx, &mut bufs)).unwrap();
    assert_eq!(
        w,
        Written {
            bytes: 11,
            chunks: 3
        }
    );
    // Never more than max_len, chunks in order.
    let mut got = Vec::new();
    while got.len() < 11 {
        let c = ready(|cx| sr.poll_read_chunk(cx, 4)).unwrap().unwrap();
        assert!(c.len() <= 4);
        got.extend_from_slice(&c);
    }
    assert_eq!(got, b"hello world");
    assert!(poll(|cx| sr.poll_read_chunk(cx, 4)).is_pending());
    cs.finish();
    assert!(ready(|cx| sr.poll_read_chunk(cx, 4)).unwrap().is_none());
    // The server's own uni stream gets the next server-initiated id.
    let mut uni = ready(|cx| s.poll_open_uni(cx)).unwrap();
    assert_eq!(uni.id(), StreamId(3));
    let mut cu = ready(|cx| c.poll_accept_uni(cx)).unwrap();
    assert_eq!(cu.id(), StreamId(3));
    ready(|cx| uni.poll_write_chunks(cx, &mut [b("x")])).unwrap();
    assert_eq!(ready(|cx| cu.poll_read_chunk(cx, 8)).unwrap().unwrap(), "x");
}

#[test]
fn mock_partial_write_accounting() {
    let (net, mut c, mut s) = MockNet::pair();
    let ((mut cs, _), (_, mut sr)) = bidi(&mut c, &mut s);
    net.max_write(Some(5));
    let mut bufs = [b("abc"), b("defgh")];
    let w = ready(|cx| cs.poll_write_chunks(cx, &mut bufs)).unwrap();
    assert_eq!(
        w,
        Written {
            bytes: 5,
            chunks: 1
        }
    );
    assert_eq!(bufs[1], "fgh");
    let mut got = Vec::new();
    while got.len() < 5 {
        got.extend_from_slice(&ready(|cx| sr.poll_read_chunk(cx, 16)).unwrap().unwrap());
    }
    assert_eq!(got, b"abcde");
}

#[test]
fn mock_peer_reset_surfaces_as_read_error() {
    let (_net, mut c, mut s) = MockNet::pair();
    let ((mut cs, _), (_, mut sr)) = bidi(&mut c, &mut s);
    ready(|cx| cs.poll_write_chunks(cx, &mut [b("x")])).unwrap();
    cs.reset(0x10c);
    assert!(matches!(
        ready(|cx| sr.poll_read_chunk(cx, 8)),
        Err(ReadError::Reset(0x10c))
    ));
}

#[test]
fn mock_stopped_and_manual_ack() {
    let (net, mut c, mut s) = MockNet::pair();
    net.ack_mode(Ack::Manual);
    let ((mut cs, _), (_, mut sr)) = bidi(&mut c, &mut s);
    net.ack_all(); // too early: must not pre-ack
    cs.finish();
    assert!(poll(|cx| cs.poll_stopped(cx)).is_pending());
    assert!(ready(|cx| sr.poll_read_chunk(cx, 8)).unwrap().is_none());
    assert!(poll(|cx| cs.poll_stopped(cx)).is_pending());
    net.ack_all();
    assert!(matches!(ready(|cx| cs.poll_stopped(cx)), Ok(None)));

    // A peer STOP_SENDING wins over acknowledgement.
    let ((mut cs2, _), (_, mut sr2)) = bidi(&mut c, &mut s);
    assert!(poll(|cx| cs2.poll_stopped(cx)).is_pending());
    sr2.stop(0x3);
    assert!(matches!(ready(|cx| cs2.poll_stopped(cx)), Ok(Some(0x3))));
    assert!(matches!(
        ready(|cx| cs2.poll_write_chunks(cx, &mut [b("x")])),
        Err(WriteError::Stopped(0x3))
    ));
    assert!(net.trace().contains(&MockObs::Stop {
        side: Side::Server,
        stream: StreamId(4),
        code: 3
    }));
}

#[test]
fn mock_datagram_size_and_loss() {
    let (net, mut c, mut s) = MockNet::pair();
    net.set_max_datagram_size(Side::Client, Some(4));
    assert_eq!(c.max_datagram_size(), Some(4));
    assert!(matches!(
        c.send_datagram(b("toolong")),
        Err(SendDatagramError::TooLarge)
    ));
    c.send_datagram(b("ab")).unwrap();
    assert_eq!(ready(|cx| s.poll_recv_datagram(cx)).unwrap(), "ab");
    net.datagram_loss(true);
    c.send_datagram(b("cd")).unwrap();
    assert!(poll(|cx| s.poll_recv_datagram(cx)).is_pending());
    net.datagram_loss(false);
    net.datagram_reorder(true);
    c.send_datagram(b("1")).unwrap();
    c.send_datagram(b("2")).unwrap();
    assert_eq!(ready(|cx| s.poll_recv_datagram(cx)).unwrap(), "2");
    net.set_max_datagram_size(Side::Client, None);
    assert!(matches!(
        c.send_datagram(b("x")),
        Err(SendDatagramError::Unsupported)
    ));
}

struct Flag(AtomicBool);
impl ArcWake for Flag {
    fn wake_by_ref(this: &Arc<Self>) {
        this.0.store(true, Ordering::SeqCst);
    }
}

#[test]
fn mock_kill_transport() {
    let (net, mut c, mut s) = MockNet::pair();
    let ((_cs, _), (_, mut sr)) = bidi(&mut c, &mut s);
    let flag = Arc::new(Flag(AtomicBool::new(false)));
    let w = waker(flag.clone());
    assert!(
        sr.poll_read_chunk(&mut Context::from_waker(&w), 8)
            .is_pending()
    );
    net.kill_transport(Side::Server, Some(0x10c));
    assert!(flag.0.load(Ordering::SeqCst));
    match ready(|cx| sr.poll_read_chunk(cx, 8)) {
        Err(ReadError::Transport(e)) => assert_eq!(e.peer_app_code, Some(0x10c)),
        other => panic!("{other:?}"),
    }
    let e = ready(|cx| s.poll_accept_uni(cx)).unwrap_err();
    assert_eq!(e.peer_app_code, Some(0x10c));
}

#[test]
fn mock_stream_credit_and_close() {
    let (net, mut c, mut s) = MockNet::pair();
    net.max_bidi_streams(Side::Client, 1);
    let ((mut cs, mut cr), (mut ss, mut sr)) = bidi(&mut c, &mut s);
    assert!(poll(|cx| c.poll_open_bidi(cx)).is_pending());
    // Both directions end: the credit comes back.
    cs.finish();
    ss.finish();
    assert!(ready(|cx| sr.poll_read_chunk(cx, 1)).unwrap().is_none());
    assert!(ready(|cx| cr.poll_read_chunk(cx, 1)).unwrap().is_none());
    assert!(poll(|cx| c.poll_open_bidi(cx)).is_ready());
    assert_eq!(net.pending_accepts(Side::Server), 1);
    c.close(0x100);
    assert_eq!(net.closed_with(Side::Client), Some(0x100));
    assert_eq!(
        ready(|cx| s.poll_accept_uni(cx)).unwrap_err().peer_app_code,
        Some(0x100)
    );
}

#[test]
fn builder_defaults() {
    let b = Builder::new();
    assert_eq!(b.read_ahead, 65_536);
    assert_eq!(b.demand_chunk, 16_384);
    assert_eq!(b.send_capacity, 65_536);
    assert_eq!(b.read_ahead_cap, 1 << 20);
    assert_eq!(b.work_budget, 64);
    assert!(b.core_config(true).h3_datagram);
    assert!(!b.core_config(false).h3_datagram);
    let mut b = Builder::new();
    assert!(b.add_setting(0x1234, 1).is_ok());
    assert!(b.add_setting(0x1234, 2).is_err());
    assert!(b.add_setting(0x33, 1).is_err()); // GREASE
}

#[test]
fn test_exec_drops_panicking_task() {
    use crate::rt::Executor;
    let exec = TestExec::default();
    let (tx, rx) = futures::channel::oneshot::channel();
    exec.execute(Box::pin(async { panic!("expected: test task panic") }));
    let inner = exec.clone();
    exec.execute(Box::pin(async move {
        // Spawned from inside a running task.
        inner.execute(Box::pin(async move {
            let _ = tx.send(7);
        }));
    }));
    assert_eq!(run(&exec, async { rx.await.unwrap() }), 7);
}

#[test]
fn mock_close_first_wins() {
    let (net, mut c, mut s) = MockNet::pair();
    s.close(0x1);
    c.close(0x2);
    net.kill_transport(Side::Server, Some(0x3));
    assert_eq!(net.closed_with(Side::Server), Some(0x1));
    assert_eq!(net.closed_with(Side::Client), None);
    assert_eq!(net.trace().len(), 1);
    assert_eq!(
        ready(|cx| c.poll_accept_uni(cx)).unwrap_err().peer_app_code,
        Some(0x1)
    );
    assert_eq!(
        ready(|cx| s.poll_accept_uni(cx)).unwrap_err().peer_app_code,
        None
    );
}

#[test]
fn mock_write_never_yields_empty_chunks() {
    let (net, mut c, mut s) = MockNet::pair();
    let ((mut cs, _), (_, mut sr)) = bidi(&mut c, &mut s);
    net.max_write(Some(3));
    let mut bufs = [b("abc"), b(""), b("def")];
    let w = ready(|cx| cs.poll_write_chunks(cx, &mut bufs)).unwrap();
    assert_eq!(
        w,
        Written {
            bytes: 3,
            chunks: 2
        }
    );
    assert_eq!(
        ready(|cx| sr.poll_read_chunk(cx, 16)).unwrap().unwrap(),
        "abc"
    );
    assert!(poll(|cx| sr.poll_read_chunk(cx, 16)).is_pending());
    // Zero capacity pends (like quinn) instead of returning Written{0,0}.
    net.max_write(Some(0));
    assert!(poll(|cx| cs.poll_write_chunks(cx, &mut bufs)).is_pending());
    net.max_write(None);
    let w = ready(|cx| cs.poll_write_chunks(cx, &mut bufs)).unwrap();
    assert_eq!(w.bytes, 6);
}

#[cfg(feature = "tokio")]
#[test]
fn tokio_executor_runs_task() {
    use crate::rt::{Executor, TokioExecutor};
    let rt = tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap();
    let ran = Arc::new(AtomicBool::new(false));
    let flag = ran.clone();
    rt.block_on(async move {
        TokioExecutor.execute(Box::pin(async move { flag.store(true, Ordering::SeqCst) }));
        // The spawned task runs when this one yields; no sleeps, and a bounded wait.
        for _ in 0..1000 {
            if ran.load(Ordering::SeqCst) {
                break;
            }
            tokio::task::yield_now().await;
        }
        assert!(ran.load(Ordering::SeqCst), "the task did not run");
    });
}
