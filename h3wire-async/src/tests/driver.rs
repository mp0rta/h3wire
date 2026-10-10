// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 mp0rta
use crate::__testing::exec::{TestExec, run};
use crate::__testing::{CorePeer, MockConn, MockNet, PeerObs, Side};
use crate::builder::Builder;
use crate::driver::Driver;
use crate::error::{Error, ErrorKind};
use crate::ext::ConnInfo;
use crate::rt::Executor;
use crate::slot::OnceSlot;
use crate::state::{Shared, assert_unlocked};
use futures::task::{ArcWake, noop_waker, waker};
use h3wire::{Config, Event, H3Code, PeerSettings, Role, StreamId};
use std::future::{Future, poll_fn};
use std::pin::{Pin, pin};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};

pub(super) type Out<T> = Arc<Mutex<Option<T>>>;

/// A driver of `role` on its side of a mock pair, and a `CorePeer` on the other side.
pub(super) fn setup(
    role: Role,
    b: &Builder,
    peer_cfg: Config,
) -> (MockNet, Driver<MockConn>, CorePeer<MockConn>) {
    let (net, c, s) = MockNet::pair();
    let (mine, theirs, peer_role) = match role {
        Role::Client => (c, s, Role::Server),
        Role::Server => (s, c, Role::Client),
    };
    let driver = Driver::new(mine, role, b);
    (net, driver, CorePeer::new(peer_role, peer_cfg, theirs))
}

/// Spawn `fut` on `exec`; its output lands in the returned slot.
pub(super) fn spawn<T: Send + 'static>(
    exec: &TestExec,
    fut: impl Future<Output = T> + Send + 'static,
) -> Out<T> {
    let out = Out::default();
    let o = out.clone();
    exec.execute(Box::pin(async move {
        let v = fut.await;
        *o.lock().unwrap() = Some(v);
    }));
    out
}

pub(super) fn done<T>(o: &Out<T>) -> bool {
    o.lock().unwrap().is_some()
}

pub(super) fn take<T>(o: &Out<T>) -> T {
    o.lock().unwrap().take().unwrap()
}

/// Poll `f` once.
pub(super) async fn poll_once<F: Future + Unpin>(f: &mut F) -> Poll<F::Output> {
    poll_fn(|cx| Poll::Ready(Pin::new(&mut *f).poll(cx))).await
}

fn peer_has_settings(p: &CorePeer<MockConn>) -> bool {
    p.trace().contains(&PeerObs::Event(Event::PeerSettings))
}

fn settings_exchange(race: bool) {
    let mut b = Builder::new();
    b.enable_connect_protocol(true);
    let mut cfg = Config::default();
    cfg.max_field_section_size = Some(1234);
    let (net, driver, mut peer) = setup(Role::Server, &b, cfg);
    net.readiness_before_register(race);
    let info = ConnInfo::new(driver.shared());
    assert_eq!(info.peer_settings(), None);
    let exec = TestExec::default();
    let res = run(&exec, async {
        let _drv = spawn(&exec, driver);
        peer.run_until(peer_has_settings).await;
        info.clone().settings().await
    });
    let got = res.expect("peer settings");
    assert_eq!(got.max_field_section_size, Some(1234));
    assert_eq!(info.peer_settings(), Some(got));
    let theirs = peer.core().peer_settings().unwrap();
    assert!(theirs.enable_connect_protocol);
    assert!(
        theirs.h3_datagram,
        "mock has datagrams, so the driver enables them"
    );
}

#[test]
fn settings_exchange_and_conninfo() {
    settings_exchange(false);
}

#[test]
fn wake_registration_race() {
    settings_exchange(true);
}

#[test]
fn critical_streams_progress_when_request_blocked() {
    let (_net, driver, mut peer) = setup(Role::Server, &Builder::new(), Config::default());
    let shared = driver.shared();
    let info = ConnInfo::new(shared.clone());
    peer.defer_control(true);
    let exec = TestExec::default();
    run(&exec, async {
        let _drv = spawn(&exec, driver);
        // A request whose head is discovered and whose body nobody reads.
        let s = peer.open_bidi().await.unwrap();
        let req = [
            (":method", "POST"),
            (":scheme", "https"),
            (":authority", "a"),
            (":path", "/"),
        ];
        peer.send_headers(s, &req, false).unwrap();
        peer.send_body(s, &[7; 100_000], false);
        let head = |sh: &Shared| sh.with(|i| i.streams.get(&s).is_some_and(|st| st.head.is_some()));
        peer.run_until(|_| head(&shared)).await;
        assert!(info.peer_settings().is_none());
        // The control stream arrives after the request and still gets read.
        peer.bind_control_now();
        peer.run_until(|_| info.peer_settings().is_some()).await;
    });
}

/// Counts wakes.
struct Count(AtomicUsize);
impl ArcWake for Count {
    fn wake_by_ref(a: &Arc<Self>) {
        a.0.fetch_add(1, Ordering::SeqCst);
    }
}

#[test]
fn driver_yields_on_budget() {
    let mut b = Builder::new();
    b.work_budget(4);
    let (_net, mut driver, mut peer) = setup(Role::Server, &b, Config::default());
    let info = ConnInfo::new(driver.shared());
    let noop = noop_waker();
    let mut ncx = Context::from_waker(&noop);
    for _ in 0..1000 {
        if info.peer_settings().is_some() && peer_has_settings(&peer) {
            break;
        }
        let _ = peer.poll_step(&mut ncx);
        let _ = Pin::new(&mut driver).poll(&mut ncx);
    }
    assert!(info.peer_settings().is_some());
    // 100 reserved frames on the peer's control stream, each its own transport chunk.
    for _ in 0..100 {
        peer.send_raw(StreamId(2), &[0x21, 0x00]);
    }
    while peer.poll_step(&mut ncx).is_ready() {}
    let (mut polls, mut self_wakes) = (0, 0);
    loop {
        let count = Arc::new(Count(AtomicUsize::new(0)));
        let w = waker(count.clone());
        assert!(
            Pin::new(&mut driver)
                .poll(&mut Context::from_waker(&w))
                .is_pending()
        );
        polls += 1;
        assert!(polls < 1000, "never quiesced");
        if count.0.load(Ordering::SeqCst) == 0 {
            break;
        }
        self_wakes += 1;
    }
    // At most 4 reads per pass: 100 chunks need at least 25 passes that wake themselves.
    assert!(self_wakes >= 25, "self-wakes: {self_wakes}");
}

#[test]
fn driver_drop_closes_no_error() {
    let (net, driver, _peer) = setup(Role::Client, &Builder::new(), Config::default());
    let info = ConnInfo::new(driver.shared());
    let exec = TestExec::default();
    run(&exec, async {
        let mut w = pin!(info.settings());
        assert!(poll_once(&mut w).await.is_pending());
        drop(driver);
        assert_eq!(w.await, None);
    });
    assert_eq!(net.closed_with(Side::Client), Some(0x100));
}

fn kind(r: Result<(), Error>) -> ErrorKind {
    r.expect_err("driver must fail").kind().clone()
}

#[test]
fn connection_error_reaches_every_handle() {
    let (net, driver, mut peer) = setup(Role::Server, &Builder::new(), Config::default());
    peer.defer_control(true); // no SETTINGS: the ConnInfo waiters stay pending
    let info = ConnInfo::new(driver.shared());
    let exec = TestExec::default();
    let waiters: Vec<Out<Option<PeerSettings>>> = (0..3)
        .map(|_| {
            let i = info.clone();
            spawn(&exec, async move { i.settings().await })
        })
        .collect();
    let drv = spawn(&exec, driver);
    run(&exec, async {
        let s = peer.open_bidi().await.unwrap();
        // A HEADERS frame header declaring 2^20 bytes.
        peer.send_raw(s, &[0x01, 0x80, 0x10, 0x00, 0x00]);
        peer.run_until(|_| done(&drv) && waiters.iter().all(done))
            .await;
    });
    match kind(take(&drv)) {
        ErrorKind::Closed { code, by_peer } => {
            assert_eq!(code, H3Code::EXCESSIVE_LOAD);
            assert!(!by_peer);
        }
        k => panic!("unexpected {k:?}"),
    }
    for w in &waiters {
        assert_eq!(take(w), None);
    }
    assert_eq!(net.closed_with(Side::Server), Some(0x107));
}

#[test]
fn transport_failure_keeps_cause() {
    let (net, driver, mut peer) = setup(Role::Server, &Builder::new(), Config::default());
    peer.defer_control(true);
    let info = ConnInfo::new(driver.shared());
    let exec = TestExec::default();
    let waiter = {
        let i = info.clone();
        spawn(&exec, async move { i.settings().await })
    };
    let drv = spawn(&exec, driver);
    run(&exec, async {
        peer.run_until(|p| !p.trace().is_empty()).await;
        net.kill_transport(Side::Server, Some(0x10c));
        poll_fn(|_| {
            if done(&drv) && done(&waiter) {
                Poll::Ready(())
            } else {
                Poll::Pending
            }
        })
        .await;
    });
    match kind(take(&drv)) {
        ErrorKind::Transport(e) => assert_eq!(e.peer_app_code, Some(0x10c)),
        k => panic!("unexpected {k:?}"),
    }
    assert_eq!(take(&waiter), None);
}

#[test]
#[cfg(debug_assertions)]
#[should_panic(expected = "user code polled under lock")]
fn lock_rule_debug_assertion() {
    let shared = Shared::new(h3wire::Connection::new(Role::Client, Config::default()));
    shared.with(|_| assert_unlocked());
}

#[test]
fn core_peer_open_waits_for_credit() {
    let (net, c, _s) = MockNet::pair();
    net.max_bidi_streams(Side::Client, 1);
    let mut peer = CorePeer::new(Role::Client, Config::default(), c);
    let exec = TestExec::default();
    run(&exec, async {
        let a = peer.open_bidi().await.unwrap();
        {
            let mut second = pin!(peer.open_bidi());
            assert!(poll_once(&mut second).await.is_pending());
        }
        // Close both directions of the first stream: the credit comes back.
        peer.reset(a, H3Code::REQUEST_CANCELLED);
        peer.stop_sending(a, H3Code::REQUEST_CANCELLED);
        assert_eq!(peer.open_bidi().await.unwrap(), StreamId(4));
    });
}

#[test]
fn once_slot_single_consumption() {
    let a = OnceSlot::new(7u32);
    let b = a.clone();
    assert_eq!(b.take(), Some(7));
    assert_eq!(a.take(), None);
}

#[test]
fn error_source_not_repeated_in_display() {
    use crate::quic::TransportError;
    use std::error::Error as _;
    let t: Error = ErrorKind::Transport(Arc::new(TransportError {
        peer_app_code: Some(0x10c),
        peer_transport_code: None,
        source: "link down".into(),
    }))
    .into();
    assert_eq!(t.to_string(), "transport error (peer closed with 0x10c)");
    let cause = t.source().expect("the TransportError");
    assert_eq!(cause.source().expect("its cause").to_string(), "link down");
    let b: Error = ErrorKind::Body(Arc::new("bad chunk".into())).into();
    assert_eq!(b.to_string(), "body error");
    assert_eq!(
        b.source().expect("the body's error").to_string(),
        "bad chunk"
    );
    assert!(Error::from(ErrorKind::NotUpgraded).source().is_none());
}

/// A peer's transport-level close: clean with `NO_ERROR`, an error otherwise.
#[test]
fn server_peer_transport_close() {
    for (code, clean) in [(0, true), (0xa, false)] {
        let (net, driver, mut peer) = setup(Role::Server, &Builder::new(), Config::default());
        let exec = TestExec::default();
        let drv = spawn(&exec, driver);
        run(&exec, async {
            peer.run_until(|p| !p.trace().is_empty()).await;
            net.close_transport(Side::Server, code);
            poll_fn(|_| {
                if done(&drv) {
                    Poll::Ready(())
                } else {
                    Poll::Pending
                }
            })
            .await;
        });
        match take(&drv) {
            Ok(()) => assert!(clean, "{code:#x}"),
            Err(e) => assert!(
                !clean
                    && matches!(e.kind(), ErrorKind::Transport(t) if t.peer_transport_code == Some(code)),
                "{e:?}"
            ),
        }
    }
}
