// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 mp0rta
//! A single-threaded test executor over `futures` (`cfg(test)` only).

use crate::rt::{BoxTask, Executor};
use futures::FutureExt;
use futures::StreamExt;
use futures::stream::FuturesUnordered;
use std::future::{Future, poll_fn};
use std::panic::AssertUnwindSafe;
use std::pin::pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker};

#[derive(Default)]
struct Inner {
    // Tasks spawned but not yet moved into `set`; lets a task spawn from inside a poll.
    incoming: Mutex<Vec<BoxTask>>,
    set: Mutex<FuturesUnordered<BoxTask>>,
    waker: Mutex<Option<Waker>>,
    /// Tasks that panicked.
    panics: AtomicUsize,
}

/// Runs spawned tasks inside [`run`]. A panicking task is dropped, as tokio does.
#[derive(Clone, Default)]
pub struct TestExec(Arc<Inner>);

impl Executor<BoxTask> for TestExec {
    fn execute(&self, fut: BoxTask) {
        // Weak: the task lives inside `Inner`.
        let inner = Arc::downgrade(&self.0);
        let task = AssertUnwindSafe(fut).catch_unwind().map(move |r| {
            if let (Err(_), Some(i)) = (r, inner.upgrade()) {
                i.panics.fetch_add(1, Ordering::Relaxed);
            }
        });
        self.0.incoming.lock().unwrap().push(Box::pin(task));
        if let Some(w) = self.0.waker.lock().unwrap().take() {
            w.wake();
        }
    }
}

impl TestExec {
    /// Poll every runnable task (spawned ones included) until none is ready; their
    /// wakes and new spawns go to `cx`. For tests that step the world themselves.
    pub fn tick(&self, cx: &mut Context<'_>) {
        *self.0.waker.lock().unwrap() = Some(cx.waker().clone());
        loop {
            let mut set = self.0.set.lock().unwrap();
            set.extend(self.0.incoming.lock().unwrap().drain(..));
            while let Poll::Ready(Some(())) = set.poll_next_unpin(cx) {}
            drop(set);
            if self.0.incoming.lock().unwrap().is_empty() {
                return;
            }
        }
    }

    /// Tasks spawned and not finished.
    pub fn pending(&self) -> usize {
        self.0.set.lock().unwrap().len() + self.0.incoming.lock().unwrap().len()
    }

    /// Tasks that panicked (each was dropped).
    pub fn panics(&self) -> usize {
        self.0.panics.load(Ordering::Relaxed)
    }
}

/// Drive `fut` and every task spawned on `exec` until `fut` completes.
pub fn run<F: Future>(exec: &TestExec, fut: F) -> F::Output {
    let inner = &exec.0;
    let mut fut = pin!(fut);
    futures::executor::block_on(poll_fn(|cx| {
        *inner.waker.lock().unwrap() = Some(cx.waker().clone());
        loop {
            let mut set = inner.set.lock().unwrap();
            set.extend(inner.incoming.lock().unwrap().drain(..));
            while let Poll::Ready(Some(())) = set.poll_next_unpin(cx) {}
            drop(set);
            if let Poll::Ready(v) = fut.as_mut().poll(cx) {
                return Poll::Ready(v);
            }
            if inner.incoming.lock().unwrap().is_empty() {
                return Poll::Pending;
            }
        }
    }))
}
