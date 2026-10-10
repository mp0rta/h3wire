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
use std::sync::{Arc, Mutex};
use std::task::{Poll, Waker};

#[derive(Default)]
struct Inner {
    // Tasks spawned but not yet moved into `set`; lets a task spawn from inside a poll.
    incoming: Mutex<Vec<BoxTask>>,
    set: Mutex<FuturesUnordered<BoxTask>>,
    waker: Mutex<Option<Waker>>,
}

/// Runs spawned tasks inside [`run`]. A panicking task is dropped, as tokio does.
#[derive(Clone, Default)]
pub struct TestExec(Arc<Inner>);

impl Executor<BoxTask> for TestExec {
    fn execute(&self, fut: BoxTask) {
        let task = AssertUnwindSafe(fut).catch_unwind().map(|_| ());
        self.0.incoming.lock().unwrap().push(Box::pin(task));
        if let Some(w) = self.0.waker.lock().unwrap().take() {
            w.wake();
        }
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
