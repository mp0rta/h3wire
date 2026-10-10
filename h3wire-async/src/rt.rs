// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 mp0rta
//! Executor abstraction. The application supplies the executor; this crate selects no
//! runtime.

use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex, PoisonError};
use std::task::{Context, Poll, Waker};

/// A boxed task, as handed to an [`Executor`].
pub type BoxTask = Pin<Box<dyn Future<Output = ()> + Send + 'static>>;

/// Spawns futures; the same shape as hyper's executor trait.
pub trait Executor<F>: Clone + Send + Sync + 'static {
    /// Run `fut` to completion in the background.
    fn execute(&self, fut: F);
}

/// An [`Executor`] backed by `tokio::spawn`; must be used inside a tokio runtime.
#[cfg(feature = "tokio")]
#[derive(Clone, Default)]
pub struct TokioExecutor;

#[cfg(feature = "tokio")]
impl Executor<BoxTask> for TokioExecutor {
    fn execute(&self, fut: BoxTask) {
        tokio::spawn(fut);
    }
}

/// Which directions of a stream an executor task owns (spec §4.6).
#[allow(dead_code)] // the client and server spawn tasks (Tasks 6–7)
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Owns {
    /// Server per-request task: cancelled once both directions are terminal.
    Both,
    /// Client request-body pipe: cancelled once the send side is terminal.
    Send,
}

/// Fired by the shared state (under its lock) when a task's directions are terminal or
/// the connection closes. Its own small lock is never held while taking the shared one.
#[derive(Clone, Debug, Default)]
pub(crate) struct CancelToken(Arc<Mutex<(bool, Option<Waker>)>>);

impl CancelToken {
    /// Mark fired; returns the task's waker, to be woken once the shared lock is released.
    pub(crate) fn fire(&self) -> Option<Waker> {
        let mut g = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        g.0 = true;
        g.1.take()
    }

    /// Whether it fired; registers `cx`'s waker if not.
    fn poll_fired(&self, cx: &Context<'_>) -> bool {
        let mut g = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        if !g.0 {
            g.1 = Some(cx.waker().clone());
        }
        g.0
    }
}

/// Wraps every executor task: once `token` fires it returns `Ready(())` and drops
/// `inner` (as h2 does), so a user future that never touches a handle again still ends.
pub(crate) struct Cancelable<F> {
    inner: Option<F>,
    token: CancelToken,
}

impl<F> Cancelable<F> {
    pub(crate) fn new(inner: F, token: CancelToken) -> Self {
        Cancelable {
            inner: Some(inner),
            token,
        }
    }
}

impl<F: Future<Output = ()> + Unpin> Future for Cancelable<F> {
    type Output = ();

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
        if self.token.poll_fired(cx) {
            self.inner = None;
            return Poll::Ready(());
        }
        let Some(f) = self.inner.as_mut() else {
            return Poll::Ready(());
        };
        crate::state::assert_unlocked();
        let r = Pin::new(f).poll(cx);
        if r.is_ready() {
            self.inner = None;
        }
        r
    }
}
