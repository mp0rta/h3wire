// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 mp0rta
//! Executor abstraction. The application supplies the executor; this crate selects no
//! runtime.

use std::future::Future;
use std::pin::Pin;

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
