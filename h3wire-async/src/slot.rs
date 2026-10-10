// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 mp0rta
//! `OnceSlot<T>`: a `Clone + Send + Sync` cell whose value is taken at most once, as
//! extension values must be `Clone`.

use std::sync::{Arc, Mutex, PoisonError};

type Hook<T> = Box<dyn FnOnce(T) + Send>;

pub(crate) struct OnceSlot<T>(Arc<Mutex<SlotState<T>>>);

struct SlotState<T> {
    value: Option<T>,
    on_last_drop: Option<Hook<T>>,
}

impl<T> Clone for OnceSlot<T> {
    fn clone(&self) -> Self {
        OnceSlot(self.0.clone())
    }
}

impl<T> OnceSlot<T> {
    pub(crate) fn new(value: T) -> Self {
        OnceSlot(Arc::new(Mutex::new(SlotState {
            value: Some(value),
            on_last_drop: None,
        })))
    }

    /// The value, for the first caller only.
    pub(crate) fn take(&self) -> Option<T> {
        self.0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .value
            .take()
    }

    /// Run `f` with the value when the last clone is dropped and nobody took it. It runs
    /// on whichever thread drops that clone, so it must not take a lock that thread may
    /// hold.
    pub(crate) fn on_last_drop(&self, f: impl FnOnce(T) + Send + 'static) {
        self.0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .on_last_drop = Some(Box::new(f));
    }
}

// Runs exactly once, when the last `Arc` goes, with no race between clones.
impl<T> Drop for SlotState<T> {
    fn drop(&mut self) {
        if let (Some(v), Some(f)) = (self.value.take(), self.on_last_drop.take()) {
            f(v);
        }
    }
}
