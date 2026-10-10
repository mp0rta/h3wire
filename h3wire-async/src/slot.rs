// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 mp0rta
//! `OnceSlot<T>`: a `Clone + Send + Sync` cell whose value is taken at most once, as
//! extension values must be `Clone`. A value nobody took is dropped with the last clone.

use std::sync::{Arc, Mutex, PoisonError};

pub(crate) struct OnceSlot<T>(Arc<Mutex<Option<T>>>);

impl<T> Clone for OnceSlot<T> {
    fn clone(&self) -> Self {
        OnceSlot(self.0.clone())
    }
}

impl<T> OnceSlot<T> {
    pub(crate) fn new(value: T) -> Self {
        OnceSlot(Arc::new(Mutex::new(Some(value))))
    }

    /// The value, for the first caller only.
    pub(crate) fn take(&self) -> Option<T> {
        self.0.lock().unwrap_or_else(PoisonError::into_inner).take()
    }
}
