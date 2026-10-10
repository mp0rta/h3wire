// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 mp0rta
//! Test support, exported as `__testing` (not public API).

#[cfg(test)]
pub mod exec;
pub mod mock;

pub use mock::{Ack, MockConn, MockNet, MockObs, Side};
