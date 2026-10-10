// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 mp0rta
//! Runtime-neutral async HTTP/3 over the sans-I/O [`h3wire`] core.
//!
//! The QUIC transport is abstracted behind the poll-based traits in [`quic`]; the
//! application supplies an [`rt::Executor`]. The API is unstable (0.x).
#![forbid(unsafe_code)]
#![warn(missing_docs)]

#[cfg(any(test, feature = "__testing"))]
#[doc(hidden)]
#[path = "testing/mod.rs"]
pub mod __testing;
pub mod builder;
pub mod error;
pub mod quic;
pub mod rt;
#[cfg(test)]
mod tests;

pub use builder::Builder;
pub use error::{BoxError, DatagramError, Error, ErrorKind};
/// The sans-I/O core; its types appear in this crate's API.
pub use h3wire as core;
