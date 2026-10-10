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
pub mod body;
pub mod builder;
pub mod client;
// Driver, shared state and OnceSlot are wired up by the client and server (Tasks 6–9).
#[allow(dead_code)]
mod driver;
pub mod error;
pub mod ext;
// Consumed by the client and server (later tasks).
#[allow(dead_code)]
mod http_map;
pub mod quic;
pub mod rt;
pub mod server;
#[allow(dead_code)]
mod slot;
#[allow(dead_code)]
mod state;
#[cfg(test)]
mod tests;
pub mod upgrade;

pub use builder::Builder;
pub use client::{ClientConnection, SendRequest};
pub use error::{BoxError, DatagramError, Error, ErrorKind};
/// The sans-I/O core; its types appear in this crate's API.
pub use h3wire as core;
pub use server::ServerConnection;
