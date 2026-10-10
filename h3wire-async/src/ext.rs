// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 mp0rta
//! Request/response extensions.

use bytes::Bytes;

/// The Extended CONNECT `:protocol` value (RFC 9220); put it in a request's extensions.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Protocol(Bytes);

impl Protocol {
    /// From a static string.
    pub fn from_static(s: &'static str) -> Self {
        Self(Bytes::from_static(s.as_bytes()))
    }

    /// From arbitrary bytes; no validation.
    pub fn new(b: Bytes) -> Self {
        Self(b)
    }

    /// The raw value.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}
