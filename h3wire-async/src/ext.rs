// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 mp0rta
//! Request/response extensions.

use crate::state::Shared;
use bytes::Bytes;
use h3wire::PeerSettings;
use std::future::poll_fn;
use std::task::Poll;

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

/// Connection information; `Clone`, and usable after the connection has closed.
#[derive(Clone)]
pub struct ConnInfo {
    shared: Shared,
}

impl std::fmt::Debug for ConnInfo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ConnInfo").finish_non_exhaustive()
    }
}

impl ConnInfo {
    #[allow(dead_code)] // used by the client and server (Tasks 6–7)
    pub(crate) fn new(shared: Shared) -> Self {
        ConnInfo { shared }
    }

    /// The peer's SETTINGS, if they have arrived.
    pub fn peer_settings(&self) -> Option<PeerSettings> {
        self.shared.with(|i| i.conn.peer_settings().cloned())
    }

    /// Wait for the peer's SETTINGS; `None` if the connection closes first.
    pub async fn settings(&self) -> Option<PeerSettings> {
        poll_fn(|cx| {
            self.shared.with(|i| {
                if let Some(s) = i.conn.peer_settings() {
                    return Poll::Ready(Some(s.clone()));
                }
                if i.close.is_some() {
                    return Poll::Ready(None);
                }
                i.wait_conn(cx.waker());
                Poll::Pending
            })
        })
        .await
    }
}
