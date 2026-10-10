// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 mp0rta
//! The single error type of this crate.

use crate::quic::TransportError;
use h3wire::{AbortSource, H3Code, UsageError};
use std::fmt;
use std::sync::Arc;

/// A boxed, thread-safe error.
pub type BoxError = Box<dyn std::error::Error + Send + Sync>;

/// An error from this crate; inspect it with [`Error::kind`].
#[derive(Clone, Debug)]
pub struct Error {
    kind: ErrorKind,
}

/// What went wrong.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub enum ErrorKind {
    /// The connection closed with `code`; `by_peer` tells who closed it.
    Closed {
        /// The HTTP/3 error code.
        code: H3Code,
        /// Whether the peer (rather than this endpoint) closed.
        by_peer: bool,
    },
    /// The stream was aborted.
    StreamAborted {
        /// The HTTP/3 error code.
        code: H3Code,
        /// Who ended the stream.
        source: AbortSource,
        /// Whether the request is safe to retry on another connection.
        retryable: bool,
    },
    /// The peer sent STOP_SENDING on this stream.
    SendStopped {
        /// The HTTP/3 error code.
        code: H3Code,
    },
    /// A local call the core refused.
    Usage(UsageError),
    /// The QUIC connection failed; keeps the QUIC-layer provenance.
    Transport(Arc<TransportError>),
    /// A user body failed.
    Body(Arc<BoxError>),
    /// A CONNECT was answered with a non-2xx response, so there is no tunnel.
    NotUpgraded,
}

impl Error {
    /// What went wrong.
    pub fn kind(&self) -> &ErrorKind {
        &self.kind
    }

    /// The HTTP/3 error code, when there is one.
    pub fn code(&self) -> Option<H3Code> {
        match &self.kind {
            ErrorKind::Closed { code, .. }
            | ErrorKind::StreamAborted { code, .. }
            | ErrorKind::SendStopped { code } => Some(*code),
            ErrorKind::Usage(UsageError::Closed(code)) => Some(*code),
            _ => None,
        }
    }

    /// Whether the request is safe to retry on another connection (a GOAWAY cutoff or a
    /// peer `H3_REQUEST_REJECTED`).
    pub fn is_retryable(&self) -> bool {
        matches!(
            self.kind,
            ErrorKind::StreamAborted {
                retryable: true,
                ..
            }
        )
    }
}

impl From<ErrorKind> for Error {
    fn from(kind: ErrorKind) -> Self {
        Error { kind }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.kind {
            ErrorKind::Closed { code, by_peer } => {
                let who = if *by_peer { "peer" } else { "local" };
                write!(f, "connection closed by {who} ({:#x})", code.0)
            }
            ErrorKind::StreamAborted { code, source, .. } => {
                write!(f, "stream aborted ({:#x}, {source:?})", code.0)
            }
            ErrorKind::SendStopped { code } => write!(f, "peer stopped sending ({:#x})", code.0),
            ErrorKind::Usage(e) => e.fmt(f),
            ErrorKind::Transport(e) => e.fmt(f),
            ErrorKind::Body(e) => write!(f, "body error: {e}"),
            ErrorKind::NotUpgraded => f.write_str("request was not upgraded"),
        }
    }
}

impl std::error::Error for Error {}

/// Why a datagram operation failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum DatagramError {
    /// The peer's SETTINGS have not confirmed `H3_DATAGRAM` yet.
    NotNegotiated,
    /// The peer does not support datagrams.
    Unsupported,
    /// The payload exceeds the current limit.
    TooLarge,
    /// The request or connection has ended.
    Closed,
}
