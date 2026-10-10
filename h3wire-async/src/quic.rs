// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 mp0rta
//! The QUIC abstraction: three poll-based I/O traits and their error types.
//!
//! These traits do I/O only and contain no HTTP/3 logic.

use bytes::Bytes;
use h3wire::StreamId;
use std::fmt;
use std::task::{Context, Poll};

/// What one `poll_write_chunks` call accepted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Written {
    /// Total bytes accepted across all chunks.
    pub bytes: usize,
    /// Number of leading chunks that were written in full.
    pub chunks: usize,
}

/// A failure of the QUIC connection itself.
#[derive(Debug)]
pub struct TransportError {
    /// The application error code the peer closed with, if it did.
    pub peer_app_code: Option<u64>,
    /// The underlying transport error.
    pub source: Box<dyn std::error::Error + Send + Sync>,
}

impl fmt::Display for TransportError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "transport error: {}", self.source)
    }
}

impl std::error::Error for TransportError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&*self.source)
    }
}

/// Why a read failed.
#[derive(Debug)]
#[non_exhaustive]
pub enum ReadError {
    /// The peer reset the stream with this code.
    Reset(u64),
    /// The connection failed.
    Transport(TransportError),
    /// The stream was closed locally (e.g. after `stop`).
    Closed,
}

/// Why a write failed.
#[derive(Debug)]
#[non_exhaustive]
pub enum WriteError {
    /// The peer sent STOP_SENDING with this code.
    Stopped(u64),
    /// The connection failed.
    Transport(TransportError),
    /// The stream was finished or reset locally.
    Closed,
}

/// Why a datagram could not be sent.
#[derive(Debug)]
#[non_exhaustive]
pub enum SendDatagramError {
    /// The datagram exceeds the current limit.
    TooLarge,
    /// Datagrams are not available on this connection.
    Unsupported,
    /// The connection failed.
    Transport(TransportError),
}

/// A QUIC connection.
// The poll signatures are spelled out as in the design (spec section 2).
#[allow(clippy::type_complexity)]
pub trait Connection: Send + 'static {
    /// The send half of a stream.
    type Send: SendStream;
    /// The receive half of a stream.
    type Recv: RecvStream;

    /// Accept a peer-initiated bidirectional stream.
    fn poll_accept_bidi(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(Self::Send, Self::Recv), TransportError>>;
    /// Accept a peer-initiated unidirectional stream.
    fn poll_accept_uni(&mut self, cx: &mut Context<'_>)
    -> Poll<Result<Self::Recv, TransportError>>;
    /// Open a bidirectional stream; pending while the peer's stream credit is exhausted.
    fn poll_open_bidi(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(Self::Send, Self::Recv), TransportError>>;
    /// Open a unidirectional stream.
    fn poll_open_uni(&mut self, cx: &mut Context<'_>) -> Poll<Result<Self::Send, TransportError>>;
    /// Receive the next QUIC DATAGRAM frame payload.
    fn poll_recv_datagram(&mut self, cx: &mut Context<'_>) -> Poll<Result<Bytes, TransportError>>;
    /// Queue a datagram (drop-oldest). `Ok` means accepted locally, not delivered; it can
    /// return `TooLarge` even after a size query because the limit can shrink.
    fn send_datagram(&mut self, data: Bytes) -> Result<(), SendDatagramError>;
    /// The current limit on a DATAGRAM frame payload (including the QSID overhead), or
    /// `None` when datagrams are unavailable.
    ///
    /// A multipath backend must report a limit valid on every path it may send on, i.e.
    /// the minimum over the eligible paths.
    fn max_datagram_size(&self) -> Option<usize>;
    /// Close the connection with an application error code.
    fn close(&mut self, code: u64);
}

/// The send half of a QUIC stream.
pub trait SendStream: Send + 'static {
    /// The stream id.
    fn id(&self) -> StreamId;
    /// Write chunks, following quinn's semantics: the first `Written::chunks` entries are
    /// fully written, and the partially written chunk is advanced in place. Callers must
    /// not advance the buffers again. A pending operation is cancellation-safe.
    ///
    /// When `bufs` holds a non-empty chunk, `Ready(Ok(_))` means at least one byte was
    /// accepted; with no room, return `Pending` and wake `cx` later. (The driver treats a
    /// zero-byte `Ready` as blocked and waits for a wake.)
    fn poll_write_chunks(
        &mut self,
        cx: &mut Context<'_>,
        bufs: &mut [Bytes],
    ) -> Poll<Result<Written, WriteError>>;
    /// Send FIN.
    fn finish(&mut self);
    /// Reset the stream with an application error code.
    fn reset(&mut self, code: u64);
    /// `Some(code)`: the peer sent STOP_SENDING. `None`: the stream completed and was
    /// acknowledged. Polled even when no write is pending.
    fn poll_stopped(&mut self, cx: &mut Context<'_>) -> Poll<Result<Option<u64>, TransportError>>;
}

/// The receive half of a QUIC stream.
pub trait RecvStream: Send + 'static {
    /// The stream id.
    fn id(&self) -> StreamId;
    /// Read the next in-order chunk of at most `max_len` bytes; `None` is EOF.
    fn poll_read_chunk(
        &mut self,
        cx: &mut Context<'_>,
        max_len: usize,
    ) -> Poll<Result<Option<Bytes>, ReadError>>;
    /// Send STOP_SENDING with an application error code.
    fn stop(&mut self, code: u64);
}
