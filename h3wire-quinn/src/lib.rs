// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 mp0rta
//! [quinn] 0.11 transport for [`h3wire_async`] (spec §4.8).
//!
//! [`QuinnConnection`] implements the [`quic`] traits over a `quinn::Connection`;
//! [`server`] and [`client`] wrap [`Builder`]. This crate selects no runtime, TLS
//! provider or certificate verifier: the application configures its own quinn.
//!
//! Stream halves wrap quinn's. The driver always ends a half explicitly (finish, reset
//! or stop) before dropping it, so quinn's implicit drop behaviour never adds a signal:
//! - a dropped `quinn::SendStream` finishes the stream, which quinn ignores once it was
//!   finished or reset, and does nothing once the connection has failed;
//! - a dropped `quinn::RecvStream` sends `STOP_SENDING(0)` only if it was neither read
//!   to the end, reset by the peer, nor stopped.
//!
//! The API is unstable (0.x).
#![forbid(unsafe_code)]
#![warn(missing_docs)]

use bytes::{Buf, Bytes};
use h3wire_async::body::RecvBody;
use h3wire_async::core::StreamId;
use h3wire_async::quic::{self, ReadError, SendDatagramError, TransportError, WriteError, Written};
use h3wire_async::rt::{BoxTask, Executor};
use h3wire_async::{BoxError, Builder, ClientConnection, Error, SendRequest, ServerConnection};
use http::{Request, Response};
use http_body::Body;
use quinn::{ConnectionError, VarInt};
use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};
use tower_service::Service;

type Pending<T> = Option<Pin<Box<dyn Future<Output = Result<T, ConnectionError>> + Send>>>;

/// A quinn connection as an h3wire-async [`quic::Connection`].
pub struct QuinnConnection {
    conn: quinn::Connection,
    accept_bi: Pending<(quinn::SendStream, quinn::RecvStream)>,
    accept_uni: Pending<quinn::RecvStream>,
    open_bi: Pending<(quinn::SendStream, quinn::RecvStream)>,
    open_uni: Pending<quinn::SendStream>,
    datagram: Pending<Bytes>,
}

impl std::fmt::Debug for QuinnConnection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("QuinnConnection")
            .field("conn", &self.conn)
            .finish_non_exhaustive()
    }
}

impl QuinnConnection {
    /// Wrap an established quinn connection.
    pub fn new(conn: quinn::Connection) -> Self {
        QuinnConnection {
            conn,
            accept_bi: None,
            accept_uni: None,
            open_bi: None,
            open_uni: None,
            datagram: None,
        }
    }
}

/// Poll the operation in `slot`, starting it with `start` if none is in flight. The
/// future is kept across `Pending`, so nothing is lost when the caller stops polling.
fn poll_op<T, F>(
    slot: &mut Pending<T>,
    conn: &quinn::Connection,
    cx: &mut Context<'_>,
    start: impl FnOnce(quinn::Connection) -> F,
) -> Poll<Result<T, TransportError>>
where
    F: Future<Output = Result<T, ConnectionError>> + Send + 'static,
{
    let f = slot.get_or_insert_with(|| Box::pin(start(conn.clone())));
    let r = f.as_mut().poll(cx);
    if r.is_ready() {
        *slot = None;
    }
    r.map_err(transport)
}

/// A connection failure; an application close by the peer keeps its code.
fn transport(e: ConnectionError) -> TransportError {
    let peer_app_code = match &e {
        ConnectionError::ApplicationClosed(c) => Some(c.error_code.into_inner()),
        _ => None,
    };
    TransportError {
        peer_app_code,
        source: Box::new(e),
    }
}

/// An application error code as a QUIC varint (codes the core emits always fit).
fn varint(code: u64) -> VarInt {
    VarInt::from_u64(code).unwrap_or(VarInt::MAX)
}

fn stream_id(id: quinn::StreamId) -> StreamId {
    StreamId(id.into())
}

fn bidi((s, r): (quinn::SendStream, quinn::RecvStream)) -> (QuinnSend, QuinnRecv) {
    (QuinnSend::new(s), QuinnRecv(r))
}

impl quic::Connection for QuinnConnection {
    type Send = QuinnSend;
    type Recv = QuinnRecv;

    fn poll_accept_bidi(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(QuinnSend, QuinnRecv), TransportError>> {
        poll_op(&mut self.accept_bi, &self.conn, cx, |c| async move {
            c.accept_bi().await
        })
        .map_ok(bidi)
    }

    fn poll_accept_uni(&mut self, cx: &mut Context<'_>) -> Poll<Result<QuinnRecv, TransportError>> {
        poll_op(&mut self.accept_uni, &self.conn, cx, |c| async move {
            c.accept_uni().await
        })
        .map_ok(QuinnRecv)
    }

    fn poll_open_bidi(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(QuinnSend, QuinnRecv), TransportError>> {
        poll_op(&mut self.open_bi, &self.conn, cx, |c| async move {
            c.open_bi().await
        })
        .map_ok(bidi)
    }

    fn poll_open_uni(&mut self, cx: &mut Context<'_>) -> Poll<Result<QuinnSend, TransportError>> {
        poll_op(&mut self.open_uni, &self.conn, cx, |c| async move {
            c.open_uni().await
        })
        .map_ok(QuinnSend::new)
    }

    fn poll_recv_datagram(&mut self, cx: &mut Context<'_>) -> Poll<Result<Bytes, TransportError>> {
        poll_op(&mut self.datagram, &self.conn, cx, |c| async move {
            c.read_datagram().await
        })
    }

    fn send_datagram(&mut self, data: Bytes) -> Result<(), SendDatagramError> {
        use quinn::SendDatagramError as E;
        self.conn.send_datagram(data).map_err(|e| match e {
            E::TooLarge => SendDatagramError::TooLarge,
            E::UnsupportedByPeer | E::Disabled => SendDatagramError::Unsupported,
            E::ConnectionLost(e) => SendDatagramError::Transport(transport(e)),
        })
    }

    fn max_datagram_size(&self) -> Option<usize> {
        self.conn.max_datagram_size()
    }

    fn close(&mut self, code: u64) {
        self.conn.close(varint(code), b"");
    }
}

type Stopped = Pin<Box<dyn Future<Output = Result<Option<VarInt>, quinn::StoppedError>> + Send>>;

/// The send half of a quinn stream.
pub struct QuinnSend {
    inner: quinn::SendStream,
    /// `stopped()`, kept while it is pending.
    stopped: Option<Stopped>,
}

impl std::fmt::Debug for QuinnSend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("QuinnSend").field(&self.inner.id()).finish()
    }
}

impl QuinnSend {
    fn new(inner: quinn::SendStream) -> Self {
        QuinnSend {
            inner,
            stopped: None,
        }
    }
}

impl quic::SendStream for QuinnSend {
    fn id(&self) -> StreamId {
        stream_id(self.inner.id())
    }

    fn poll_write_chunks(
        &mut self,
        cx: &mut Context<'_>,
        bufs: &mut [Bytes],
    ) -> Poll<Result<Written, WriteError>> {
        use quinn::WriteError as E;
        // quinn advances `bufs` itself; a fresh future per poll is cancel-safe (quinn
        // writes nothing unless it returns `Ready`).
        let f = std::pin::pin!(self.inner.write_chunks(bufs));
        f.poll(cx).map(|r| match r {
            Ok(w) => Ok(Written {
                bytes: w.bytes,
                chunks: w.chunks,
            }),
            Err(E::Stopped(code)) => Err(WriteError::Stopped(code.into_inner())),
            Err(E::ConnectionLost(e)) => Err(WriteError::Transport(transport(e))),
            Err(E::ClosedStream | E::ZeroRttRejected) => Err(WriteError::Closed),
        })
    }

    fn finish(&mut self) {
        // Err: already finished or reset.
        let _ = self.inner.finish();
    }

    fn reset(&mut self, code: u64) {
        // Err: already finished or reset.
        let _ = self.inner.reset(varint(code));
    }

    fn poll_stopped(&mut self, cx: &mut Context<'_>) -> Poll<Result<Option<u64>, TransportError>> {
        let inner = &self.inner;
        let f = self
            .stopped
            .get_or_insert_with(|| Box::pin(inner.stopped()));
        let r = f.as_mut().poll(cx);
        if r.is_ready() {
            self.stopped = None;
        }
        r.map(|r| match r {
            Ok(code) => Ok(code.map(VarInt::into_inner)),
            Err(quinn::StoppedError::ConnectionLost(e)) => Err(transport(e)),
            // A rejected 0-RTT stream never reaches the peer; h3wire never opens one.
            Err(e @ quinn::StoppedError::ZeroRttRejected) => Err(TransportError {
                peer_app_code: None,
                source: Box::new(e),
            }),
        })
    }
}

/// The receive half of a quinn stream.
#[derive(Debug)]
pub struct QuinnRecv(quinn::RecvStream);

impl quic::RecvStream for QuinnRecv {
    fn id(&self) -> StreamId {
        stream_id(self.0.id())
    }

    fn poll_read_chunk(
        &mut self,
        cx: &mut Context<'_>,
        max_len: usize,
    ) -> Poll<Result<Option<Bytes>, ReadError>> {
        use quinn::ReadError as E;
        // Cancel-safe in quinn: a fresh future per poll loses nothing.
        let f = std::pin::pin!(self.0.read_chunk(max_len, true));
        f.poll(cx).map(|r| match r {
            Ok(c) => Ok(c.map(|c| c.bytes)),
            Err(E::Reset(code)) => Err(ReadError::Reset(code.into_inner())),
            Err(E::ConnectionLost(e)) => Err(ReadError::Transport(transport(e))),
            Err(E::ClosedStream | E::IllegalOrderedRead | E::ZeroRttRejected) => {
                Err(ReadError::Closed)
            }
        })
    }

    fn stop(&mut self, code: u64) {
        // Err: already stopped. Marks the stream as read, so its drop adds no STOP_SENDING.
        let _ = self.0.stop(varint(code));
    }
}

/// Serve HTTP/3 on `conn`: [`Builder::serve_connection`] over a [`QuinnConnection`].
pub fn server<S, B, E>(
    conn: quinn::Connection,
    builder: &Builder,
    service: S,
    exec: E,
) -> ServerConnection<QuinnConnection, S, E>
where
    S: Service<Request<RecvBody>, Response = Response<B>> + Clone + Send + 'static,
    S::Future: Send + 'static,
    S::Error: Into<BoxError>,
    B: Body + Send + 'static,
    B::Data: Buf + Send,
    B::Error: Into<BoxError>,
    E: Executor<BoxTask>,
{
    builder.serve_connection(QuinnConnection::new(conn), service, exec)
}

/// Start an HTTP/3 client on `conn`: [`Builder::handshake`] over a [`QuinnConnection`].
/// Spawn the returned [`ClientConnection`] on `exec`.
pub async fn client<B, E>(
    conn: quinn::Connection,
    builder: &Builder,
    exec: E,
) -> Result<(SendRequest<B>, ClientConnection<QuinnConnection>), Error>
where
    B: Body + Send + 'static,
    B::Data: Buf + Send,
    B::Error: Into<BoxError>,
    E: Executor<BoxTask>,
{
    builder.handshake(QuinnConnection::new(conn), exec).await
}
