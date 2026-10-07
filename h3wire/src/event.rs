// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 mp0rta
//! What the connection reports to the application (`Event`), asks of the transport
//! (`Action`), and returns from `recv` and `parse_datagram`.

use crate::error::H3Code;
use crate::headers::HeaderBlockId;
pub use crate::headers::HeadersKind;
use crate::stream::{StreamId, UniKind};
use std::ops::Range;

/// What happened, for the application; taken with
/// [`Connection::poll_event`](crate::Connection::poll_event).
///
/// While the connection is open, every request stream gets exactly one terminal event for
/// its receive side, [`Event::Finished`] or [`Event::StreamAborted`]; nothing follows it
/// for that stream except possibly [`Event::SendStopped`]. [`Event::Closed`] is emitted
/// once and stands in for the terminal event of every stream still open.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Event {
    /// A validated header block arrived. Read it with
    /// [`Connection::headers`](crate::Connection::headers), then
    /// [`release`](crate::Connection::release) it: the stream's next HEADERS frame is not
    /// decoded until then ([`Recv::Paused`]).
    Headers {
        /// The request stream.
        stream: StreamId,
        /// The decoded block; it outlives the stream until released.
        block: HeaderBlockId,
        /// Which part of the message the block is.
        kind: HeadersKind,
    },
    /// The receive side ended with a complete message: a clean FIN at a frame boundary
    /// after the request (server) or final response (client) HEADERS, with a matching
    /// Content-Length where one applies. Terminal.
    Finished(StreamId),
    /// The stream ended abnormally: local `abort`, a peer RESET_STREAM, a stream error
    /// (e.g. a malformed message), or a GOAWAY cutoff. Terminal. Any wire effect is queued
    /// as actions.
    ///
    /// A server may get this for a request stream it never saw `Headers` on: rejected at a
    /// GOAWAY cutoff, malformed request, or reset by the peer before any byte arrived.
    StreamAborted {
        /// The request stream.
        stream: StreamId,
        /// The reason, as the application should read it. It can differ from the code on
        /// the wire: a client cancelled at a peer GOAWAY sees `REQUEST_REJECTED` here and
        /// sends `REQUEST_CANCELLED`.
        code: H3Code,
        /// Who ended the stream; see also [`Event::retryable`].
        source: AbortSource,
    },
    /// The peer sent STOP_SENDING: our send side is reset (an `Action::ResetStream` is
    /// queued) and receiving goes on. Not terminal.
    SendStopped {
        /// The request stream.
        stream: StreamId,
        /// The peer's code.
        code: H3Code,
    },
    /// The peer's SETTINGS arrived; see
    /// [`Connection::peer_settings`](crate::Connection::peer_settings).
    PeerSettings,
    /// The peer sent GOAWAY. Client: `id` is the first request stream the server will not
    /// process; requests at or above it with no response yet are aborted (retryable) and
    /// no new request may start. Server: `id` is a push ID and has no effect on requests.
    GoAway {
        /// The GOAWAY identifier.
        id: u64,
    },
    /// The peer opened a uni stream of a type registered with
    /// [`Config::register_uni_stream`](crate::Config::register_uni_stream); its bytes
    /// come back from `recv` as [`Recv::Raw`].
    UniStream {
        /// The peer uni stream.
        stream: StreamId,
        /// Its stream type.
        ty: u64,
    },
    /// The connection is closed; the last event. Stands in for the terminal event of
    /// every stream still open.
    Closed {
        /// The connection error code; `NO_ERROR` after
        /// [`Connection::transport_closed`](crate::Connection::transport_closed).
        code: H3Code,
    },
}

impl Event {
    /// Whether the aborted request may be retried on a new connection.
    /// Judged from provenance (spec section 4): at/above a GOAWAY cutoff, or the peer
    /// sent `REQUEST_REJECTED`.
    pub fn retryable(&self) -> bool {
        matches!(
            self,
            Event::StreamAborted {
                source: AbortSource::GoAway,
                ..
            } | Event::StreamAborted {
                source: AbortSource::Peer,
                code: H3Code::REQUEST_REJECTED,
                ..
            }
        )
    }
}

/// Who ended a stream reported by [`Event::StreamAborted`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum AbortSource {
    /// This endpoint: `abort`, a stream error it detected, or (server) a request rejected
    /// at its own GOAWAY cutoff.
    Local,
    /// The peer reset the stream.
    Peer,
    /// Client: the request is at or above the server's GOAWAY id and was not processed.
    GoAway,
}

/// A transport operation the caller executes on the QUIC connection; taken with
/// [`Connection::poll_action`](crate::Connection::poll_action), in order.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Action {
    /// Open a local unidirectional stream and bind it with
    /// [`Connection::bind_uni`](crate::Connection::bind_uni). The three are emitted by
    /// [`Connection::new`](crate::Connection::new).
    OpenUni(UniKind),
    /// Reset our send side of `stream` (QUIC RESET_STREAM).
    ResetStream {
        /// The stream.
        stream: StreamId,
        /// The application error code.
        code: H3Code,
    },
    /// Ask the peer to stop sending on `stream` (QUIC STOP_SENDING).
    StopSending {
        /// The stream.
        stream: StreamId,
        /// The application error code.
        code: H3Code,
    },
    /// Everything the stream had to send is written: send FIN. The only way a stream is
    /// finished; the caller never sets FIN on its own.
    FinishStream(StreamId),
    /// Close the QUIC connection with this application error code: the sole trigger for
    /// the wire effects of a connection error.
    CloseConnection {
        /// The HTTP/3 error code.
        code: H3Code,
        /// A static description; never contains peer data.
        reason: &'static str,
    },
}

/// Result of [`Connection::recv`](crate::Connection::recv). `consumed` counts bytes from
/// the start of the caller's buffer, and every `range` indexes that buffer (within
/// `0..consumed`); payload is never copied.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Recv {
    /// Bytes the core handled itself: frame headers, HEADERS, control and QPACK streams,
    /// skipped frames, discarded bytes.
    Consumed(usize),
    /// DATA payload (the part in this chunk): request or response body, or tunnel bytes.
    Body {
        /// Bytes consumed.
        consumed: usize,
        /// The payload.
        range: Range<usize>,
    },
    /// A piece of an extension frame registered with
    /// [`Config::register_frame`](crate::Config::register_frame).
    Frame {
        /// Bytes consumed.
        consumed: usize,
        /// The frame type.
        ty: u64,
        /// This piece of the payload.
        range: Range<usize>,
        /// Where the piece starts within the frame payload.
        offset: u64,
        /// The frame's payload length.
        frame_len: u64,
    },
    /// Bytes of a peer uni stream of a registered type (after [`Event::UniStream`]).
    Raw {
        /// Bytes consumed.
        consumed: usize,
        /// The stream bytes.
        range: Range<usize>,
    },
    /// Nothing consumed: the stream's next HEADERS waits until its previous block is
    /// [`release`](crate::Connection::release)d. Stop feeding this stream until then, then
    /// feed the same bytes again.
    Paused,
}

/// DATA frame prefix (type 0x00 + length varint) to write before the payload.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DataFrame {
    pub(crate) bytes: [u8; 9],
    pub(crate) len: u8,
}

impl DataFrame {
    /// The bytes to write before the payload (empty for a FIN-only `send_data`).
    pub fn prefix(&self) -> &[u8] {
        &self.bytes[..usize::from(self.len).min(self.bytes.len())]
    }
}

/// Routing decision for a received HTTP datagram, from
/// [`Connection::parse_datagram`](crate::Connection::parse_datagram). Ranges index the
/// payload passed in (the part after the Quarter Stream ID).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Datagram {
    /// For this open request stream. Whether the request carries datagram semantics is
    /// the caller's decision; if it does not, abort the stream with `H3_DATAGRAM_ERROR`.
    Deliver(StreamId, Range<usize>),
    /// For a request stream not seen yet (the datagram can overtake its HEADERS). The
    /// core never buffers; the caller decides whether to keep it briefly (about a round
    /// trip, RFC 9297 section 2.1) or drop it.
    NotYetOpen(StreamId, Range<usize>),
    /// Discard it: the receive side of that request is closed, or HTTP datagrams are not
    /// enabled locally.
    Drop,
}
