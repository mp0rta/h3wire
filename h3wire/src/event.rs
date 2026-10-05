//! What the connection reports to the application (`Event`), asks of the transport
//! (`Action`), and returns from `recv` and `parse_datagram`.

use crate::error::H3Code;
use crate::headers::HeaderBlockId;
pub use crate::headers::HeadersKind;
use crate::stream::{StreamId, UniKind};
use std::ops::Range;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Event {
    Headers {
        stream: StreamId,
        block: HeaderBlockId,
        kind: HeadersKind,
    },
    /// Receive side ended with a complete message.
    Finished(StreamId),
    StreamAborted {
        stream: StreamId,
        code: H3Code,
        source: AbortSource,
    },
    /// Peer STOP_SENDING; the receive side is unaffected.
    SendStopped {
        stream: StreamId,
        code: H3Code,
    },
    /// Peer SETTINGS arrived; see `Connection::peer_settings`.
    PeerSettings,
    GoAway {
        id: u64,
    },
    /// A registered uni stream type.
    UniStream {
        stream: StreamId,
        ty: u64,
    },
    /// Connection closed; the last event.
    Closed {
        code: H3Code,
    },
}

impl Event {
    /// Whether the aborted request may be retried on a new connection.
    pub fn retryable(&self) -> bool {
        false
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum AbortSource {
    Local,
    Peer,
    GoAway,
}

/// Executed by the caller / adapter on the QUIC connection.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Action {
    OpenUni(UniKind),
    ResetStream { stream: StreamId, code: H3Code },
    StopSending { stream: StreamId, code: H3Code },
    FinishStream(StreamId),
    CloseConnection { code: H3Code, reason: &'static str },
}

/// Result of `Connection::recv`; ranges index the caller's buffer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Recv {
    /// Frame headers, HEADERS, control frames.
    Consumed(usize),
    /// DATA payload (the part in this chunk).
    Body {
        consumed: usize,
        range: Range<usize>,
    },
    /// A piece of a registered extension frame.
    Frame {
        consumed: usize,
        ty: u64,
        range: Range<usize>,
        offset: u64,
        frame_len: u64,
    },
    /// Registered uni stream bytes.
    Raw {
        consumed: usize,
        range: Range<usize>,
    },
    /// Nothing consumed: the stream waits on `release` of its unreleased block.
    Paused,
}

/// DATA frame prefix (type 0x00 + length varint) to write before the payload.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DataFrame {
    pub(crate) bytes: [u8; 9],
    pub(crate) len: u8,
}

impl DataFrame {
    pub fn prefix(&self) -> &[u8] {
        &self.bytes[..usize::from(self.len).min(self.bytes.len())]
    }
}

/// Routing decision for a received HTTP datagram.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Datagram {
    Deliver(StreamId, Range<usize>),
    /// The caller decides whether to buffer briefly.
    NotYetOpen(StreamId, Range<usize>),
    /// The receive side of that request is closed.
    Drop,
}
