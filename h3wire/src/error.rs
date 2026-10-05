//! HTTP/3 error codes and error types.

use std::fmt;

/// An HTTP/3 error code (RFC 9114 section 8.1), kept as the raw wire value.
///
/// `==` compares raw values; use [`H3Code::semantic`] to interpret a received code.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct H3Code(
    /// The raw code.
    pub u64,
);

impl H3Code {
    /// `H3_NO_ERROR`: no error; also what unknown codes mean locally.
    pub const NO_ERROR: H3Code = H3Code(0x100);
    /// `H3_GENERAL_PROTOCOL_ERROR`.
    pub const GENERAL_PROTOCOL_ERROR: H3Code = H3Code(0x101);
    /// `H3_INTERNAL_ERROR`.
    pub const INTERNAL_ERROR: H3Code = H3Code(0x102);
    /// `H3_STREAM_CREATION_ERROR`: a stream was created that is not acceptable.
    pub const STREAM_CREATION_ERROR: H3Code = H3Code(0x103);
    /// `H3_CLOSED_CRITICAL_STREAM`: a control or QPACK stream was closed.
    pub const CLOSED_CRITICAL_STREAM: H3Code = H3Code(0x104);
    /// `H3_FRAME_UNEXPECTED`: a frame not permitted in the current state or stream.
    pub const FRAME_UNEXPECTED: H3Code = H3Code(0x105);
    /// `H3_FRAME_ERROR`: a malformed frame.
    pub const FRAME_ERROR: H3Code = H3Code(0x106);
    /// `H3_EXCESSIVE_LOAD`: the peer exceeded a local resource bound.
    pub const EXCESSIVE_LOAD: H3Code = H3Code(0x107);
    /// `H3_ID_ERROR`: a stream or push ID was used incorrectly.
    pub const ID_ERROR: H3Code = H3Code(0x108);
    /// `H3_SETTINGS_ERROR`: an invalid SETTINGS frame or value.
    pub const SETTINGS_ERROR: H3Code = H3Code(0x109);
    /// `H3_MISSING_SETTINGS`: the control stream did not start with SETTINGS.
    pub const MISSING_SETTINGS: H3Code = H3Code(0x10a);
    /// `H3_REQUEST_REJECTED`: the request was not processed; safe to retry.
    pub const REQUEST_REJECTED: H3Code = H3Code(0x10b);
    /// `H3_REQUEST_CANCELLED`: the request or its response was cancelled.
    pub const REQUEST_CANCELLED: H3Code = H3Code(0x10c);
    /// `H3_REQUEST_INCOMPLETE`: the request stream ended before a complete request.
    pub const REQUEST_INCOMPLETE: H3Code = H3Code(0x10d);
    /// `H3_MESSAGE_ERROR`: a malformed HTTP message.
    pub const MESSAGE_ERROR: H3Code = H3Code(0x10e);
    /// `H3_CONNECT_ERROR`: the CONNECT tunnel was reset or closed abnormally.
    pub const CONNECT_ERROR: H3Code = H3Code(0x10f);
    /// `H3_VERSION_FALLBACK`: retry the request over HTTP/1.1.
    pub const VERSION_FALLBACK: H3Code = H3Code(0x110);
    /// `QPACK_DECOMPRESSION_FAILED` (RFC 9204): a field section could not be decoded.
    pub const QPACK_DECOMPRESSION_FAILED: H3Code = H3Code(0x200);
    /// `QPACK_ENCODER_STREAM_ERROR` (RFC 9204): an invalid encoder stream instruction.
    pub const QPACK_ENCODER_STREAM_ERROR: H3Code = H3Code(0x201);
    /// `QPACK_DECODER_STREAM_ERROR` (RFC 9204): an invalid decoder stream instruction.
    pub const QPACK_DECODER_STREAM_ERROR: H3Code = H3Code(0x202);
    /// `H3_DATAGRAM_ERROR` (RFC 9297): a malformed or unexpected HTTP datagram.
    pub const DATAGRAM_ERROR: H3Code = H3Code(0x33);

    /// Whether this is one of the codes defined above.
    pub fn is_known(self) -> bool {
        matches!(
            self,
            Self::NO_ERROR
                | Self::GENERAL_PROTOCOL_ERROR
                | Self::INTERNAL_ERROR
                | Self::STREAM_CREATION_ERROR
                | Self::CLOSED_CRITICAL_STREAM
                | Self::FRAME_UNEXPECTED
                | Self::FRAME_ERROR
                | Self::EXCESSIVE_LOAD
                | Self::ID_ERROR
                | Self::SETTINGS_ERROR
                | Self::MISSING_SETTINGS
                | Self::REQUEST_REJECTED
                | Self::REQUEST_CANCELLED
                | Self::REQUEST_INCOMPLETE
                | Self::MESSAGE_ERROR
                | Self::CONNECT_ERROR
                | Self::VERSION_FALLBACK
                | Self::QPACK_DECOMPRESSION_FAILED
                | Self::QPACK_ENCODER_STREAM_ERROR
                | Self::QPACK_DECODER_STREAM_ERROR
                | Self::DATAGRAM_ERROR
        )
    }

    /// The code's meaning for local handling: unknown codes are treated as `NO_ERROR`.
    pub fn semantic(self) -> H3Code {
        if self.is_known() {
            self
        } else {
            Self::NO_ERROR
        }
    }

    /// Whether this is a reserved (GREASE) code, `0x1f * N + 0x21`.
    pub fn is_grease(self) -> bool {
        is_grease_id(self.0)
    }
}

/// The connection is closed: returned by peer-input calls (`recv`, `parse_datagram`,
/// `stream_reset_received`, `stop_sending_received`).
///
/// A state notification only. When the call itself closed the connection, the wire effect
/// is the [`Action::CloseConnection`](crate::Action::CloseConnection) it queued; the caller
/// must not close the QUIC connection because of the `Err`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionError {
    /// The connection is closed with this code (`NO_ERROR` after
    /// [`Connection::transport_closed`](crate::Connection::transport_closed)).
    Closed(H3Code),
}

/// A local call the connection refused; it had no effect and no wire effect.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UsageError {
    /// `send_data`: core-owned bytes are still queued or a DATA frame is in flight on that
    /// stream. Retry after writing them.
    Blocked,
    /// The connection is closed with this code.
    Closed(H3Code),
    /// No such stream: never opened, already finished, or not a stream this call accepts.
    UnknownStream,
    /// The stream id is of the wrong kind (e.g. not a request stream, not a local uni stream).
    WrongStreamKind,
    /// Not allowed in the stream's current state (e.g. DATA before a final response,
    /// HEADERS after trailers, writing more than is pending).
    WrongPhase,
    /// Needs a setting not negotiated with the peer (Extended CONNECT, HTTP datagrams).
    NotNegotiated,
    /// Client: the peer sent GOAWAY, so no new request may start.
    GoingAway,
    /// The header block was released, or the id is not from this connection.
    StaleBlock,
    /// The fields to send do not form a valid HTTP/3 message head or trailer section.
    InvalidField,
    /// A setting, frame type or uni stream type that cannot be added or registered.
    Reserved,
    /// A value above the varint maximum, 2^62-1.
    OutOfRange,
    /// `abort` with `H3_REQUEST_REJECTED` where it may not be sent (a client, or a
    /// server once the request was processed; RFC 9114 section 4.1.1).
    ForbiddenCode,
}

impl fmt::Display for ConnectionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Closed(c) => write!(f, "connection closed ({:#x})", c.0),
        }
    }
}

impl fmt::Display for UsageError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Closed(c) => write!(f, "connection closed ({:#x})", c.0),
            other => write!(f, "usage error: {other:?}"),
        }
    }
}

impl std::error::Error for ConnectionError {}
impl std::error::Error for UsageError {}

/// GREASE reserved values have the form `0x1f * N + 0x21` (RFC 9114 section 7.2.8).
pub(crate) fn is_grease_id(v: u64) -> bool {
    v >= 0x21 && (v - 0x21) % 0x1f == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn semantic_maps_unknown_to_no_error() {
        assert_eq!(H3Code(0x1234).semantic(), H3Code::NO_ERROR);
        assert_eq!(H3Code::FRAME_ERROR.semantic(), H3Code::FRAME_ERROR);
    }

    #[test]
    fn eq_compares_raw() {
        assert_ne!(H3Code(0x21), H3Code::NO_ERROR);
    }

    #[test]
    fn grease_ids() {
        assert!(is_grease_id(0x21));
        assert!(is_grease_id(0x21 + 0x1f * 7));
        assert!(!is_grease_id(0x22));
        assert!(!is_grease_id(0));
    }
}
