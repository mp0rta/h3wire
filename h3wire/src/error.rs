//! HTTP/3 error codes and error types.

use std::fmt;

/// An HTTP/3 error code (RFC 9114 section 8.1), kept as the raw wire value.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct H3Code(pub u64);

impl H3Code {
    pub const NO_ERROR: H3Code = H3Code(0x100);
    pub const GENERAL_PROTOCOL_ERROR: H3Code = H3Code(0x101);
    pub const INTERNAL_ERROR: H3Code = H3Code(0x102);
    pub const STREAM_CREATION_ERROR: H3Code = H3Code(0x103);
    pub const CLOSED_CRITICAL_STREAM: H3Code = H3Code(0x104);
    pub const FRAME_UNEXPECTED: H3Code = H3Code(0x105);
    pub const FRAME_ERROR: H3Code = H3Code(0x106);
    pub const EXCESSIVE_LOAD: H3Code = H3Code(0x107);
    pub const ID_ERROR: H3Code = H3Code(0x108);
    pub const SETTINGS_ERROR: H3Code = H3Code(0x109);
    pub const MISSING_SETTINGS: H3Code = H3Code(0x10a);
    pub const REQUEST_REJECTED: H3Code = H3Code(0x10b);
    pub const REQUEST_CANCELLED: H3Code = H3Code(0x10c);
    pub const REQUEST_INCOMPLETE: H3Code = H3Code(0x10d);
    pub const MESSAGE_ERROR: H3Code = H3Code(0x10e);
    pub const CONNECT_ERROR: H3Code = H3Code(0x10f);
    pub const VERSION_FALLBACK: H3Code = H3Code(0x110);
    pub const QPACK_DECOMPRESSION_FAILED: H3Code = H3Code(0x200);
    pub const QPACK_ENCODER_STREAM_ERROR: H3Code = H3Code(0x201);
    pub const QPACK_DECODER_STREAM_ERROR: H3Code = H3Code(0x202);
    pub const DATAGRAM_ERROR: H3Code = H3Code(0x33);

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

    pub fn is_grease(self) -> bool {
        is_grease_id(self.0)
    }
}

/// Connection-level failure notification; the wire effect is carried by `Action::CloseConnection`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionError {
    Closed(H3Code),
}

/// Misuse of the public API.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UsageError {
    Blocked,
    Closed(H3Code),
    UnknownStream,
    WrongStreamKind,
    WrongPhase,
    NotNegotiated,
    GoingAway,
    StaleBlock,
    InvalidField,
    Reserved,
    OutOfRange,
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
