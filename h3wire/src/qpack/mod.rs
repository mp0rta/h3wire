//! QPACK (RFC 9204) building blocks.

pub mod huffman;
pub mod prefix_int;

/// Failure of a QPACK primitive; callers map it to the proper H3 error code.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QpackError {
    Truncated,
    Overflow,
    Huffman,
    Invalid,
}
