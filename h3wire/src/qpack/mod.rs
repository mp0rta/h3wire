//! QPACK (RFC 9204) building blocks.

pub mod decoder;
pub mod encoder;
pub mod huffman;
pub mod instructions;
pub mod prefix_int;
pub mod static_table;

/// Failure of a QPACK primitive; callers map it to the proper H3 error code.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QpackError {
    Truncated,
    Overflow,
    Huffman,
    Invalid,
}
