//! RFC 7541 section 5 prefix integers and string literals.

use super::{QpackError, huffman};
use crate::varint;

/// Encode `v` with an N-bit prefix; `first_byte_flags` occupies the bits above the prefix.
pub fn encode(v: u64, prefix_bits: u8, first_byte_flags: u8, out: &mut Vec<u8>) {
    debug_assert!((1..=8).contains(&prefix_bits));
    let mask = ((1u16 << prefix_bits) - 1) as u8;
    if v < u64::from(mask) {
        out.push(first_byte_flags | v as u8);
        return;
    }
    out.push(first_byte_flags | mask);
    let mut v = v - u64::from(mask);
    while v >= 128 {
        out.push((v & 127) as u8 | 128);
        v >>= 7;
    }
    out.push(v as u8);
}

/// Decode a prefix integer, returning `(value, bytes consumed)`. Values above 2^62-1 are `Overflow`.
pub fn decode(buf: &[u8], prefix_bits: u8) -> Result<(u64, usize), QpackError> {
    debug_assert!((1..=8).contains(&prefix_bits));
    let mask = ((1u16 << prefix_bits) - 1) as u8;
    let first = *buf.first().ok_or(QpackError::Truncated)? & mask;
    if first < mask {
        return Ok((u64::from(first), 1));
    }
    let mut v = u64::from(mask);
    let mut shift = 0u32;
    for (i, &b) in buf[1..].iter().enumerate() {
        let add = u64::from(b & 127);
        if shift >= 63 || add.leading_zeros() < shift {
            return Err(QpackError::Overflow);
        }
        v = v.checked_add(add << shift).ok_or(QpackError::Overflow)?;
        if v > varint::MAX {
            return Err(QpackError::Overflow);
        }
        if b & 128 == 0 {
            return Ok((v, i + 2));
        }
        shift += 7;
    }
    Err(QpackError::Truncated)
}

/// String literal: length as a prefix integer with the Huffman flag at `1 << prefix_bits`
/// (so `prefix_bits <= 7`); Huffman is used iff strictly shorter.
pub fn encode_str(s: &[u8], prefix_bits: u8, flags: u8, out: &mut Vec<u8>) {
    debug_assert!(prefix_bits <= 7);
    let h = huffman::encoded_len(s);
    if h < s.len() {
        encode(h as u64, prefix_bits, flags | (1 << prefix_bits), out);
        huffman::encode(s, out);
    } else {
        encode(s.len() as u64, prefix_bits, flags, out);
        out.extend_from_slice(s);
    }
}

/// Decode a string literal, appending to `out`; returns bytes consumed. `out` is unchanged on error.
pub fn decode_str(buf: &[u8], prefix_bits: u8, out: &mut Vec<u8>) -> Result<usize, QpackError> {
    debug_assert!(prefix_bits <= 7);
    let is_huff = *buf.first().ok_or(QpackError::Truncated)? & (1 << prefix_bits) != 0;
    let (len, n) = decode(buf, prefix_bits)?;
    let end = usize::try_from(len)
        .ok()
        .and_then(|l| n.checked_add(l))
        .filter(|&e| e <= buf.len())
        .ok_or(QpackError::Truncated)?;
    let body = &buf[n..end];
    if is_huff {
        let mark = out.len();
        huffman::decode(body, out).inspect_err(|_| out.truncate(mark))?;
    } else {
        out.extend_from_slice(body);
    }
    Ok(end)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prefix_int_rfc7541_c1() {
        for (v, bits, enc) in [
            (10u64, 5u8, &[0x0au8][..]),
            (1337, 5, &[0x1f, 0x9a, 0x0a]),
            (42, 8, &[0x2a]),
        ] {
            let mut o = Vec::new();
            encode(v, bits, 0, &mut o);
            assert_eq!(o, enc);
            assert_eq!(decode(enc, bits), Ok((v, enc.len())));
        }
        assert_eq!(decode(&[0x1f, 0x9a], 5), Err(QpackError::Truncated));
        assert_eq!(decode(&[], 5), Err(QpackError::Truncated));
        let mut b = vec![0x1f];
        b.extend([0xff; 10]);
        b.push(0x01);
        assert_eq!(decode(&b, 5), Err(QpackError::Overflow));
        // exactly 2^62-1 decodes, 2^62 overflows
        let mut o = Vec::new();
        encode(varint::MAX, 5, 0, &mut o);
        assert_eq!(decode(&o, 5), Ok((varint::MAX, o.len())));
        let mut o = Vec::new();
        encode(varint::MAX + 1, 5, 0, &mut o);
        assert_eq!(decode(&o, 5), Err(QpackError::Overflow));
    }

    #[test]
    fn prefix_int_flags_preserved() {
        let mut o = Vec::new();
        encode(1337, 5, 0xe0, &mut o);
        assert_eq!(o, [0xff, 0x9a, 0x0a]);
        assert_eq!(decode(&o, 5), Ok((1337, 3)));
    }

    #[test]
    fn string_roundtrip() {
        for s in [&b""[..], b"www.example.com", b"\x00\x01\xff", b"a"] {
            for bits in [3u8, 7] {
                let mut o = Vec::new();
                encode_str(s, bits, 0, &mut o);
                let mut out = b"pre".to_vec();
                assert_eq!(decode_str(&o, bits, &mut out), Ok(o.len()));
                assert_eq!(&out[3..], s);
            }
        }
        // Huffman only when strictly shorter
        let mut o = Vec::new();
        encode_str(b"www.example.com", 7, 0, &mut o);
        assert_eq!(o[0], 0x80 | 12);
        let mut o = Vec::new();
        encode_str(b"\xff", 7, 0, &mut o);
        assert_eq!(o, [1, 0xff]);
    }

    #[test]
    fn string_errors() {
        let mut out = Vec::new();
        assert_eq!(
            decode_str(&[0x05, b'a'], 7, &mut out),
            Err(QpackError::Truncated)
        );
        assert_eq!(decode_str(&[], 7, &mut out), Err(QpackError::Truncated));
        assert_eq!(
            decode_str(&[0xff; 12], 7, &mut out),
            Err(QpackError::Overflow)
        );
        assert_eq!(
            decode_str(&[0x7f, 0xff, 0xff, 0xff, 0xff, 0x0f], 7, &mut out),
            Err(QpackError::Truncated)
        );
        assert!(out.is_empty());
    }
}
