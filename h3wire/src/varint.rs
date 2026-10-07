// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 mp0rta
//! QUIC variable-length integers (RFC 9000 section 16).

pub const MAX: u64 = (1 << 62) - 1;

/// Encoded length of `v` in bytes. Caller guarantees `v <= MAX`.
pub fn len(v: u64) -> usize {
    debug_assert!(v <= MAX);
    match v {
        0..=63 => 1,
        64..=16_383 => 2,
        16_384..=1_073_741_823 => 4,
        _ => 8,
    }
}

/// Encode `v` into `buf`, returning the number of bytes used.
pub fn encode_to(v: u64, buf: &mut [u8; 8]) -> usize {
    let n = len(v);
    let tag = match n {
        1 => 0u64,
        2 => 1,
        4 => 2,
        _ => 3,
    };
    let x = v | (tag << (n * 8 - 2));
    buf[..n].copy_from_slice(&x.to_be_bytes()[8 - n..]);
    n
}

pub fn encode(v: u64, out: &mut Vec<u8>) {
    let mut b = [0u8; 8];
    let n = encode_to(v, &mut b);
    out.extend_from_slice(&b[..n]);
}

/// Decode a varint from the start of `buf`; `None` means more bytes are needed.
pub fn decode(buf: &[u8]) -> Option<(u64, usize)> {
    let first = *buf.first()?;
    let n = 1usize << (first >> 6);
    let bytes = buf.get(..n)?;
    let mut v = u64::from(first & 0x3f);
    for &b in &bytes[1..] {
        v = (v << 8) | u64::from(b);
    }
    Some((v, n))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc9000_a1_vectors() {
        assert_eq!(
            decode(&[0xc2, 0x19, 0x7c, 0x5e, 0xff, 0x14, 0xe8, 0x8c]),
            Some((151_288_809_941_952_652, 8))
        );
        assert_eq!(decode(&[0x9d, 0x7f, 0x3e, 0x7d]), Some((494_878_333, 4)));
        assert_eq!(decode(&[0x7b, 0xbd]), Some((15_293, 2)));
        assert_eq!(decode(&[0x25]), Some((37, 1)));
        assert_eq!(decode(&[0x40, 0x25]), Some((37, 2))); // non-minimal accepted
    }

    #[test]
    fn every_length_boundary_roundtrips() {
        for v in [0, 63, 64, 16_383, 16_384, 1_073_741_823, 1_073_741_824, MAX] {
            let mut b = Vec::new();
            encode(v, &mut b);
            assert_eq!(b.len(), len(v));
            assert_eq!(decode(&b), Some((v, b.len())));
            for cut in 0..b.len() {
                assert_eq!(decode(&b[..cut]), None);
            }
        }
    }
}
