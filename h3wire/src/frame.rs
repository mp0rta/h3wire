// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 mp0rta
//! HTTP/3 frame header codec (RFC 9114 section 7.1).

use crate::varint;

pub const DATA: u64 = 0x00;
pub const HEADERS: u64 = 0x01;
pub const CANCEL_PUSH: u64 = 0x03;
pub const SETTINGS: u64 = 0x04;
pub const PUSH_PROMISE: u64 = 0x05;
pub const GOAWAY: u64 = 0x07;
pub const MAX_PUSH_ID: u64 = 0x0d;
/// Frame types reserved because they were defined by HTTP/2.
pub const H2_RESERVED: [u64; 4] = [0x02, 0x06, 0x08, 0x09];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FrameHeader {
    pub ty: u64,
    pub len: u64,
}

/// Incremental parser for a frame's type and length varints.
#[derive(Clone, Debug, Default)]
pub struct FrameHeaderParser {
    buf: [u8; 16],
    n: usize,
}

impl FrameHeaderParser {
    pub fn new() -> Self {
        Self::default()
    }

    /// Consume bytes up to the end of type+length; returns the header once complete.
    pub fn feed(&mut self, buf: &[u8]) -> (usize, Option<FrameHeader>) {
        for (i, &b) in buf.iter().enumerate() {
            self.buf[self.n] = b;
            self.n += 1;
            // Type is complete once its varint decodes; the length must then end exactly here.
            // (let-chains avoided: MSRV 1.85)
            let Some((ty, a)) = varint::decode(&self.buf[..self.n]) else {
                continue;
            };
            if let Some((len, l)) = varint::decode(&self.buf[a..self.n]) {
                if a + l == self.n {
                    self.n = 0;
                    return (i + 1, Some(FrameHeader { ty, len }));
                }
            }
        }
        (buf.len(), None)
    }

    /// True if part of a header is buffered.
    pub fn mid_header(&self) -> bool {
        self.n > 0
    }
}

pub fn encode_header(ty: u64, len: u64, out: &mut Vec<u8>) {
    varint::encode(ty, out);
    varint::encode(len, out);
}

/// DATA frame type byte plus the length varint; returns the bytes and used length (<= 9).
pub fn data_prefix(len: u64) -> ([u8; 9], u8) {
    let mut out = [0u8; 9];
    let mut v = [0u8; 8];
    let n = varint::encode_to(len, &mut v);
    out[1..=n].copy_from_slice(&v[..n]);
    (out, (n + 1) as u8)
}

pub fn goaway_payload(id: u64, out: &mut Vec<u8>) {
    varint::encode(id, out);
}

/// Exactly one varint and nothing else (GOAWAY / MAX_PUSH_ID / CANCEL_PUSH payloads).
pub fn parse_single_varint_payload(p: &[u8]) -> Option<u64> {
    match varint::decode(p) {
        Some((v, n)) if n == p.len() => Some(v),
        _ => None,
    }
}

pub fn grease_frame_type(seed: u64) -> u64 {
    0x1f * (seed % 0x1000) + 0x21
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn header_split_at_every_byte() {
        let mut w = Vec::new();
        encode_header(0x21 + 0x1f * 3, 16_384, &mut w);
        for cut in 0..=w.len() {
            let mut p = FrameHeaderParser::new();
            let (n1, h1) = p.feed(&w[..cut]);
            let (n2, h2) = p.feed(&w[cut..]);
            assert_eq!(n1 + n2, w.len());
            assert_eq!(
                h1.or(h2),
                Some(FrameHeader {
                    ty: 0x21 + 0x1f * 3,
                    len: 16_384
                })
            );
        }
    }

    #[test]
    fn feed_stops_at_header_end() {
        let mut p = FrameHeaderParser::new();
        assert_eq!(
            p.feed(&[0x01, 0x02, 0xaa, 0xbb]),
            (
                2,
                Some(FrameHeader {
                    ty: HEADERS,
                    len: 2
                })
            )
        );
        assert!(!p.mid_header());
        assert_eq!(p.feed(&[0x40]), (1, None));
        assert!(p.mid_header());
    }

    #[test]
    fn data_prefix_is_type_and_len() {
        let (b, n) = data_prefix(300);
        assert_eq!(&b[..n as usize], &[0x00, 0x41, 0x2c]);
    }

    #[test]
    fn single_varint_payload_rejects_trailing_or_short() {
        assert_eq!(parse_single_varint_payload(&[0x04]), Some(4));
        assert_eq!(parse_single_varint_payload(&[0x04, 0x00]), None);
        assert_eq!(parse_single_varint_payload(&[0x40]), None);
    }
}
