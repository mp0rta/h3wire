// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 mp0rta
//! A test-only minimal capsule parser (RFC 9297 §3.2) and CONNECT-UDP requests
//! (RFC 9298), for the MASQUE boundary suite.

use bytes::{Buf, Bytes, BytesMut};
use h3wire_async::core::varint;
use h3wire_async::datagram::RegisterDatagrams;
use h3wire_async::ext::Protocol;
use http::{Method, Request};

/// The DATAGRAM capsule type (RFC 9297 §3.5), the only one surfaced.
pub const DATAGRAM: u64 = 0x00;

/// A complete capsule.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Capsule {
    pub ty: u64,
    pub payload: Bytes,
}

/// The tunnel ended inside a capsule.
#[derive(Debug, PartialEq, Eq)]
pub struct Truncated;

#[derive(Default)]
enum State {
    /// Collecting the type and length varints (split across reads).
    #[default]
    Head,
    /// A DATAGRAM capsule's payload: bytes still missing.
    Payload(u64),
    /// An unknown capsule: bytes still to skip (never buffered).
    Skip(u64),
}

/// Incremental capsule parser: varints may be split across reads, unknown capsules are
/// skipped without buffering, and [`finish`](Self::finish) detects truncation.
#[derive(Default)]
pub struct CapsuleParser {
    head: Vec<u8>,
    payload: BytesMut,
    state: State,
}

impl CapsuleParser {
    /// Parse `b`; the DATAGRAM capsules it completes.
    pub fn feed(&mut self, mut b: Bytes) -> Vec<Capsule> {
        let mut out = Vec::new();
        loop {
            match self.state {
                State::Head => {
                    let Some(&x) = b.first() else { return out };
                    b.advance(1);
                    self.head.push(x);
                    let Some((ty, n)) = varint::decode(&self.head) else {
                        continue;
                    };
                    let Some((len, _)) = varint::decode(&self.head[n..]) else {
                        continue;
                    };
                    self.head.clear();
                    self.state = if ty == DATAGRAM {
                        State::Payload(len)
                    } else {
                        State::Skip(len)
                    };
                }
                State::Skip(0) => self.state = State::Head,
                State::Skip(left) => {
                    if b.is_empty() {
                        return out;
                    }
                    let n = left.min(b.len() as u64);
                    b.advance(n as usize);
                    self.state = State::Skip(left - n);
                }
                State::Payload(0) => {
                    out.push(Capsule {
                        ty: DATAGRAM,
                        payload: self.payload.split().freeze(),
                    });
                    self.state = State::Head;
                }
                State::Payload(left) => {
                    if b.is_empty() {
                        return out;
                    }
                    let n = left.min(b.len() as u64);
                    self.payload.extend_from_slice(&b.split_to(n as usize));
                    self.state = State::Payload(left - n);
                }
            }
        }
    }

    /// At a clean tunnel EOF: `Truncated` unless the stream ended between capsules.
    pub fn finish(&self) -> Result<(), Truncated> {
        match self.state {
            State::Head if self.head.is_empty() => Ok(()),
            _ => Err(Truncated),
        }
    }
}

/// One encoded capsule.
pub fn capsule(ty: u64, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    varint::encode(ty, &mut out);
    varint::encode(payload.len() as u64, &mut out);
    out.extend_from_slice(payload);
    out
}

/// The `:path` of a CONNECT-UDP request (RFC 9298 §2, the default template).
pub fn udp_path(host: &str, port: u16) -> String {
    format!("/.well-known/masque/udp/{host}/{port}/")
}

/// An Extended CONNECT for `connect-udp` to `host:port` through `authority`, with
/// `capsule-protocol: ?1`, registering HTTP datagrams.
pub fn connect_udp_request<B: Default>(authority: &str, host: &str, port: u16) -> Request<B> {
    let mut r = Request::builder()
        .method(Method::CONNECT)
        .uri(format!("https://{authority}{}", udp_path(host, port)))
        .header("capsule-protocol", "?1")
        .body(B::default())
        .unwrap();
    r.extensions_mut()
        .insert(Protocol::from_static("connect-udp"));
    r.extensions_mut().insert(RegisterDatagrams);
    r
}

#[test]
fn parser_split_at_every_offset() {
    // Multi-byte varints in both positions, an empty DATAGRAM, unknown capsules (one
    // with an empty payload) and a payload over 64 bytes.
    let big: Vec<u8> = (0..300u32).map(|i| i as u8).collect();
    let mut wire = capsule(DATAGRAM, b"a");
    wire.extend(capsule(0x4040, &[9; 70]));
    wire.extend(capsule(DATAGRAM, b""));
    wire.extend(capsule(0x2a, b""));
    wire.extend(capsule(DATAGRAM, &big));
    let want = [&b"a"[..], b"", &big];
    for i in 0..=wire.len() {
        for j in i..=wire.len() {
            let mut p = CapsuleParser::default();
            let mut got = Vec::new();
            for part in [&wire[..i], &wire[i..j], &wire[j..]] {
                got.extend(p.feed(Bytes::copy_from_slice(part)));
            }
            let got: Vec<_> = got.iter().map(|c| &c.payload[..]).collect();
            assert_eq!(got, want, "split at {i}, {j}");
            assert_eq!(p.finish(), Ok(()));
        }
    }
}

#[test]
fn parser_byte_at_a_time_and_truncation() {
    let mut wire = capsule(0x2a, &[1; 100]);
    let boundary = wire.len();
    wire.extend(capsule(DATAGRAM, b"xyz"));
    let mut p = CapsuleParser::default();
    let mut got = Vec::new();
    for (k, &x) in wire.iter().enumerate() {
        // A prefix is clean only between capsules.
        let clean = k == 0 || k == boundary;
        assert_eq!(p.finish(), if clean { Ok(()) } else { Err(Truncated) });
        got.extend(p.feed(Bytes::copy_from_slice(&[x])));
    }
    assert_eq!(
        got,
        [Capsule {
            ty: DATAGRAM,
            payload: Bytes::from_static(b"xyz")
        }]
    );
    assert_eq!(p.finish(), Ok(()));
    // Unknown capsules are skipped incrementally: nothing of them is buffered.
    let mut p = CapsuleParser::default();
    assert!(
        p.feed(Bytes::from(capsule(0x2a, &[0; 4096])[..2000].to_vec()))
            .is_empty()
    );
    assert!(p.head.is_empty() && p.payload.is_empty());
    assert_eq!(p.finish(), Err(Truncated));
}
