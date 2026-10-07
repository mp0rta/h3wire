// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 mp0rta
#![no_main]

use h3wire::frame::{FrameHeader, FrameHeaderParser};
use libfuzzer_sys::fuzz_target;

/// Feed `bytes` in `chunk`-sized pieces; returns every header parsed.
fn parse(bytes: &[u8], chunk: usize) -> Vec<FrameHeader> {
    let mut p = FrameHeaderParser::new();
    let mut out = Vec::new();
    for piece in bytes.chunks(chunk) {
        let mut rest = piece;
        while !rest.is_empty() {
            let (n, h) = p.feed(rest);
            assert!(n > 0 && n <= rest.len());
            rest = &rest[n..];
            out.extend(h);
        }
    }
    out
}

// The input is a back-to-back sequence of frame headers (no payloads): parsing must
// not depend on where the input is split.
fuzz_target!(|data: &[u8]| {
    let Some((&k, bytes)) = data.split_first() else {
        return;
    };
    let whole = parse(bytes, bytes.len().max(1));
    assert_eq!(parse(bytes, usize::from(k % 17).max(1)), whole);
});
