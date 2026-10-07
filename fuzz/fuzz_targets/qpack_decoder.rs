// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 mp0rta
#![no_main]

use h3wire::qpack::decoder::{Span, decode_field_section};
use h3wire::qpack::instructions::{DecoderStreamParser, EncoderStreamParser};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let mut arena = Vec::new();
    let mut fields = Vec::new();
    if decode_field_section(data, &mut arena, &mut fields).is_ok() {
        // The sizes `Connection::debug_bound` relies on: at most one field per encoded
        // byte, and Huffman output at most 8/5 of its input.
        assert!(fields.len() <= data.len());
        assert!(arena.len() <= data.len() * 8 / 5);
        for f in &fields {
            for span in [f.name, f.value] {
                if let Span::Arena(s, e) = span {
                    assert!(s <= e && e as usize <= arena.len());
                }
            }
        }
    }
    let _ = EncoderStreamParser.feed(data);
    // Decoder stream instructions, split at every third byte.
    let mut d = DecoderStreamParser::default();
    for piece in data.chunks(3) {
        match d.feed(piece) {
            Ok(n) => assert_eq!(n, piece.len()),
            Err(_) => break,
        }
    }
});
