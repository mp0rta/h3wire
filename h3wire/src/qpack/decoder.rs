// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 mp0rta
//! QPACK field section decoder: static table and literals only (v0.1).

use super::{prefix_int, static_table};
use crate::error::H3Code;

/// Bytes of a decoded name or value: static table entry or a range of the arena.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Span {
    Static(&'static [u8]),
    /// `[start, end)` in the arena.
    Arena(u32, u32),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DecodedField {
    pub name: Span,
    pub value: Span,
    pub never_index: bool,
}

/// Decode a field section, appending to `arena` and `fields` (the caller clears them).
pub fn decode_field_section(
    buf: &[u8],
    arena: &mut Vec<u8>,
    fields: &mut Vec<DecodedField>,
) -> Result<(), H3Code> {
    let fail = |_| H3Code::QPACK_DECOMPRESSION_FAILED;
    // Prefix: Required Insert Count must be 0; Sign must be 0 (Delta Base is ignored).
    let (ric, n) = prefix_int::decode(buf, 8).map_err(fail)?;
    let rest = &buf[n..];
    if ric != 0 || rest.first().ok_or(H3Code::QPACK_DECOMPRESSION_FAILED)? & 0x80 != 0 {
        return Err(H3Code::QPACK_DECOMPRESSION_FAILED);
    }
    let (_, n2) = prefix_int::decode(rest, 7).map_err(fail)?;
    let mut buf = &rest[n2..];

    while let Some(&b) = buf.first() {
        let (name, value, never_index, used);
        if b & 0x80 != 0 {
            // Indexed, static only.
            let (idx, n) = static_ref(buf, 6, 0x40)?;
            (name, value) = (Span::Static(idx.0), Span::Static(idx.1));
            never_index = false;
            used = n;
        } else if b & 0xc0 == 0x40 {
            // Literal with static name reference.
            let (idx, n) = static_ref(buf, 4, 0x10)?;
            name = Span::Static(idx.0);
            never_index = b & 0x20 != 0;
            let (v, m) = literal(&buf[n..], 7, arena)?;
            (value, used) = (v, n + m);
        } else if b & 0xe0 == 0x20 {
            // Literal with literal name.
            let (nm, n) = literal(buf, 3, arena)?;
            name = nm;
            never_index = b & 0x10 != 0;
            let (v, m) = literal(&buf[n..], 7, arena)?;
            (value, used) = (v, n + m);
        } else {
            // Post-base forms.
            return Err(H3Code::QPACK_DECOMPRESSION_FAILED);
        }
        fields.push(DecodedField {
            name,
            value,
            never_index,
        });
        buf = &buf[used..];
    }
    Ok(())
}

type Entry = (&'static [u8], &'static [u8]);

/// Static table entry for an index with `bits` prefix bits and the T flag `t_mask`.
fn static_ref(buf: &[u8], bits: u8, t_mask: u8) -> Result<(Entry, usize), H3Code> {
    let fail = H3Code::QPACK_DECOMPRESSION_FAILED;
    if buf[0] & t_mask == 0 {
        return Err(fail);
    }
    let (i, n) = prefix_int::decode(buf, bits).map_err(|_| fail)?;
    let e = usize::try_from(i)
        .ok()
        .and_then(|i| static_table::ENTRIES.get(i))
        .ok_or(fail)?;
    Ok((*e, n))
}

/// Decode a string literal into the arena.
fn literal(buf: &[u8], bits: u8, arena: &mut Vec<u8>) -> Result<(Span, usize), H3Code> {
    let fail = H3Code::QPACK_DECOMPRESSION_FAILED;
    let start = arena.len();
    let n = prefix_int::decode_str(buf, bits, arena).map_err(|_| fail)?;
    match (u32::try_from(start), u32::try_from(arena.len())) {
        (Ok(s), Ok(e)) => Ok((Span::Arena(s, e), n)),
        _ => {
            arena.truncate(start);
            Err(fail)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::headers::FieldRef;
    use crate::qpack::encoder::encode_field_section;

    const FAIL: H3Code = H3Code::QPACK_DECOMPRESSION_FAILED;

    fn dec(buf: &[u8]) -> Result<(Vec<u8>, Vec<DecodedField>), H3Code> {
        let (mut a, mut f) = (Vec::new(), Vec::new());
        decode_field_section(buf, &mut a, &mut f).map(|_| (a, f))
    }

    fn bytes(a: &[u8], s: Span) -> &[u8] {
        match s {
            Span::Static(b) => b,
            Span::Arena(x, y) => &a[x as usize..y as usize],
        }
    }

    fn sample() -> Vec<FieldRef<'static>> {
        let long = Box::leak("v".repeat(300).into_boxed_str()).as_bytes();
        vec![
            FieldRef::new(b":method", b"GET"),
            FieldRef::new(b":path", b"/index.html"),
            FieldRef::new(b"accept-encoding", b"gzip, deflate, br"),
            FieldRef {
                name: b"authorization",
                value: b"secret",
                never_index: true,
            },
            FieldRef::new(b"x-custom", long),
            FieldRef::new(b"x-empty", b""),
        ]
    }

    #[test]
    fn decode_roundtrips_encoder() {
        let want = sample();
        let mut wire = Vec::new();
        encode_field_section(&want, &mut wire);
        let (a, got) = dec(&wire).unwrap();
        assert_eq!(got.len(), want.len());
        for (g, w) in got.iter().zip(&want) {
            assert_eq!(bytes(&a, g.name), w.name);
            assert_eq!(bytes(&a, g.value), w.value);
            assert_eq!(g.never_index, w.never_index);
        }
    }

    #[test]
    fn decode_rejects_dynamic() {
        for bad in [
            &[0x01u8, 0x00, 0xd1][..],
            &[0x00, 0x00, 0x80],
            &[0x00, 0x00, 0x10],
            &[0x00, 0x80, 0xd1],
            &[0x00, 0x00, 0xff, 0x3d],       // static index 99
            &[0x00, 0x00, 0x40, 0x00],       // literal name ref, dynamic
            &[0x00, 0x00, 0x5f, 0x54, 0x00], // literal name ref, static 99
            &[0x00, 0x00, 0x00, 0x00],       // literal post-base name ref
        ] {
            assert_eq!(dec(bad).unwrap_err(), FAIL, "{bad:x?}");
        }
        assert!(dec(&[0x00, 0x05, 0xd1]).is_ok());
    }

    #[test]
    fn decode_truncated_fails() {
        let all = sample();
        let mut wire = Vec::new();
        encode_field_section(&all, &mut wire);
        // Only the prefix and whole-line boundaries may decode.
        let mut boundaries = Vec::new();
        for k in 0..all.len() {
            let mut w = Vec::new();
            encode_field_section(&all[..k], &mut w);
            boundaries.push(w.len());
        }
        for n in 0..wire.len() {
            assert_eq!(dec(&wire[..n]).is_ok(), boundaries.contains(&n), "len {n}");
        }
    }

    #[test]
    fn decode_garbage_never_panics() {
        for b in 0..=255u8 {
            for c in [0u8, 0x7f, 0xff] {
                let _ = dec(&[0, 0, b, c, b, c, b]);
            }
        }
    }
}
