//! QPACK field section encoder: static table and literals only (RFC 9204 section 4.5).

use super::{prefix_int, static_table};
use crate::headers::FieldRef;

pub fn encode_field_section(fields: &[FieldRef], out: &mut Vec<u8>) {
    out.extend_from_slice(&[0x00, 0x00]); // Required Insert Count 0, Base 0
    for f in fields {
        let n = if f.never_index { 0x20 } else { 0 };
        match static_table::find(f.name, f.value) {
            Some((i, true)) if !f.never_index => prefix_int::encode(i as u64, 6, 0xc0, out),
            Some((i, _)) => {
                // literal with static name reference: 01 N 1 + 4-bit index
                prefix_int::encode(i as u64, 4, 0x50 | n, out);
                prefix_int::encode_str(f.value, 7, 0, out);
            }
            None => {
                // literal with literal name: 001 N H + 3-bit name length
                prefix_int::encode_str(f.name, 3, 0x20 | (n >> 1), out);
                prefix_int::encode_str(f.value, 7, 0, out);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn enc(fields: &[FieldRef]) -> Vec<u8> {
        let mut out = Vec::new();
        encode_field_section(fields, &mut out);
        out
    }

    #[test]
    fn encode_indexed() {
        let out = enc(&[
            FieldRef::new(b":method", b"GET"),
            FieldRef::new(b":path", b"/"),
        ]);
        assert_eq!(out, [0x00, 0x00, 0xd1, 0xc1]);
    }

    #[test]
    fn encode_never_index_uses_n_bit() {
        let f = FieldRef {
            name: b"authorization",
            value: b"secret",
            never_index: true,
        };
        assert_eq!(enc(&[f])[2..4], [0x7f, 0x45]);
    }

    #[test]
    fn never_index_full_match_not_indexed() {
        let f = FieldRef {
            name: b":method",
            value: b"GET",
            never_index: true,
        };
        let out = enc(&[f]);
        assert_eq!(out[2] & 0xf0, 0x70);
        assert_ne!(out[2], 0xd1);
    }

    #[test]
    fn literal_name_and_name_ref() {
        // name ref: :method PATCH -> 0101 0000 | 15 overflow...
        let out = enc(&[FieldRef::new(b":method", b"PATCH")]);
        assert_eq!(out[2] & 0xf0, 0x50);
        // literal name "x" (no Huffman gain) value "y": 0010 0001 'x' 0000 0001 'y'
        let out = enc(&[FieldRef::new(b"x", b"y")]);
        assert_eq!(out[2..], [0x21, b'x', 0x01, b'y']);
        let out = enc(&[FieldRef {
            name: b"x",
            value: b"y",
            never_index: true,
        }]);
        assert_eq!(out[2], 0x31);
    }
}
