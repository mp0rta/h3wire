//! Decode other implementations' QPACK encoder output (qpackers/qifs, dynamic table
//! capacity 0) and compare with the source header lists.

use h3wire::qpack::decoder::{Span, decode_field_section};
use h3wire::qpack::instructions::EncoderStreamParser;
use std::path::PathBuf;

type Block = Vec<(Vec<u8>, Vec<u8>)>;

fn data() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("testdata/qifs")
}

/// QIF: `name\tvalue` lines, blocks separated by blank lines, `#` comments.
fn parse_qif(text: &[u8]) -> Vec<Block> {
    let mut blocks = vec![];
    let mut cur = vec![];
    for line in text.split(|&b| b == b'\n') {
        if line.first() == Some(&b'#') {
            continue;
        }
        if line.is_empty() {
            if !cur.is_empty() {
                blocks.push(std::mem::take(&mut cur));
            }
            continue;
        }
        let tab = line
            .iter()
            .position(|&b| b == b'\t')
            .expect("tab in QIF line");
        cur.push((line[..tab].to_vec(), line[tab + 1..].to_vec()));
    }
    if !cur.is_empty() {
        blocks.push(cur);
    }
    blocks
}

/// Offline interop format: (u64 stream id, u32 length, bytes)*; stream 0 is the encoder stream.
fn decode_encoded(buf: &[u8]) -> Vec<(u64, Block)> {
    let mut out = vec![];
    let mut enc = EncoderStreamParser;
    let mut rest = buf;
    while !rest.is_empty() {
        let id = u64::from_be_bytes(rest[..8].try_into().unwrap());
        let len = u32::from_be_bytes(rest[8..12].try_into().unwrap()) as usize;
        let body = &rest[12..12 + len];
        rest = &rest[12 + len..];
        if id == 0 {
            assert_eq!(enc.feed(body), Ok(len), "encoder stream instructions");
            continue;
        }
        let (mut arena, mut fields) = (vec![], vec![]);
        decode_field_section(body, &mut arena, &mut fields)
            .unwrap_or_else(|e| panic!("stream {id}: {e:?}"));
        let bytes = |s: Span| match s {
            Span::Static(b) => b.to_vec(),
            Span::Arena(a, b) => arena[a as usize..b as usize].to_vec(),
        };
        out.push((
            id,
            fields
                .iter()
                .map(|f| (bytes(f.name), bytes(f.value)))
                .collect(),
        ));
    }
    out
}

#[test]
fn decodes_other_encoders_static_only_output() {
    let mut checked = 0;
    for name in ["fb-req", "fb-resp", "netbsd"] {
        let expected = parse_qif(&std::fs::read(data().join(format!("qifs/{name}.qif"))).unwrap());
        for encoder in ["ls-qpack", "nghttp3", "qthingey", "quinn"] {
            let path = data().join(format!("encoded/qpack-06/{encoder}/{name}.out.0.0.0"));
            let got = decode_encoded(&std::fs::read(&path).unwrap());
            assert_eq!(got.len(), expected.len(), "{encoder}/{name}: block count");
            for (i, (id, block)) in got.iter().enumerate() {
                // Block N of the QIF is sent on stream N (1-based).
                assert_eq!(*id, i as u64 + 1, "{encoder}/{name}: stream order");
                assert_eq!(block, &expected[i], "{encoder}/{name}: block {id}");
            }
            checked += got.len();
        }
    }
    assert!(checked > 1000, "only {checked} blocks checked");
}
