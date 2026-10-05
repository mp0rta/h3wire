//! QPACK encoder/decoder stream instruction parsers (v0.1 rules: no dynamic table).

use super::{QpackError, prefix_int};
use crate::error::H3Code;

const MAX_PENDING: usize = 16;

/// Encoder stream: only `Set Dynamic Table Capacity(0)` is tolerated.
#[derive(Debug, Default)]
pub struct EncoderStreamParser;

impl EncoderStreamParser {
    pub fn feed(&mut self, buf: &[u8]) -> Result<usize, H3Code> {
        // 0x20 is the only valid instruction: any other first byte is capacity > 0 or an insert.
        match buf.iter().position(|&b| b != 0x20) {
            None => Ok(buf.len()),
            Some(_) => Err(H3Code::QPACK_ENCODER_STREAM_ERROR),
        }
    }
}

/// Decoder stream: only Stream Cancellation is tolerated (and ignored).
#[derive(Debug, Default)]
pub struct DecoderStreamParser {
    pending: Vec<u8>,
}

impl DecoderStreamParser {
    pub fn feed(&mut self, buf: &[u8]) -> Result<usize, H3Code> {
        const ERR: H3Code = H3Code::QPACK_DECODER_STREAM_ERROR;
        for &b in buf {
            // Only `01` Stream Cancellation is valid; its first byte is enough to reject the rest.
            if self.pending.is_empty() && b & 0xc0 != 0x40 {
                return Err(ERR);
            }
            self.pending.push(b);
            match prefix_int::decode(&self.pending, 6) {
                Ok(_) => self.pending.clear(),
                Err(QpackError::Truncated) if self.pending.len() < MAX_PENDING => {}
                Err(_) => return Err(ERR),
            }
        }
        Ok(buf.len())
    }

    /// Heap bytes held for a partial instruction.
    pub(crate) fn buffered_bytes(&self) -> usize {
        self.pending.capacity()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encoder_stream_rules() {
        let mut p = EncoderStreamParser;
        assert_eq!(p.feed(&[0x20]), Ok(1));
        assert_eq!(p.feed(&[]), Ok(0));
        for bad in [
            &[0x21u8][..],
            &[0x3f, 0x01],
            &[0xc1, 0x01, b'a'],
            &[0x41, 0x01, b'a'],
            &[0x00],
        ] {
            assert_eq!(
                EncoderStreamParser.feed(bad),
                Err(H3Code::QPACK_ENCODER_STREAM_ERROR),
                "{bad:x?}"
            );
        }
    }

    #[test]
    fn decoder_stream_rules() {
        let mut p = DecoderStreamParser::default();
        assert_eq!(p.feed(&[0x44]), Ok(1));
        for bad in [&[0x84u8][..], &[0x01], &[0x00]] {
            assert_eq!(
                DecoderStreamParser::default().feed(bad),
                Err(H3Code::QPACK_DECODER_STREAM_ERROR),
                "{bad:x?}"
            );
        }
    }

    #[test]
    fn decoder_stream_split_cancellation() {
        // Stream id 1000: 0x7f, 0xa9, 0x07 (6-bit prefix int).
        let mut p = DecoderStreamParser::default();
        assert_eq!(p.feed(&[0x7f]), Ok(1));
        assert_eq!(p.feed(&[0xa9]), Ok(1));
        assert_eq!(p.feed(&[0x07, 0x44]), Ok(2));
        // Byte after the completed instruction is parsed fresh.
        assert_eq!(p.feed(&[0x84]), Err(H3Code::QPACK_DECODER_STREAM_ERROR));
    }

    #[test]
    fn decoder_stream_overlong_is_error() {
        let mut p = DecoderStreamParser::default();
        let mut buf = vec![0x7f];
        buf.extend([0xff; 20]);
        assert_eq!(p.feed(&buf), Err(H3Code::QPACK_DECODER_STREAM_ERROR));
    }
}
