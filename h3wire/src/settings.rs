//! SETTINGS frame codec (RFC 9114 section 7.2.4).

use crate::config::Config;
use crate::error::{H3Code, is_grease_id};
use crate::frame::{SETTINGS, encode_header, grease_frame_type};
use crate::varint;
use std::collections::HashSet;

pub const QPACK_MAX_TABLE_CAPACITY: u64 = 0x01;
pub const MAX_FIELD_SECTION_SIZE: u64 = 0x06;
pub const QPACK_BLOCKED_STREAMS: u64 = 0x07;
pub const ENABLE_CONNECT_PROTOCOL: u64 = 0x08;
pub const H3_DATAGRAM: u64 = 0x33;
pub const H2_RESERVED_SETTINGS: [u64; 5] = [0x00, 0x02, 0x03, 0x04, 0x05];

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PeerSettings {
    pub qpack_max_table_capacity: u64,
    pub qpack_blocked_streams: u64,
    pub max_field_section_size: Option<u64>,
    pub enable_connect_protocol: bool,
    pub h3_datagram: bool,
    pub unknown: Vec<(u64, u64)>,
}

/// Encode the full local SETTINGS frame (type, length, payload).
pub(crate) fn encode_local(cfg: &Config, grease_seed: u64, out: &mut Vec<u8>) {
    let mut p = Vec::new();
    let mut put = |id: u64, v: u64| {
        varint::encode(id, &mut p);
        varint::encode(v, &mut p);
    };
    if let Some(v) = cfg.max_field_section_size {
        put(MAX_FIELD_SECTION_SIZE, v.min(varint::MAX));
    }
    if cfg.enable_connect_protocol {
        put(ENABLE_CONNECT_PROTOCOL, 1);
    }
    if cfg.h3_datagram {
        put(H3_DATAGRAM, 1);
    }
    for &(id, v) in &cfg.extra_settings {
        put(id, v);
    }
    if cfg.grease {
        put(grease_frame_type(grease_seed), grease_seed & 0xff);
    }
    encode_header(SETTINGS, p.len() as u64, out);
    out.extend_from_slice(&p);
}

/// Decode the payload of a peer SETTINGS frame.
pub(crate) fn decode_peer(payload: &[u8]) -> Result<PeerSettings, H3Code> {
    let mut s = PeerSettings::default();
    let mut seen = HashSet::new();
    let mut rest = payload;
    while !rest.is_empty() {
        let (id, n) = varint::decode(rest).ok_or(H3Code::FRAME_ERROR)?;
        rest = &rest[n..];
        let (v, n) = varint::decode(rest).ok_or(H3Code::FRAME_ERROR)?;
        rest = &rest[n..];
        if H2_RESERVED_SETTINGS.contains(&id) || !seen.insert(id) {
            return Err(H3Code::SETTINGS_ERROR);
        }
        let flag = |v: u64| match v {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(H3Code::SETTINGS_ERROR),
        };
        match id {
            QPACK_MAX_TABLE_CAPACITY => s.qpack_max_table_capacity = v,
            QPACK_BLOCKED_STREAMS => s.qpack_blocked_streams = v,
            MAX_FIELD_SECTION_SIZE => s.max_field_section_size = Some(v),
            ENABLE_CONNECT_PROTOCOL => s.enable_connect_protocol = flag(v)?,
            H3_DATAGRAM => s.h3_datagram = flag(v)?,
            _ if is_grease_id(id) => {}
            _ => s.unknown.push((id, v)),
        }
    }
    Ok(s)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{Contexts, FrameExtension};
    use crate::error::UsageError;

    #[test]
    fn config_rejects_reserved() {
        let mut c = Config::default();
        for (id, v) in [(0x21, 1), (0x02, 1), (0x08, 1)] {
            assert_eq!(c.add_setting(id, v), Err(UsageError::Reserved));
        }
        for ty in [0x06, 0x21] {
            let ext = FrameExtension {
                ty,
                contexts: Contexts::REQUEST,
            };
            assert_eq!(c.register_frame(ext), Err(UsageError::Reserved));
        }
        assert_eq!(c.register_uni_stream(0x02), Err(UsageError::Reserved));
        assert_eq!(c.add_setting(0x2b603742, 1), Ok(()));
        assert_eq!(c.add_setting(0x2b603742, 1), Err(UsageError::Reserved));
        assert_eq!(
            c.add_setting(0x2b603742, 1 << 62),
            Err(UsageError::OutOfRange)
        );
        let ext = FrameExtension {
            ty: 0x41,
            contexts: Contexts::REQUEST | Contexts::TUNNEL,
        };
        assert_eq!(c.register_frame(ext), Ok(()));
        assert_eq!(c.register_frame(ext), Err(UsageError::Reserved));
        assert!(
            ext.contexts.contains(Contexts::TUNNEL) && !ext.contexts.contains(Contexts::RESPONSE)
        );
        assert_eq!(c.register_uni_stream(0x54), Ok(()));
        assert_eq!(c.register_uni_stream(0x54), Err(UsageError::Reserved));
    }

    #[test]
    fn encode_local_minimal() {
        let c = Config {
            grease: false,
            ..Config::default()
        };
        let mut out = Vec::new();
        encode_local(&c, 0, &mut out);
        assert_eq!(out, [0x04, 0x00]);
    }

    #[test]
    fn encode_local_flags() {
        let c = Config {
            grease: false,
            enable_connect_protocol: true,
            h3_datagram: true,
            max_field_section_size: Some(u64::MAX),
            ..Config::default()
        };
        let mut out = Vec::new();
        encode_local(&c, 0, &mut out);
        assert_eq!(out[0], 0x04);
        let s = decode_peer(&out[2..]).unwrap();
        assert!(s.enable_connect_protocol && s.h3_datagram);
        assert_eq!(s.max_field_section_size, Some(varint::MAX));
    }

    #[test]
    fn encode_local_grease_roundtrip() {
        let mut c = Config::default();
        c.add_setting(0x2b603742, 9).unwrap();
        let mut out = Vec::new();
        encode_local(&c, 7, &mut out);
        let s = decode_peer(&out[2..]).unwrap();
        assert_eq!(s.unknown, [(0x2b603742, 9)]);
    }

    #[test]
    fn decode_rejects() {
        let e = Err(H3Code::SETTINGS_ERROR);
        assert_eq!(decode_peer(&[0x02, 0x00]), e);
        assert_eq!(decode_peer(&[0x06, 0x01, 0x06, 0x02]), e);
        assert_eq!(decode_peer(&[0x08, 0x02]), e);
        assert_eq!(decode_peer(&[0x33, 0x02]), e);
        assert_eq!(decode_peer(&[0x06]), Err(H3Code::FRAME_ERROR));
    }

    #[test]
    fn decode_keeps_unknown_drops_grease() {
        let s = decode_peer(&[0x21, 0x05, 0x40, 0x64, 0x07]).unwrap();
        assert_eq!(s.unknown, [(0x64, 7)]);
    }
}
