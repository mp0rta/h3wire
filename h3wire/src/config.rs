//! Connection configuration and extension-point registration.

use crate::error::{UsageError, is_grease_id};
use crate::frame::{
    CANCEL_PUSH, DATA, GOAWAY, H2_RESERVED, HEADERS, MAX_PUSH_ID, PUSH_PROMISE, SETTINGS,
};
use crate::settings::{
    ENABLE_CONNECT_PROTOCOL, H2_RESERVED_SETTINGS, H3_DATAGRAM, MAX_FIELD_SECTION_SIZE,
    QPACK_BLOCKED_STREAMS, QPACK_MAX_TABLE_CAPACITY,
};
use crate::varint;
use std::ops::BitOr;

/// Set of stream contexts in which an extension frame is allowed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Contexts(u8);

impl Contexts {
    pub const REQUEST: Contexts = Contexts(1);
    pub const RESPONSE: Contexts = Contexts(2);
    pub const TUNNEL: Contexts = Contexts(4);

    pub fn contains(self, other: Contexts) -> bool {
        self.0 & other.0 == other.0
    }
}

impl BitOr for Contexts {
    type Output = Contexts;
    fn bitor(self, rhs: Contexts) -> Contexts {
        Contexts(self.0 | rhs.0)
    }
}

/// An extension frame type the application wants delivered instead of ignored.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FrameExtension {
    pub ty: u64,
    pub contexts: Contexts,
}

#[derive(Clone, Debug)]
pub struct Config {
    pub max_encoded_field_section_size: usize,
    pub max_control_frame_size: usize,
    pub max_field_section_size: Option<u64>,
    pub enable_connect_protocol: bool,
    pub h3_datagram: bool,
    pub grease: bool,
    pub(crate) extra_settings: Vec<(u64, u64)>,
    pub(crate) frames: Vec<FrameExtension>,
    pub(crate) uni_types: Vec<u64>,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            max_encoded_field_section_size: 65_536,
            max_control_frame_size: 16_384,
            max_field_section_size: None,
            enable_connect_protocol: false,
            h3_datagram: false,
            grease: true,
            extra_settings: Vec::new(),
            frames: Vec::new(),
            uni_types: Vec::new(),
        }
    }
}

impl Config {
    pub fn add_setting(&mut self, id: u64, value: u64) -> Result<(), UsageError> {
        if id > varint::MAX || value > varint::MAX {
            return Err(UsageError::OutOfRange);
        }
        let defined = [
            QPACK_MAX_TABLE_CAPACITY,
            MAX_FIELD_SECTION_SIZE,
            QPACK_BLOCKED_STREAMS,
            ENABLE_CONNECT_PROTOCOL,
            H3_DATAGRAM,
        ];
        if is_grease_id(id)
            || H2_RESERVED_SETTINGS.contains(&id)
            || defined.contains(&id)
            || self.extra_settings.iter().any(|&(i, _)| i == id)
        {
            return Err(UsageError::Reserved);
        }
        self.extra_settings.push((id, value));
        Ok(())
    }

    pub fn register_frame(&mut self, ext: FrameExtension) -> Result<(), UsageError> {
        let ty = ext.ty;
        if ty > varint::MAX {
            return Err(UsageError::OutOfRange);
        }
        let known = [
            DATA,
            HEADERS,
            CANCEL_PUSH,
            SETTINGS,
            PUSH_PROMISE,
            GOAWAY,
            MAX_PUSH_ID,
        ];
        if is_grease_id(ty)
            || H2_RESERVED.contains(&ty)
            || known.contains(&ty)
            || self.frames.iter().any(|f| f.ty == ty)
        {
            return Err(UsageError::Reserved);
        }
        self.frames.push(ext);
        Ok(())
    }

    pub fn register_uni_stream(&mut self, ty: u64) -> Result<(), UsageError> {
        if ty > varint::MAX {
            return Err(UsageError::OutOfRange);
        }
        if ty <= 0x03 || is_grease_id(ty) || self.uni_types.contains(&ty) {
            return Err(UsageError::Reserved);
        }
        self.uni_types.push(ty);
        Ok(())
    }
}
