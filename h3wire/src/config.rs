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

/// Set of stream contexts in which an extension frame is delivered; combine with `|`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Contexts(u8);

impl Contexts {
    /// A request stream before a tunnel is established, as received by a server.
    pub const REQUEST: Contexts = Contexts(1);
    /// A request stream before a tunnel is established, as received by a client.
    pub const RESPONSE: Contexts = Contexts(2);
    /// A request stream after a successful (Extended) CONNECT, either role.
    pub const TUNNEL: Contexts = Contexts(4);

    /// Whether every context in `other` is in `self`.
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
///
/// On a request stream, a frame of this type in one of `contexts` comes back from
/// [`Connection::recv`](crate::Connection::recv) as [`Recv::Frame`](crate::Recv::Frame)
/// pieces; in any other context it is skipped like an unknown frame, except that in a
/// tunnel it is `H3_FRAME_UNEXPECTED` (RFC 9114 section 4.4).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FrameExtension {
    /// The frame type.
    pub ty: u64,
    /// Where the frame is delivered.
    pub contexts: Contexts,
}

/// Connection configuration. Start from [`Config::default`] and set what you need.
#[derive(Clone, Debug)]
pub struct Config {
    /// Local memory bound: the largest HEADERS frame payload (encoded field section) the
    /// core buffers. A larger declared length is `H3_EXCESSIVE_LOAD` (connection error),
    /// checked before any payload byte is buffered. Not advertised. Default 65,536.
    pub max_encoded_field_section_size: usize,
    /// Local memory bound: the largest SETTINGS frame payload accepted on the peer control
    /// stream; larger is `H3_EXCESSIVE_LOAD`. Not advertised. Default 16,384.
    pub max_control_frame_size: usize,
    /// Advertised as `SETTINGS_MAX_FIELD_SECTION_SIZE` when `Some` (values above 2^62-1
    /// are capped). Advertised only: the core does not enforce it; see
    /// `max_encoded_field_section_size` for the local bound. Default `None`.
    pub max_field_section_size: Option<u64>,
    /// Server: advertise `SETTINGS_ENABLE_CONNECT_PROTOCOL = 1` and accept Extended
    /// CONNECT requests (RFC 9220). Default off.
    pub enable_connect_protocol: bool,
    /// Advertise `SETTINGS_H3_DATAGRAM = 1` (RFC 9297); set it only when the QUIC
    /// connection supports DATAGRAM frames. Default off.
    pub h3_datagram: bool,
    /// Send a reserved (GREASE) setting and frame on the control stream. Default on.
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
    /// Advertise an extra setting `id = value`.
    ///
    /// `Err(OutOfRange)` beyond 2^62-1; `Err(Reserved)` for GREASE and HTTP/2-reserved
    /// identifiers, the settings this crate defines, and an id already added.
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

    /// Deliver frames of `ext.ty` instead of skipping them.
    ///
    /// `Err(OutOfRange)` beyond 2^62-1; `Err(Reserved)` for GREASE and HTTP/2-reserved
    /// types, the frame types RFC 9114 defines, and a type already registered.
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

    /// Accept peer unidirectional streams of type `ty`: each yields
    /// [`Event::UniStream`](crate::Event::UniStream), then its bytes come back as
    /// [`Recv::Raw`](crate::Recv::Raw). Unregistered unknown types are refused with
    /// `STOP_SENDING(H3_STREAM_CREATION_ERROR)` and their bytes discarded.
    ///
    /// `Err(OutOfRange)` beyond 2^62-1; `Err(Reserved)` for types 0x00 to 0x03, GREASE
    /// types, and a type already registered.
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
