// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 mp0rta
//! Receive on peer unidirectional streams: control, QPACK encoder/decoder, push,
//! registered extension types and unknown types (RFC 9114 section 6.2).

use super::{Connection, Role};
use crate::error::{ConnectionError, H3Code};
use crate::event::{Action, Event, Recv};
use crate::frame::{
    CANCEL_PUSH, DATA, FrameHeader, FrameHeaderParser, GOAWAY, H2_RESERVED, HEADERS, MAX_PUSH_ID,
    PUSH_PROMISE, SETTINGS, parse_single_varint_payload,
};
use crate::qpack::instructions::{DecoderStreamParser, EncoderStreamParser};
use crate::settings::decode_peer;
use crate::stream::{StreamId, UniKind};
use crate::varint;

/// Receive state of one peer uni stream.
pub(crate) enum PeerUni {
    /// The stream type varint is not complete yet.
    Type {
        buf: [u8; 8],
        n: usize,
    },
    Control(ControlRecv),
    Encoder(EncoderStreamParser),
    Decoder(DecoderStreamParser),
    /// Registered extension type: bytes go to the application as `Recv::Raw`.
    Raw,
    /// Unknown type: STOP_SENDING requested, bytes discarded.
    Discard,
}

#[derive(Default)]
pub(crate) struct ControlRecv {
    hdr: FrameHeaderParser,
    /// Type of the frame being read and its payload bytes still to come.
    cur: Option<(u64, u64)>,
    /// Payload of a frame the core interprets; its length was bounded at header parse.
    payload: Vec<u8>,
}

impl PeerUni {
    /// Heap bytes held: a control frame payload or a partial decoder instruction.
    pub(super) fn buffered_bytes(&self) -> usize {
        match self {
            PeerUni::Control(c) => c.payload.capacity(),
            PeerUni::Decoder(p) => p.buffered_bytes(),
            _ => 0,
        }
    }
}

/// Control frames whose payload is buffered and interpreted; all others are skipped.
fn interpreted(ty: u64) -> bool {
    matches!(ty, SETTINGS | GOAWAY | MAX_PUSH_ID | CANCEL_PUSH)
}

impl Connection {
    /// Always consumes all of `bytes` (or closes the connection).
    ///
    /// A registered type yields `Event::UniStream` once its type varint completes; the
    /// bytes after the type in that same chunk and every later chunk come back as one
    /// `Recv::Raw` covering the rest of the chunk (`Consumed` when that rest is empty).
    pub(super) fn recv_uni(
        &mut self,
        s: StreamId,
        bytes: &[u8],
        fin: bool,
    ) -> Result<Recv, ConnectionError> {
        let mut st = self
            .peer_uni
            .remove(&s)
            .unwrap_or(PeerUni::Type { buf: [0; 8], n: 0 });
        let mut rest = bytes;
        while let PeerUni::Type { buf, n } = &mut st {
            let Some((&b, tail)) = rest.split_first() else {
                break;
            };
            rest = tail;
            // A varint is at most 8 bytes and decodes as soon as it is complete.
            buf[*n] = b;
            *n += 1;
            if let Some((ty, _)) = varint::decode(&buf[..*n]) {
                st = self.uni_type(s, ty, fin)?;
            }
        }
        let start = bytes.len() - rest.len();
        let mut out = Recv::Consumed(bytes.len());
        match &mut st {
            PeerUni::Type { .. } | PeerUni::Discard => {}
            PeerUni::Control(c) => self.control_bytes(c, rest)?,
            PeerUni::Encoder(p) => {
                p.feed(rest)
                    .map_err(|code| self.close_with(code, "QPACK encoder stream error"))?;
            }
            PeerUni::Decoder(p) => {
                p.feed(rest)
                    .map_err(|code| self.close_with(code, "QPACK decoder stream error"))?;
            }
            PeerUni::Raw if !rest.is_empty() => {
                out = Recv::Raw {
                    consumed: bytes.len(),
                    range: start..bytes.len(),
                };
            }
            PeerUni::Raw => {}
        }
        if !fin {
            self.peer_uni.insert(s, st);
        } else if matches!(
            st,
            PeerUni::Control(_) | PeerUni::Encoder(_) | PeerUni::Decoder(_)
        ) {
            return Err(self.close_with(H3Code::CLOSED_CRITICAL_STREAM, "critical stream closed"));
        }
        // Otherwise the stream is done (or closed before its type completed): forget it.
        Ok(out)
    }

    /// The stream type of peer uni stream `s` is complete.
    fn uni_type(&mut self, s: StreamId, ty: u64, fin: bool) -> Result<PeerUni, ConnectionError> {
        let (kind, st) = match ty {
            0x00 => (UniKind::Control, PeerUni::Control(ControlRecv::default())),
            0x02 => (UniKind::QpackEncoder, PeerUni::Encoder(EncoderStreamParser)),
            0x03 => (UniKind::QpackDecoder, PeerUni::Decoder(Default::default())),
            0x01 => {
                // Push is never enabled (no MAX_PUSH_ID sent; servers never accept push).
                let code = match self.role {
                    Role::Client => H3Code::ID_ERROR,
                    Role::Server => H3Code::STREAM_CREATION_ERROR,
                };
                return Err(self.close_with(code, "push stream"));
            }
            _ if self.config.uni_types.contains(&ty) => {
                self.events.push_back(Event::UniStream { stream: s, ty });
                return Ok(PeerUni::Raw);
            }
            _ => {
                if !fin {
                    self.actions.push_back(Action::StopSending {
                        stream: s,
                        code: H3Code::STREAM_CREATION_ERROR,
                    });
                }
                return Ok(PeerUni::Discard);
            }
        };
        if std::mem::replace(&mut self.peer_critical[kind as usize], true) {
            return Err(self.close_with(H3Code::STREAM_CREATION_ERROR, "duplicate critical stream"));
        }
        Ok(st)
    }

    /// Parse control stream bytes; unknown frames are skipped by counting, never buffered.
    fn control_bytes(
        &mut self,
        c: &mut ControlRecv,
        mut bytes: &[u8],
    ) -> Result<(), ConnectionError> {
        loop {
            let Some((ty, left)) = c.cur else {
                if bytes.is_empty() {
                    return Ok(());
                }
                let (n, h) = c.hdr.feed(bytes);
                bytes = &bytes[n..];
                if let Some(h) = h {
                    self.control_frame_start(h)?;
                    c.cur = Some((h.ty, h.len));
                }
                continue;
            };
            // `take <= bytes.len()`, so the cast is lossless.
            let take = left.min(bytes.len() as u64) as usize;
            if interpreted(ty) {
                c.payload.extend_from_slice(&bytes[..take]);
            }
            bytes = &bytes[take..];
            if left > take as u64 {
                c.cur = Some((ty, left - take as u64));
                return Ok(());
            }
            c.cur = None;
            self.control_frame_end(ty, std::mem::take(&mut c.payload))?;
        }
    }

    /// Frame header checks, before any payload byte is buffered.
    fn control_frame_start(&mut self, h: FrameHeader) -> Result<(), ConnectionError> {
        const UNEXPECTED: Option<(H3Code, &str)> = Some((
            H3Code::FRAME_UNEXPECTED,
            "frame not allowed on control stream",
        ));
        let first = self.peer_settings.is_none();
        let fail = match h.ty {
            // RFC 9114 section 6.2.1: any other first frame, unknown types included.
            _ if first && h.ty != SETTINGS => Some((
                H3Code::MISSING_SETTINGS,
                "control stream must start with SETTINGS",
            )),
            SETTINGS if !first => UNEXPECTED,
            SETTINGS if h.len > self.config.max_control_frame_size as u64 => Some((
                H3Code::EXCESSIVE_LOAD,
                "SETTINGS exceeds max_control_frame_size",
            )),
            DATA | HEADERS | PUSH_PROMISE => UNEXPECTED,
            t if H2_RESERVED.contains(&t) => UNEXPECTED,
            MAX_PUSH_ID if self.role == Role::Client => {
                Some((H3Code::FRAME_UNEXPECTED, "MAX_PUSH_ID received by client"))
            }
            GOAWAY | MAX_PUSH_ID | CANCEL_PUSH if h.len > 8 => {
                Some((H3Code::FRAME_ERROR, "fixed-layout control frame too long"))
            }
            _ => None,
        };
        match fail {
            Some((code, reason)) => Err(self.close_with(code, reason)),
            None => Ok(()),
        }
    }

    /// A control frame is complete; `payload` is empty unless `interpreted(ty)`.
    fn control_frame_end(&mut self, ty: u64, payload: Vec<u8>) -> Result<(), ConnectionError> {
        if ty == SETTINGS {
            let s =
                decode_peer(&payload).map_err(|code| self.close_with(code, "invalid SETTINGS"))?;
            self.peer_settings = Some(s);
            self.events.push_back(Event::PeerSettings);
            return Ok(());
        }
        if !interpreted(ty) {
            return Ok(());
        }
        let Some(id) = parse_single_varint_payload(&payload) else {
            return Err(self.close_with(H3Code::FRAME_ERROR, "malformed control frame payload"));
        };
        let r = match ty {
            GOAWAY => self.on_goaway(id).map_err(|code| (code, "invalid GOAWAY")),
            // Server only (rejected for clients at header parse); push stays disabled.
            MAX_PUSH_ID if self.max_push_id.is_some_and(|m| id < m) => {
                Err((H3Code::ID_ERROR, "MAX_PUSH_ID decreased"))
            }
            MAX_PUSH_ID => {
                self.max_push_id = Some(id);
                Ok(())
            }
            // CANCEL_PUSH: no push ID is ever valid.
            _ => Err((H3Code::ID_ERROR, "CANCEL_PUSH without push")),
        };
        r.map_err(|(code, reason)| self.close_with(code, reason))
    }
}
