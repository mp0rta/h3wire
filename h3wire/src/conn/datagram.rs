// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 mp0rta
//! HTTP Datagram framing and routing (RFC 9297 section 2.1, spec section 2.5).

use super::{Connection, Role};
use crate::error::{ConnectionError, H3Code, UsageError};
use crate::event::Datagram;
use crate::stream::{RecvPhase, SendPhase, StreamId};
use crate::varint;

/// Largest Quarter Stream ID: `q * 4` must stay a valid stream id (< 2^62).
const MAX_QUARTER: u64 = (1 << 60) - 1;

impl Connection {
    /// Write the Quarter Stream ID prefix for an HTTP datagram on request stream `s` into
    /// `buf`; returns its length. The caller sends prefix then payload as one QUIC
    /// DATAGRAM.
    ///
    /// `Err(NotNegotiated)` unless `SETTINGS_H3_DATAGRAM = 1` was both sent (written to
    /// the transport) and received; `Err(WrongStreamKind)` for a non-request stream;
    /// `Err(WrongPhase)` unless the stream's send side is open (on a server, also only
    /// after its request was delivered).
    pub fn datagram_prefix(&self, s: StreamId, buf: &mut [u8; 8]) -> Result<usize, UsageError> {
        self.check_open().map_err(UsageError::Closed)?;
        let peer_on = self.peer_settings.as_ref().is_some_and(|p| p.h3_datagram);
        if !(self.config.h3_datagram && self.local_settings_sent && peer_on) {
            return Err(UsageError::NotNegotiated);
        }
        if !s.is_request() {
            return Err(UsageError::WrongStreamKind);
        }
        // A server answers only a delivered request (as `send_headers` does).
        let delivered = |phase| self.role == Role::Client || phase != RecvPhase::AwaitHeaders;
        match self.streams.get(&s) {
            Some(st) if st.send.phase != SendPhase::Done && delivered(st.recv.phase) => {}
            _ => return Err(UsageError::WrongPhase),
        }
        Ok(varint::encode_to(s.0 / 4, buf))
    }

    /// Route a received HTTP datagram payload (the QUIC DATAGRAM frame contents); the
    /// returned range is the datagram body. Never buffers or copies anything; see
    /// [`Datagram`] for what the caller decides.
    ///
    /// A truncated Quarter Stream ID or one above 2^60-1 is `H3_DATAGRAM_ERROR`
    /// (connection error).
    pub fn parse_datagram(&mut self, payload: &[u8]) -> Result<Datagram, ConnectionError> {
        self.check_open().map_err(ConnectionError::Closed)?;
        let (q, n) = match varint::decode(payload) {
            Some((q, n)) if q <= MAX_QUARTER => (q, n),
            _ => {
                return Err(self.close_with(H3Code::DATAGRAM_ERROR, "invalid quarter stream id"));
            }
        };
        if !self.config.h3_datagram {
            return Ok(Datagram::Drop);
        }
        let s = StreamId(q * 4);
        let range = n..payload.len();
        Ok(match self.streams.get(&s) {
            Some(st) if !st.recv.closed => Datagram::Deliver(s, range),
            Some(_) => Datagram::Drop,
            None if self.is_reaped(s) => Datagram::Drop,
            None => Datagram::NotYetOpen(s, range),
        })
    }
}
