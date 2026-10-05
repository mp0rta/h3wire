//! HTTP Datagram framing and routing (RFC 9297 section 2.1, spec section 2.5).

use super::{Connection, Role};
use crate::error::{ConnectionError, H3Code, UsageError};
use crate::event::Datagram;
use crate::stream::{RecvPhase, SendPhase, StreamId};
use crate::varint;

/// Largest Quarter Stream ID: `q * 4` must stay a valid stream id (< 2^62).
const MAX_QUARTER: u64 = (1 << 60) - 1;

impl Connection {
    /// Write the Quarter Stream ID prefix for a datagram on request stream `s`.
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

    /// Route a received HTTP datagram payload; the range is the datagram body.
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
