//! Core-owned per-stream send path: uni stream binding and the byte queues.

use super::Connection;
use crate::error::UsageError;
use crate::frame::{encode_header, grease_frame_type};
use crate::settings::encode_local;
use crate::stream::{SendState, Stream, StreamId, UniKind};
use crate::varint;

impl Connection {
    /// Bind a stream opened for `Action::OpenUni(kind)`; queues its stream type
    /// (and, for the control stream, SETTINGS plus an optional GREASE frame).
    pub fn bind_uni(&mut self, kind: UniKind, stream: StreamId) -> Result<(), UsageError> {
        self.check_open().map_err(UsageError::Closed)?;
        if !stream.is_uni() || !self.is_local(stream) {
            return Err(UsageError::WrongStreamKind);
        }
        if self.local_uni[kind as usize].is_some() || self.streams.contains_key(&stream) {
            return Err(UsageError::WrongPhase);
        }
        let ty = match kind {
            UniKind::Control => 0x00,
            UniKind::QpackEncoder => 0x02,
            UniKind::QpackDecoder => 0x03,
        };
        let mut queue = Vec::new();
        varint::encode(ty, &mut queue);
        if kind == UniKind::Control {
            encode_local(&self.config, self.grease_seed, &mut queue);
            self.settings_left = queue.len();
            if self.config.grease {
                encode_header(grease_frame_type(self.grease_seed), 0, &mut queue);
            }
        }
        self.local_uni[kind as usize] = Some(stream);
        let send = SendState {
            queue,
            ..SendState::default()
        };
        self.streams.insert(stream, Stream { send });
        Ok(())
    }

    /// Streams with core-owned bytes pending and no DATA in flight, ascending id.
    pub fn sendable(&self) -> impl Iterator<Item = StreamId> + '_ {
        let open = self.check_open().is_ok();
        self.streams
            .iter()
            .filter(move |(_, st)| open && !st.send.pending().is_empty())
            .map(|(&id, _)| id)
    }

    pub fn poll_send(&self, s: StreamId) -> Option<&[u8]> {
        self.check_open().ok()?;
        let p = self.streams.get(&s)?.send.pending();
        (!p.is_empty()).then_some(p)
    }

    /// The transport accepted the first `n` bytes of `poll_send(s)`.
    pub fn sent(&mut self, s: StreamId, n: usize) -> Result<(), UsageError> {
        self.check_open().map_err(UsageError::Closed)?;
        let st = self.streams.get_mut(&s).ok_or(UsageError::UnknownStream)?;
        if n > st.send.pending().len() {
            return Err(UsageError::WrongPhase);
        }
        st.send.advance(n);
        if Some(s) == self.local_uni[UniKind::Control as usize] && !self.local_settings_sent {
            self.settings_left = self.settings_left.saturating_sub(n);
            self.local_settings_sent = self.settings_left == 0;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use crate::conn::Role;

    #[test]
    fn local_settings_sent_after_settings_fully_written() {
        let cfg = Config {
            grease: false,
            ..Config::default()
        };
        let mut c = Connection::new(Role::Client, cfg);
        c.bind_uni(UniKind::Control, StreamId(2)).unwrap(); // [0x00, 0x04, 0x00]
        c.sent(StreamId(2), 2).unwrap(); // stops inside SETTINGS
        assert!(!c.local_settings_sent);
        c.sent(StreamId(2), 1).unwrap();
        assert!(c.local_settings_sent);
    }
}
