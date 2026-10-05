//! Connection close path and transport-side stream inputs.

use super::Connection;
use super::recv_uni::PeerUni;
use crate::error::{ConnectionError, H3Code};
use crate::event::{Action, Event};
use crate::stream::StreamId;

impl Connection {
    /// The single connection-error path: closes for good and queues the wire effect.
    pub(crate) fn close_with(&mut self, code: H3Code, reason: &'static str) -> ConnectionError {
        if let Some(c) = self.closed {
            return ConnectionError::Closed(c);
        }
        self.closed = Some(code);
        self.actions
            .push_back(Action::CloseConnection { code, reason });
        self.events.push_back(Event::Closed { code });
        self.streams.clear();
        self.peer_uni.clear();
        self.blocks.clear();
        ConnectionError::Closed(code)
    }

    /// `Err(code)` once the connection is closed; checked first by every public method.
    pub(crate) fn check_open(&self) -> Result<(), H3Code> {
        self.closed.map_or(Ok(()), Err)
    }

    pub fn stream_reset_received(
        &mut self,
        s: StreamId,
        _code: H3Code,
    ) -> Result<(), ConnectionError> {
        self.check_open().map_err(ConnectionError::Closed)?;
        match self.peer_uni.get(&s) {
            Some(PeerUni::Control(_) | PeerUni::Encoder(_) | PeerUni::Decoder(_)) => {
                Err(self.close_with(H3Code::CLOSED_CRITICAL_STREAM, "critical stream reset"))
            }
            Some(_) => {
                self.peer_uni.remove(&s);
                Ok(())
            }
            // Request streams: Task 13.
            None => Ok(()),
        }
    }

    pub fn stop_sending_received(
        &mut self,
        s: StreamId,
        _code: H3Code,
    ) -> Result<(), ConnectionError> {
        self.check_open().map_err(ConnectionError::Closed)?;
        if self.local_uni.contains(&Some(s)) {
            return Err(self.close_with(H3Code::CLOSED_CRITICAL_STREAM, "critical stream stopped"));
        }
        // Request streams: Task 13.
        Ok(())
    }

    /// Still a no-op (Task 13); once filled it must return early when already closed.
    pub fn transport_closed(&mut self) {}
}
