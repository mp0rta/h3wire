//! Connection close path and transport-side stream inputs.

use super::Connection;
use super::recv_uni::PeerUni;
use crate::error::{ConnectionError, H3Code};
use crate::event::{AbortSource, Action, Event};
use crate::stream::{SendPhase, SendState, StreamId};

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
        self.block_stream.clear();
        ConnectionError::Closed(code)
    }

    /// A stream error detected locally (spec section 4).
    pub(crate) fn stream_error(&mut self, s: StreamId, code: H3Code) {
        self.abort_stream(s, code, code, AbortSource::Local);
    }

    /// The single per-stream abort path; minimal until Task 13 completes it.
    ///
    /// `ResetStream` if our send side is not `Done`; `StopSending` unless the receive side
    /// is closed (a caller that saw the peer's FIN sets `recv.closed` first, and the event
    /// is still emitted); queued send bytes are dropped; `Event::StreamAborted`.
    pub(crate) fn abort_stream(
        &mut self,
        s: StreamId,
        wire: H3Code,
        event: H3Code,
        source: AbortSource,
    ) {
        let Some(st) = self.streams.get_mut(&s) else {
            return;
        };
        if st.send.phase != SendPhase::Done {
            self.actions.push_back(Action::ResetStream {
                stream: s,
                code: wire,
            });
        }
        if !st.recv.closed {
            self.actions.push_back(Action::StopSending {
                stream: s,
                code: wire,
            });
        }
        st.send = SendState {
            phase: SendPhase::Done,
            ..SendState::default()
        };
        st.recv.closed = true;
        self.events.push_back(Event::StreamAborted {
            stream: s,
            code: event,
            source,
        });
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
