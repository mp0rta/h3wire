//! GOAWAY by role, the "processed" invariant, and the hooks used by the send and receive
//! paths (spec section 4, "GOAWAY").

use super::{Connection, Role};
use crate::error::{H3Code, UsageError};
use crate::event::{AbortSource, Event};
use crate::frame::{GOAWAY, encode_header, goaway_payload};
use crate::stream::{StreamId, UniKind};

/// The last client-initiated bidirectional stream id (RFC 9114 section 5.2).
const LAST_REQUEST: u64 = (1 << 62) - 4;

/// Append a GOAWAY(`id`) frame to `out`.
pub(super) fn encode_goaway(id: u64, out: &mut Vec<u8>) {
    let mut p = Vec::new();
    goaway_payload(id, &mut p);
    encode_header(GOAWAY, p.len() as u64, out);
    out.extend_from_slice(&p);
}

impl Connection {
    /// Server: announce shutdown with GOAWAY(2^62-4), unless a GOAWAY was already sent.
    /// Client: GOAWAY(0), a push ID (push is never enabled); requests are unaffected.
    pub fn start_shutdown(&mut self) -> Result<(), UsageError> {
        self.check_open().map_err(UsageError::Closed)?;
        match self.role {
            Role::Client => self.send_goaway(0),
            // No valid cutoff is left once the last request id was processed.
            Role::Server if self.highest_processed == Some(LAST_REQUEST) => {}
            Role::Server => self.send_goaway(LAST_REQUEST),
        }
        Ok(())
    }

    /// Server: send the actual cutoff (the request id after the highest processed one,
    /// or 0) and reject every unprocessed request at or above it. Client: as
    /// `start_shutdown`.
    pub fn finish_shutdown(&mut self) -> Result<(), UsageError> {
        self.check_open().map_err(UsageError::Closed)?;
        if self.role == Role::Client || self.highest_processed == Some(LAST_REQUEST) {
            return self.start_shutdown();
        }
        let cutoff = self.highest_processed.map_or(0, |h| h + 4);
        self.send_goaway(cutoff);
        let rejected: Vec<StreamId> = self
            .streams
            .range(StreamId(cutoff)..)
            .filter(|(s, st)| s.is_request() && !st.recv.delivered)
            .map(|(&s, _)| s)
            .collect();
        for s in rejected {
            self.reject(s);
        }
        Ok(())
    }

    /// Queue GOAWAY(`id`) on our control stream unless it would not lower the last one
    /// sent. Before the control stream is bound only the value is recorded: `bind_uni`
    /// writes GOAWAY(last sent) after SETTINGS, which supersedes any higher earlier one.
    fn send_goaway(&mut self, id: u64) {
        if self.goaway_sent.is_some_and(|last| id >= last) {
            return;
        }
        self.goaway_sent = Some(id);
        let control = self.local_uni[UniKind::Control as usize];
        if let Some(st) = control.and_then(|c| self.streams.get_mut(&c)) {
            encode_goaway(id, &mut st.send.queue);
        }
    }

    /// Server: reject unprocessed request `s` (RFC 9114 section 4.1.1).
    fn reject(&mut self, s: StreamId) {
        let code = H3Code::REQUEST_REJECTED;
        self.abort_stream(s, code, code, AbortSource::Local);
    }

    /// A GOAWAY frame carrying `id` arrived on the peer control stream.
    pub(crate) fn on_goaway(&mut self, id: u64) -> Result<(), H3Code> {
        // A client accepts only a non-increasing client bidi stream id; a server, a
        // non-increasing push ID (any value).
        let invalid = self.role == Role::Client && id % 4 != 0;
        if invalid || self.goaway_received.is_some_and(|last| id > last) {
            return Err(H3Code::ID_ERROR);
        }
        self.goaway_received = Some(id);
        self.events.push_back(Event::GoAway { id });
        if self.role == Role::Server {
            return Ok(());
        }
        // Requests without response data (a 1xx counts) will not be processed. Clients
        // must not send REQUEST_REJECTED: the wire code is REQUEST_CANCELLED.
        let doomed: Vec<StreamId> = self
            .streams
            .range(StreamId(id)..)
            .filter(|(s, st)| s.is_request() && !st.recv.delivered)
            .map(|(&s, _)| s)
            .collect();
        for s in doomed {
            self.abort_stream(
                s,
                H3Code::REQUEST_CANCELLED,
                H3Code::REQUEST_REJECTED,
                AbortSource::GoAway,
            );
        }
        Ok(())
    }

    /// Whether a new request stream may be opened (false after a peer GOAWAY).
    pub(crate) fn may_start_request(&self) -> bool {
        self.goaway_received.is_none()
    }

    /// Whether request stream `s` may deliver an item to the application. A server
    /// stream not yet processed and at or above the sent cutoff is rejected (and closed)
    /// instead: `false`.
    pub(crate) fn may_deliver(&mut self, s: StreamId) -> bool {
        let processed = self.streams.get(&s).is_some_and(|st| st.recv.delivered);
        let over = self.goaway_sent.is_some_and(|cutoff| s.0 >= cutoff);
        if self.role == Role::Server && !processed && over {
            self.reject(s);
            return false;
        }
        true
    }

    /// Something from `s` reached the application; a server request is now processed.
    pub(crate) fn mark_delivered(&mut self, s: StreamId) {
        if let Some(st) = self.streams.get_mut(&s) {
            st.recv.delivered = true;
        }
        if self.role == Role::Server {
            self.highest_processed = self.highest_processed.max(Some(s.0));
        }
    }
}
