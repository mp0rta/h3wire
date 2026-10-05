//! GOAWAY handling hooks (filled by Task 14).

use super::Connection;
use crate::error::H3Code;
use crate::stream::StreamId;

impl Connection {
    /// A GOAWAY frame carrying `id` arrived on the peer control stream.
    pub(crate) fn on_goaway(&mut self, _id: u64) -> Result<(), H3Code> {
        Ok(())
    }

    /// Whether a new request stream may be opened (false after a peer GOAWAY).
    pub(crate) fn may_start_request(&self) -> bool {
        true
    }

    /// Server: whether request stream `s` may deliver its first item to the application;
    /// `false` means the stream was rejected (and closed).
    pub(crate) fn may_deliver(&mut self, _s: StreamId) -> bool {
        true
    }
}
