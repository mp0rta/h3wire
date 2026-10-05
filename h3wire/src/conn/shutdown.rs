//! GOAWAY handling hooks (filled by Task 14).

use super::Connection;
use crate::error::H3Code;

impl Connection {
    /// A GOAWAY frame carrying `id` arrived on the peer control stream.
    pub(crate) fn on_goaway(&mut self, _id: u64) -> Result<(), H3Code> {
        Ok(())
    }
}
