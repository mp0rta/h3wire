//! Stream identifiers and per-stream state.

/// A QUIC stream id.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct StreamId(pub u64);

impl StreamId {
    pub fn is_uni(self) -> bool {
        self.0 & 0x2 != 0
    }

    pub fn is_client_initiated(self) -> bool {
        self.0 & 0x1 == 0
    }

    /// Client-initiated bidirectional: a request stream.
    pub fn is_request(self) -> bool {
        self.0 % 4 == 0
    }
}

/// The local unidirectional streams the core opens via `Action::OpenUni`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum UniKind {
    Control,
    QpackEncoder,
    QpackDecoder,
}

/// Per-stream state kept by the connection.
#[derive(Default)]
pub(crate) struct Stream {
    pub send: SendState,
    pub recv: RecvState,
}

/// Receive side of a request stream.
#[derive(Default)]
pub(crate) struct RecvState {
    /// Client only: our request was HEAD, so the response carries no content.
    pub expects_no_content: bool,
    pub tunnel: TunnelState,
}

/// CONNECT tracking (spec §2.3).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) enum TunnelState {
    #[default]
    Regular,
    ConnectPending,
    Tunnel,
}

/// Send side: core-owned bytes not yet accepted by the transport, plus the DATA frame in flight.
#[derive(Default)]
pub(crate) struct SendState {
    pub queue: Vec<u8>,
    /// Bytes of `queue` already accepted by the transport.
    pub read: usize,
    pub phase: SendPhase,
    pub in_flight: Option<InFlight>,
    /// Server: the request was HEAD (set on receive), so the response has no content.
    pub request_is_head: bool,
    /// Server: the final response status is 204 or 304.
    pub no_content_status: bool,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) enum SendPhase {
    #[default]
    Idle,
    Headers,
    Body,
    Tunnel,
    Trailers,
    /// A call with `end = true` was accepted; FIN follows once drained.
    Ending,
    /// `Action::FinishStream` queued.
    Done,
}

/// A DATA frame (prefix + payload) handed out by `send_data` and not yet fully written.
pub(crate) struct InFlight {
    /// Prefix plus payload length.
    pub frame_len: u64,
    pub written: u64,
}

impl SendState {
    /// Core-owned bytes the transport may take now; empty while DATA is in flight.
    pub fn pending(&self) -> &[u8] {
        if self.in_flight.is_some() {
            return &[];
        }
        self.queue.get(self.read..).unwrap_or_default()
    }

    /// Nothing core-owned left to write: no queued bytes, no DATA in flight.
    pub fn drained(&self) -> bool {
        self.in_flight.is_none() && self.queue.is_empty()
    }

    /// Mark `n` pending bytes as written; the caller checked `n <= pending().len()`.
    pub fn advance(&mut self, n: usize) {
        self.read += n;
        if self.read == self.queue.len() {
            self.queue.clear();
            self.read = 0;
        }
    }
}
