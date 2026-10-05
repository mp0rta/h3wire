//! Stream identifiers and per-stream state.

use crate::frame::{FrameHeader, FrameHeaderParser};
use crate::headers::HeaderBlockId;

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
    /// `Finished` or `StreamAborted` was emitted (independent of directional closure).
    pub terminal_emitted: bool,
}

/// Receive side of a request stream.
#[derive(Default)]
pub(crate) struct RecvState {
    pub parser: FrameHeaderParser,
    /// The frame being read and its payload bytes still to come.
    pub cur: Option<(FrameHeader, u64)>,
    pub phase: RecvPhase,
    /// Payload of the HEADERS frame being read; bounded at frame-header parse.
    pub headers_buf: Vec<u8>,
    /// The last delivered block until the application releases it (backpressure).
    pub unreleased: Option<HeaderBlockId>,
    /// From the request or final response (never from trailers).
    pub content_length: Option<u64>,
    pub data_received: u64,
    pub tunnel: TunnelState,
    /// Client only: the response carries no content (request was HEAD, or status 204/304).
    pub expects_no_content: bool,
    /// Something reached the application (decoded HEADERS or an extension frame piece).
    pub delivered: bool,
    /// Receive side ended: `Finished`, FIN at a stream error, or aborted.
    pub closed: bool,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) enum RecvPhase {
    #[default]
    AwaitHeaders,
    AfterInformational,
    Body,
    AfterTrailers,
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

impl Stream {
    /// A final response was sent (server) or received (client) (spec section 2.3): on a
    /// CONNECT stream 2xx enters the tunnel, anything else returns to a regular message.
    pub fn connect_final(&mut self, success: bool) {
        if self.recv.tunnel != TunnelState::ConnectPending {
            return;
        }
        if success {
            self.enter_tunnel();
        } else {
            self.recv.tunnel = TunnelState::Regular;
        }
    }

    /// Content-Length checks stop; a send side still in `Body` moves to `Tunnel`
    /// (one already `Ending`/`Done` is left alone).
    fn enter_tunnel(&mut self) {
        self.recv.tunnel = TunnelState::Tunnel;
        if self.send.phase == SendPhase::Body {
            self.send.phase = SendPhase::Tunnel;
        }
    }
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

    /// Sending is over (reset or stopped): queued bytes and in-flight DATA are dropped.
    pub fn stop(&mut self) {
        *self = SendState {
            phase: SendPhase::Done,
            ..SendState::default()
        };
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
