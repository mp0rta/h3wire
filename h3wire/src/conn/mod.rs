// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 mp0rta
//! The HTTP/3 connection state machine.

mod abort;
mod datagram;
mod recv_req;
mod recv_uni;
mod send;
mod shutdown;

use crate::config::Config;
use crate::error::{ConnectionError, H3Code, UsageError};
use crate::event::{Action, Event, Recv};
use crate::headers::{BlockStore, HeaderBlockId, HeaderBlockRef};
use crate::settings::PeerSettings;
use crate::stream::{Stream, StreamId, UniKind};
use recv_uni::PeerUni;
use std::collections::hash_map::RandomState;
use std::collections::{BTreeMap, HashMap, VecDeque};
use std::hash::BuildHasher;
use std::ops::Range;

/// Which end of the QUIC connection this is.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Role {
    /// Opens request streams.
    Client,
    /// Answers them.
    Server,
}

/// The HTTP/3 state of one QUIC connection. See the [crate docs](crate) for the driving
/// loop and the caller contracts.
///
/// Once closed (a connection error, which queues [`Action::CloseConnection`], or
/// [`Connection::transport_closed`]) it never recovers: [`Connection::poll_event`],
/// [`Connection::poll_action`] and [`Connection::peer_settings`] keep working so the caller
/// can drain them, and every other call returns `Err(Closed(code))` (or nothing).
pub struct Connection {
    role: Role,
    config: Config,
    grease_seed: u64,
    events: VecDeque<Event>,
    actions: VecDeque<Action>,
    streams: BTreeMap<StreamId, Stream>,
    /// Reaped request stream ids: sorted, disjoint, adjacent ranges merged (ids step by 4).
    closed_ids: Vec<Range<u64>>,
    blocks: BlockStore,
    /// Request stream of each delivered block, so `release` can lift that stream's pause.
    block_stream: HashMap<HeaderBlockId, StreamId>,
    peer_settings: Option<PeerSettings>,
    /// Local uni streams, indexed by `UniKind as usize`.
    local_uni: [Option<StreamId>; 3],
    /// Bytes of the control stream (type + SETTINGS) not yet accepted by the transport.
    settings_left: usize,
    local_settings_sent: bool,
    /// Set once by `close_with` or `transport_closed` (never recovers).
    closed: Option<H3Code>,
    peer_uni: BTreeMap<StreamId, PeerUni>,
    /// Peer critical streams seen, indexed by `UniKind as usize`.
    peer_critical: [bool; 3],
    /// Largest MAX_PUSH_ID received (server); push itself stays disabled.
    max_push_id: Option<u64>,
    /// Id of the last GOAWAY we sent (never increases).
    goaway_sent: Option<u64>,
    /// Id of the last GOAWAY the peer sent.
    goaway_received: Option<u64>,
    /// Server: the highest processed request id (see `mark_delivered`).
    highest_processed: Option<u64>,
    /// Largest `closed_ids.len()` ever: merging ranges does not shrink the capacity.
    peak_closed_ranges: usize,
}

impl Connection {
    /// A new connection. Queues [`Action::OpenUni`] for the control and QPACK
    /// encoder/decoder streams; SETTINGS go out once the control stream is bound.
    pub fn new(role: Role, config: Config) -> Connection {
        let actions = [
            UniKind::Control,
            UniKind::QpackEncoder,
            UniKind::QpackDecoder,
        ]
        .map(Action::OpenUni);
        Connection {
            role,
            config,
            grease_seed: RandomState::new().hash_one(0u8),
            events: VecDeque::new(),
            actions: VecDeque::from(actions),
            streams: BTreeMap::new(),
            closed_ids: Vec::new(),
            blocks: BlockStore::default(),
            block_stream: HashMap::new(),
            peer_settings: None,
            local_uni: [None; 3],
            settings_left: 0,
            local_settings_sent: false,
            closed: None,
            peer_uni: BTreeMap::new(),
            peer_critical: [false; 3],
            max_push_id: None,
            goaway_sent: None,
            goaway_received: None,
            highest_processed: None,
            peak_closed_ranges: 0,
        }
    }

    /// The next event for the application, in order.
    pub fn poll_event(&mut self) -> Option<Event> {
        self.events.pop_front()
    }

    /// The next action for the transport, in order. Execute each one; after a connection
    /// error, the queued [`Action::CloseConnection`] is the only thing that closes the QUIC
    /// connection.
    pub fn poll_action(&mut self) -> Option<Action> {
        self.actions.pop_front()
    }

    /// The peer's SETTINGS, once [`Event::PeerSettings`] was emitted.
    pub fn peer_settings(&self) -> Option<&PeerSettings> {
        self.peer_settings.as_ref()
    }

    /// Read a delivered header block. It stays readable after its stream finished or was
    /// aborted, until [`Connection::release`]. `Err(StaleBlock)` once released;
    /// `Err(Closed)` once the connection is closed (every block is freed then).
    pub fn headers(&self, b: HeaderBlockId) -> Result<HeaderBlockRef<'_>, UsageError> {
        self.check_open().map_err(UsageError::Closed)?;
        self.blocks.get(b)
    }

    /// Free a header block. A stream holds at most one unreleased block: its next HEADERS
    /// is not decoded until then ([`Recv::Paused`]); feed the stream again after this.
    /// Releasing a stale block is a no-op.
    pub fn release(&mut self, b: HeaderBlockId) {
        if self.check_open().is_err() {
            return;
        }
        self.blocks.release(b);
        // The stream may be gone or aborted already; that is fine.
        if let Some(s) = self.block_stream.remove(&b) {
            if let Some(st) = self.streams.get_mut(&s) {
                if st.recv.unreleased == Some(b) {
                    st.recv.unreleased = None;
                }
            }
        }
    }

    /// Whether `s` is initiated by this endpoint.
    fn is_local(&self, s: StreamId) -> bool {
        s.is_client_initiated() == (self.role == Role::Client)
    }

    /// Feed bytes received on stream `s` (`fin`: the peer's FIN follows them).
    ///
    /// Progress contract:
    /// - Each call consumes a prefix of `bytes` (the `consumed` count of the result); the
    ///   caller re-feeds the rest on a later call.
    /// - `fin` counts only on a call that consumes all of `bytes`; an empty `bytes` with
    ///   `fin = true` is valid (a bare FIN).
    /// - `Consumed(0)` is returned only for empty `bytes`; every other result makes
    ///   progress, except [`Recv::Paused`]: then stop feeding this stream until the
    ///   [`release`](Connection::release) of its unreleased block, and feed the same bytes
    ///   again.
    /// - A call returns at most one application-visible item: it stops right after a
    ///   decoded HEADERS block, so the [`Event::Headers`] comes before what follows.
    ///
    /// Peer control and QPACK streams (and registered uni stream types) always consume
    /// everything; read them eagerly, independently of application demand. Bytes on a
    /// stream that was aborted or finished are consumed and discarded.
    ///
    /// `Err` means the connection is closed (by this call, which then queued
    /// [`Action::CloseConnection`], or earlier).
    pub fn recv(&mut self, s: StreamId, bytes: &[u8], fin: bool) -> Result<Recv, ConnectionError> {
        self.check_open().map_err(ConnectionError::Closed)?;
        if s.is_uni() {
            if self.is_local(s) {
                // Our own send-only stream: caller misuse, ignored.
                return Ok(Recv::Consumed(bytes.len()));
            }
            return self.recv_uni(s, bytes, fin);
        }
        if self.role == Role::Client && !s.is_client_initiated() {
            return Err(self.close_with(
                H3Code::STREAM_CREATION_ERROR,
                "server-initiated bidirectional stream",
            ));
        }
        self.recv_req(s, bytes, fin)
    }

    /// Heap bytes held by the connection's buffers: decoded header blocks, per-stream
    /// HEADERS payloads and send queues, peer control/QPACK stream buffers and the
    /// reaped-id ranges.
    #[doc(hidden)]
    pub fn debug_buffered_bytes(&self) -> usize {
        let streams: usize = self
            .streams
            .values()
            .map(|st| st.recv.headers_buf.capacity() + st.send.queue.capacity())
            .sum();
        let uni: usize = self.peer_uni.values().map(PeerUni::buffered_bytes).sum();
        let closed = self.closed_ids.capacity() * size_of::<Range<u64>>();
        self.blocks.buffered_bytes() + streams + uni + closed
    }

    /// Entries in the stream map: live request streams plus the bound local uni streams
    /// (control, QPACK encoder/decoder). Peer uni stream state is kept apart.
    #[doc(hidden)]
    pub fn debug_stream_count(&self) -> usize {
        self.streams.len()
    }

    /// Ranges in the reaped-id history.
    #[doc(hidden)]
    pub fn debug_closed_ranges(&self) -> usize {
        self.closed_ids.len()
    }

    /// Upper bound for `debug_buffered_bytes` (factors of 2 cover `Vec` capacity doubling).
    ///
    /// A decoded section of `E` encoded bytes needs at most `8/5 E` arena bytes (Huffman)
    /// and `E` fields (one per encoded byte); a HEADERS payload is at most `E` and a
    /// buffered control frame at most `C`; a send queue frees its buffer once drained,
    /// so its capacity is at most twice the bytes it holds (or 8, within the per-stream
    /// slack).
    #[doc(hidden)]
    pub fn debug_bound(&self) -> usize {
        let e = self.config.max_encoded_field_section_size;
        let c = self.config.max_control_frame_size;
        let field = size_of::<crate::qpack::decoder::DecodedField>();
        let slot = e.saturating_mul(2).saturating_add(e.saturating_mul(field));
        let range = size_of::<Range<u64>>();
        [
            self.blocks.slots().saturating_mul(slot.saturating_mul(2)),
            self.streams
                .len()
                .saturating_mul(e.saturating_add(64).saturating_mul(2)),
            c.saturating_mul(2),
            self.streams
                .values()
                .map(|st| st.send.queue.len())
                .fold(0, usize::saturating_add)
                .saturating_mul(2),
            self.peak_closed_ranges.saturating_mul(2 * range),
            1 << 20,
        ]
        .into_iter()
        .fold(0, usize::saturating_add)
    }
}
