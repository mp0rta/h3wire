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

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Role {
    Client,
    Server,
}

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

    pub fn poll_event(&mut self) -> Option<Event> {
        self.events.pop_front()
    }

    pub fn poll_action(&mut self) -> Option<Action> {
        self.actions.pop_front()
    }

    pub fn peer_settings(&self) -> Option<&PeerSettings> {
        self.peer_settings.as_ref()
    }

    pub fn headers(&self, b: HeaderBlockId) -> Result<HeaderBlockRef<'_>, UsageError> {
        self.check_open().map_err(UsageError::Closed)?;
        self.blocks.get(b)
    }

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
