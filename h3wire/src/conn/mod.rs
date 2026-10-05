//! The HTTP/3 connection state machine.

mod abort;
mod recv_req;
mod recv_uni;
mod send;
mod shutdown;

use crate::config::Config;
use crate::error::{ConnectionError, H3Code, UsageError};
use crate::event::{Action, Datagram, Event, Recv};
use crate::headers::{BlockStore, HeaderBlockId, HeaderBlockRef};
use crate::settings::PeerSettings;
use crate::stream::{Stream, StreamId, UniKind};
use recv_uni::PeerUni;
use std::collections::hash_map::RandomState;
use std::collections::{BTreeMap, HashMap, VecDeque};
use std::hash::BuildHasher;

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
    blocks: BlockStore,
    /// Request stream of each delivered block, so `release` can lift that stream's pause.
    block_stream: HashMap<HeaderBlockId, StreamId>,
    peer_settings: Option<PeerSettings>,
    /// Local uni streams, indexed by `UniKind as usize`.
    local_uni: [Option<StreamId>; 3],
    /// Bytes of the control stream (type + SETTINGS) not yet accepted by the transport.
    settings_left: usize,
    local_settings_sent: bool,
    /// Set once by `close_with` (never recovers).
    closed: Option<H3Code>,
    peer_uni: BTreeMap<StreamId, PeerUni>,
    /// Peer critical streams seen, indexed by `UniKind as usize`.
    peer_critical: [bool; 3],
    /// Largest MAX_PUSH_ID received (server); push itself stays disabled.
    max_push_id: Option<u64>,
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

    // Stubs below: final signatures, bodies filled by later tasks.

    pub fn abort(&mut self, _s: StreamId, _code: H3Code) -> Result<(), UsageError> {
        self.check_open().map_err(UsageError::Closed)?;
        Err(UsageError::WrongPhase)
    }

    pub fn start_shutdown(&mut self) -> Result<(), UsageError> {
        self.check_open().map_err(UsageError::Closed)?;
        Err(UsageError::WrongPhase)
    }

    pub fn finish_shutdown(&mut self) -> Result<(), UsageError> {
        self.check_open().map_err(UsageError::Closed)?;
        Err(UsageError::WrongPhase)
    }

    pub fn datagram_prefix(&self, _s: StreamId, _buf: &mut [u8; 8]) -> Result<usize, UsageError> {
        self.check_open().map_err(UsageError::Closed)?;
        Err(UsageError::NotNegotiated)
    }

    pub fn parse_datagram(&mut self, _payload: &[u8]) -> Result<Datagram, ConnectionError> {
        self.check_open().map_err(ConnectionError::Closed)?;
        Ok(Datagram::Drop)
    }

    #[doc(hidden)]
    pub fn debug_buffered_bytes(&self) -> usize {
        0
    }

    #[doc(hidden)]
    pub fn debug_bound(&self) -> usize {
        usize::MAX
    }
}
