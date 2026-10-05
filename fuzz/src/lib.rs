//! Shared driver for the connection-level fuzz targets (`wire`, `api_ops`).

use h3wire::__invariants::{Obs, Side, check};
use h3wire::{
    Config, Connection, Contexts, Datagram, Event, FrameExtension, H3Code, HeaderBlockId, Recv,
    Role, StreamId,
};

/// Stream ids the fuzz inputs address: request streams, then both roles' uni streams.
pub const IDS: [u64; 9] = [0, 4, 8, 2, 3, 6, 7, 10, 11];

pub fn id(i: u8) -> StreamId {
    StreamId(IDS[usize::from(i) % IDS.len()])
}

/// Every feature on, so extension paths are reachable.
pub fn config() -> Config {
    let mut c = Config::default();
    c.enable_connect_protocol = true;
    c.h3_datagram = true;
    let contexts = Contexts::REQUEST | Contexts::RESPONSE | Contexts::TUNNEL;
    c.register_frame(FrameExtension { ty: 0x30, contexts })
        .unwrap();
    c.register_uni_stream(0x54).unwrap();
    c
}

/// One connection plus everything observed from it.
pub struct Peer {
    pub conn: Connection,
    pub side: Side,
    pub trace: Vec<Obs>,
    /// Every header block delivered, in order.
    pub blocks: Vec<HeaderBlockId>,
    /// Release each block as soon as it is delivered.
    pub auto_release: bool,
}

impl Peer {
    pub fn new(role: Role, auto_release: bool) -> Peer {
        let side = match role {
            Role::Client => Side::Client,
            Role::Server => Side::Server,
        };
        Peer {
            conn: Connection::new(role, config()),
            side,
            trace: Vec::new(),
            blocks: Vec::new(),
            auto_release,
        }
    }

    /// Record every pending event and action; read (and maybe release) header blocks.
    pub fn drain(&mut self) {
        while let Some(e) = self.conn.poll_event() {
            if let Event::Headers { block, .. } = e {
                if let Ok(h) = self.conn.headers(block) {
                    let _ = (h.pseudo(), h.iter().count());
                }
                self.blocks.push(block);
                if self.auto_release {
                    self.conn.release(block);
                }
            }
            self.trace.push(Obs::Event(self.side, e));
        }
        while let Some(a) = self.conn.poll_action() {
            self.trace.push(Obs::Action(self.side, a));
        }
    }

    /// Feed `bytes` on `s` until consumed, paused, or the connection fails.
    pub fn recv(&mut self, s: StreamId, bytes: &[u8], fin: bool) {
        let mut rest = bytes;
        while let Ok(r) = self.conn.recv(s, rest, fin) {
            let paused = r == Recv::Paused;
            let n = match r {
                Recv::Consumed(n) | Recv::Raw { consumed: n, .. } => n,
                Recv::Body { consumed, range } => {
                    assert!(range.end <= consumed);
                    let (side, stream, len) = (self.side, s, range.len());
                    self.trace.push(Obs::Body { side, stream, len });
                    consumed
                }
                Recv::Frame {
                    consumed, range, ..
                } => {
                    assert!(range.end <= consumed);
                    self.trace.push(Obs::Frame {
                        side: self.side,
                        stream: s,
                    });
                    consumed
                }
                Recv::Paused => 0,
            };
            assert!(n <= rest.len(), "consumed {n} of {}", rest.len());
            rest = &rest[n..];
            self.drain();
            if paused {
                // Only an unreleased block pauses a stream.
                assert!(!self.auto_release, "paused with every block released");
                break;
            }
            if rest.is_empty() {
                break;
            }
            assert!(n > 0, "recv made no progress");
        }
        self.drain();
    }

    pub fn reset(&mut self, s: StreamId, code: u16) {
        let _ = self.conn.stream_reset_received(s, H3Code(code.into()));
        self.drain();
    }

    pub fn stop_sending(&mut self, s: StreamId, code: u16) {
        let _ = self.conn.stop_sending_received(s, H3Code(code.into()));
        self.drain();
    }

    pub fn datagram(&mut self, payload: &[u8]) {
        if let Ok(Datagram::Deliver(_, r) | Datagram::NotYetOpen(_, r)) =
            self.conn.parse_datagram(payload)
        {
            assert!(r.start <= r.end && r.end == payload.len());
        }
        self.drain();
    }

    /// The trace invariants and the memory bound hold.
    pub fn check(&self) {
        check(&self.trace).unwrap();
        let (used, bound) = (self.conn.debug_buffered_bytes(), self.conn.debug_bound());
        assert!(used <= bound, "buffered {used} > bound {bound}");
    }
}
