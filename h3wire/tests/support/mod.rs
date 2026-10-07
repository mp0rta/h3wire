// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 mp0rta
//! In-memory fake transport and wire-building helpers shared by integration tests.
#![allow(dead_code)]

use h3wire::{
    Action, Config, Connection, Event, H3Code, HeaderBlockId, HeadersKind, Recv, Role, StreamId,
};
use std::collections::{BTreeMap, HashMap, HashSet};

pub use h3wire::__invariants::{Obs, Side};

/// Hand-built wire bytes.
pub mod wire {
    use h3wire::FieldRef;

    pub fn varint(v: u64) -> Vec<u8> {
        let mut out = Vec::new();
        h3wire::varint::encode(v, &mut out);
        out
    }

    pub fn frame(ty: u64, payload: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        h3wire::frame::encode_header(ty, payload.len() as u64, &mut out);
        out.extend_from_slice(payload);
        out
    }

    pub fn settings(params: &[(u64, u64)]) -> Vec<u8> {
        let p: Vec<u8> = params
            .iter()
            .flat_map(|&(id, v)| [varint(id), varint(v)].concat())
            .collect();
        frame(0x04, &p)
    }

    /// A HEADERS frame carrying `fields` encoded with the static-table QPACK encoder.
    pub fn headers(fields: &[(&str, &str)]) -> Vec<u8> {
        let refs: Vec<FieldRef> = fields
            .iter()
            .map(|(n, v)| FieldRef::new(n.as_bytes(), v.as_bytes()))
            .collect();
        let mut block = Vec::new();
        h3wire::qpack::encoder::encode_field_section(&refs, &mut block);
        frame(0x01, &block)
    }
}

#[derive(Default)]
pub struct Opts {
    /// Most bytes the transport accepts per write call.
    pub max_write: Option<usize>,
    /// Most bytes handed to `recv` per call.
    pub recv_chunk: Option<usize>,
    /// Streams whose writes the transport refuses.
    pub write_blocked: HashSet<(Side, StreamId)>,
}

/// A received field: name, value, never_index.
pub type Field = (Vec<u8>, Vec<u8>, bool);

/// An event with its header block resolved, so runs can be compared.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Seen {
    Headers {
        stream: StreamId,
        kind: HeadersKind,
        /// Pseudo-headers (in `:method :scheme :authority :path :protocol :status` order), then
        /// regular fields in wire order.
        fields: Vec<Field>,
    },
    Event(Event),
}

/// Resolve `block` into fields (empty once the connection closed).
pub fn resolve(c: &Connection, block: HeaderBlockId) -> Vec<Field> {
    let Ok(h) = c.headers(block) else {
        return Vec::new();
    };
    let p = h.pseudo();
    let status = p.status.map(|s| s.to_string().into_bytes());
    let pseudo = [
        (":method", p.method.map(<[u8]>::to_vec)),
        (":scheme", p.scheme.map(<[u8]>::to_vec)),
        (":authority", p.authority.map(<[u8]>::to_vec)),
        (":path", p.path.map(<[u8]>::to_vec)),
        (":protocol", p.protocol.map(<[u8]>::to_vec)),
        (":status", status),
    ];
    let pseudo = pseudo
        .into_iter()
        .filter_map(|(n, v)| Some((n.as_bytes().to_vec(), v?, false)));
    pseudo
        .chain(
            h.iter()
                .map(|f| (f.name.to_vec(), f.value.to_vec(), f.never_index)),
        )
        .collect()
}

/// `e` as a `Seen`; a header block is resolved, then released (so `recv` never pauses on it).
pub fn see(c: &mut Connection, e: Event) -> Seen {
    match e {
        Event::Headers {
            stream,
            block,
            kind,
        } => {
            let fields = resolve(c, block);
            c.release(block);
            Seen::Headers {
                stream,
                kind,
                fields,
            }
        }
        e => Seen::Event(e),
    }
}

/// One direction of one stream: bytes written but not yet consumed by the receiver.
#[derive(Default)]
struct Pipe {
    buf: Vec<u8>,
    fin: bool,
    /// FIN delivered, reset, or the receiver failed: nothing more is fed.
    done: bool,
    /// The receiver returned `Paused`; resumes on the next `drive`.
    paused: bool,
}

/// A client and a server joined by an in-memory transport.
pub struct Pair {
    pub client: Connection,
    pub server: Connection,
    pub opts: Opts,
    pub trace: Vec<Obs>,
    pub closed: Vec<(Side, H3Code)>,
    pub bodies: HashMap<(Side, StreamId), Vec<u8>>,
    /// Every byte written, keyed by writing side.
    pub wire: HashMap<(Side, StreamId), Vec<u8>>,
    /// Events resolved by `run_to_completion_resolving`, in trace order.
    pub seen: Vec<(Side, Seen)>,
    /// Trace entries already resolved into `seen`.
    resolved: usize,
    /// Indexed by receiving side.
    pipes: [BTreeMap<StreamId, Pipe>; 2],
    next_uni: [u64; 2],
    dead: [bool; 2],
}

/// Generous cap on `drive` loop iterations; hitting it means the pair never settles.
const MAX_DRIVE_ITERATIONS: usize = 1_000_000;

fn idx(side: Side) -> usize {
    match side {
        Side::Client => 0,
        Side::Server => 1,
    }
}

pub fn peer(side: Side) -> Side {
    match side {
        Side::Client => Side::Server,
        Side::Server => Side::Client,
    }
}

pub fn consumed(r: &Recv) -> usize {
    match *r {
        Recv::Consumed(n)
        | Recv::Body { consumed: n, .. }
        | Recv::Frame { consumed: n, .. }
        | Recv::Raw { consumed: n, .. } => n,
        Recv::Paused => 0,
    }
}

impl Pair {
    pub fn new(client: Config, server: Config) -> Pair {
        Pair {
            client: Connection::new(Role::Client, client),
            server: Connection::new(Role::Server, server),
            opts: Opts::default(),
            trace: Vec::new(),
            closed: Vec::new(),
            bodies: HashMap::new(),
            wire: HashMap::new(),
            seen: Vec::new(),
            resolved: 0,
            pipes: [BTreeMap::new(), BTreeMap::new()],
            next_uni: [2, 3],
            dead: [false; 2],
        }
    }

    pub fn conn(&mut self, side: Side) -> &mut Connection {
        match side {
            Side::Client => &mut self.client,
            Side::Server => &mut self.server,
        }
    }

    /// Events of one side, in order.
    pub fn events(&self, side: Side) -> Vec<Event> {
        self.trace
            .iter()
            .filter_map(|o| match o {
                Obs::Event(s, e) if *s == side => Some(*e),
                _ => None,
            })
            .collect()
    }

    /// Resolved events of one side, in order.
    pub fn seen_by(&self, side: Side) -> Vec<Seen> {
        self.seen
            .iter()
            .filter(|(s, _)| *s == side)
            .map(|(_, e)| e.clone())
            .collect()
    }

    /// Drive until quiet, resolving and releasing every header block as it shows up.
    pub fn run_to_completion_resolving(&mut self) {
        loop {
            self.drive();
            if self.resolved == self.trace.len() {
                return;
            }
            let new: Vec<(Side, Event)> = self.trace[self.resolved..]
                .iter()
                .filter_map(|o| match o {
                    Obs::Event(s, e) => Some((*s, *e)),
                    _ => None,
                })
                .collect();
            self.resolved = self.trace.len();
            for (side, e) in new {
                let seen = see(self.conn(side), e);
                self.seen.push((side, seen));
            }
        }
    }

    /// Inject raw bytes into the pipe towards `to` on stream `s`.
    pub fn feed(&mut self, to: Side, s: StreamId, bytes: &[u8], fin: bool) {
        let p = self.pipes[idx(to)].entry(s).or_default();
        p.buf.extend_from_slice(bytes);
        p.fin |= fin;
    }

    /// Run until nothing moves: actions, writes, deliveries.
    pub fn drive(&mut self) {
        for p in self.pipes.iter_mut().flat_map(|m| m.values_mut()) {
            p.paused = false;
        }
        for _ in 0..MAX_DRIVE_ITERATIONS {
            let mut progress = false;
            for side in [Side::Client, Side::Server] {
                progress |= self.flush(side);
                progress |= self.write(side);
            }
            for side in [Side::Client, Side::Server] {
                progress |= self.deliver(side);
            }
            if !progress {
                h3wire::__invariants::check(&self.trace).unwrap();
                return;
            }
        }
        panic!("drive: livelock, still progressing after {MAX_DRIVE_ITERATIONS} iterations");
    }

    /// A transport write by `from` on `s`; writing after FIN is a bug in the core.
    fn transmit(&mut self, from: Side, s: StreamId, bytes: &[u8]) {
        let p = self.pipes[idx(peer(from))].entry(s).or_default();
        assert!(!p.fin, "{from:?} wrote on {s:?} after FinishStream");
        p.buf.extend_from_slice(bytes);
        self.wire
            .entry((from, s))
            .or_default()
            .extend_from_slice(bytes);
    }

    /// `send_data` plus a scatter write of prefix and payload honoring `max_write`.
    pub fn send_body(&mut self, side: Side, s: StreamId, payload: &[u8], end: bool) {
        let f = self
            .conn(side)
            .send_data(s, payload.len() as u64, end)
            .unwrap();
        let all = [f.prefix(), payload].concat();
        let max = self.opts.max_write.unwrap_or(usize::MAX).max(1);
        for chunk in all.chunks(max) {
            self.transmit(side, s, chunk);
            self.conn(side).data_written(s, chunk.len()).unwrap();
        }
    }

    /// Record pending events and record + execute pending actions of `side`.
    fn flush(&mut self, side: Side) -> bool {
        let mut progress = false;
        while let Some(e) = self.conn(side).poll_event() {
            if matches!(e, Event::Closed { .. }) {
                self.dead[idx(side)] = true;
            }
            self.trace.push(Obs::Event(side, e));
            progress = true;
        }
        while let Some(a) = self.conn(side).poll_action() {
            self.trace.push(Obs::Action(side, a));
            self.execute(side, a);
            progress = true;
        }
        progress
    }

    fn execute(&mut self, side: Side, a: Action) {
        let other = peer(side);
        match a {
            Action::OpenUni(kind) => {
                let id = StreamId(self.next_uni[idx(side)]);
                self.next_uni[idx(side)] += 4;
                let r = self.conn(side).bind_uni(kind, id);
                if !self.dead[idx(side)] {
                    r.unwrap();
                }
            }
            Action::FinishStream(s) => {
                assert!(
                    self.conn(side).poll_send(s).is_none(),
                    "{side:?} FinishStream({s:?}) with core-owned bytes still queued"
                );
                let p = self.pipes[idx(other)].entry(s).or_default();
                assert!(!p.fin, "{side:?} FinishStream({s:?}) twice");
                p.fin = true;
            }
            Action::ResetStream { stream, code } => {
                let p = self.pipes[idx(other)].entry(stream).or_default();
                p.buf.clear();
                p.done = true;
                let _ = self.conn(other).stream_reset_received(stream, code);
            }
            Action::StopSending { stream, code } => {
                let _ = self.conn(other).stop_sending_received(stream, code);
            }
            Action::CloseConnection { code, .. } => {
                self.closed.push((side, code));
                self.dead = [true; 2];
                self.conn(other).transport_closed();
            }
        }
    }

    /// One write per sendable stream, at most `max_write` bytes.
    fn write(&mut self, side: Side) -> bool {
        let max = self.opts.max_write.unwrap_or(usize::MAX).max(1);
        let ids: Vec<StreamId> = self.conn(side).sendable().collect();
        let mut progress = false;
        for s in ids {
            if self.opts.write_blocked.contains(&(side, s)) {
                continue;
            }
            let Some(bytes) = self.conn(side).poll_send(s) else {
                continue;
            };
            let chunk = bytes[..bytes.len().min(max)].to_vec();
            self.transmit(side, s, &chunk);
            self.conn(side).sent(s, chunk.len()).unwrap();
            progress = true;
        }
        progress
    }

    /// One `recv` per live pipe towards `side`, at most `recv_chunk` bytes.
    fn deliver(&mut self, side: Side) -> bool {
        if self.dead[idx(side)] {
            return false;
        }
        let max = self.opts.recv_chunk.unwrap_or(usize::MAX).max(1);
        let ids: Vec<StreamId> = self.pipes[idx(side)].keys().copied().collect();
        let mut progress = false;
        for s in ids {
            if self.dead[idx(side)] {
                break;
            }
            let p = &self.pipes[idx(side)][&s];
            if p.done || p.paused || (p.buf.is_empty() && !p.fin) {
                continue;
            }
            let chunk = p.buf[..p.buf.len().min(max)].to_vec();
            let fin = p.fin && chunk.len() == p.buf.len();
            let r = self.conn(side).recv(s, &chunk, fin);
            let p = self.pipes[idx(side)].get_mut(&s).unwrap();
            let Ok(r) = r else {
                p.done = true;
                progress = true;
                continue;
            };
            if r == Recv::Paused {
                p.paused = true;
                continue;
            }
            let n = consumed(&r);
            assert!(n > 0 || chunk.is_empty(), "recv made no progress on {s:?}");
            assert!(
                n <= chunk.len(),
                "recv consumed {n} of {} on {s:?}",
                chunk.len()
            );
            p.buf.drain(..n);
            if fin && n == chunk.len() {
                p.done = true;
            }
            progress = true;
            match r {
                Recv::Body { range, .. } => {
                    let len = range.len();
                    self.trace.push(Obs::Body {
                        side,
                        stream: s,
                        len,
                    });
                    self.bodies
                        .entry((side, s))
                        .or_default()
                        .extend_from_slice(&chunk[range]);
                }
                Recv::Raw { range, .. } => self
                    .bodies
                    .entry((side, s))
                    .or_default()
                    .extend_from_slice(&chunk[range]),
                Recv::Frame { .. } => self.trace.push(Obs::Frame { side, stream: s }),
                _ => {}
            }
            self.flush(side);
        }
        progress
    }
}

/// Feed `bytes` to `c` on `s`, re-feeding the unconsumed remainder until all is consumed.
pub fn feed_all(c: &mut Connection, s: StreamId, bytes: &[u8], fin: bool) {
    let mut rest = bytes;
    loop {
        let r = c.recv(s, rest, fin).unwrap();
        assert!(r != Recv::Paused, "feed_all: recv paused on {s:?}");
        let n = consumed(&r);
        assert!(
            n <= rest.len(),
            "recv consumed {n} of {} on {s:?}",
            rest.len()
        );
        assert!(n > 0 || rest.is_empty(), "recv made no progress on {s:?}");
        rest = &rest[n..];
        if rest.is_empty() {
            break;
        }
    }
}

fn ready(role: Role, cfg: Config, peer_params: &[(u64, u64)]) -> Connection {
    let mut c = Connection::new(role, cfg);
    let (mut next, peer_control) = match role {
        Role::Client => (2, StreamId(3)),
        Role::Server => (3, StreamId(2)),
    };
    while let Some(a) = c.poll_action() {
        if let Action::OpenUni(kind) = a {
            c.bind_uni(kind, StreamId(next)).unwrap();
            next += 4;
        }
    }
    let ids: Vec<StreamId> = c.sendable().collect();
    for s in ids {
        let n = c.poll_send(s).map_or(0, <[u8]>::len);
        c.sent(s, n).unwrap();
    }
    let control = [&[0x00][..], &wire::settings(peer_params)].concat();
    feed_all(&mut c, peer_control, &control, false);
    while c.poll_event().is_some() || c.poll_action().is_some() {}
    c
}

/// A server whose uni streams are bound and written and whose peer SETTINGS (empty) arrived.
pub fn server_ready(cfg: Config) -> Connection {
    ready(Role::Server, cfg, &[])
}

/// Like `server_ready`, with the client's SETTINGS carrying `peer`.
pub fn server_ready_with(cfg: Config, peer: &[(u64, u64)]) -> Connection {
    ready(Role::Server, cfg, peer)
}

/// A client whose uni streams are bound and written and whose peer SETTINGS (empty) arrived.
pub fn client_ready(cfg: Config) -> Connection {
    client_ready_with(cfg, &[])
}

/// Like `client_ready`, with the server's SETTINGS carrying `peer`.
pub fn client_ready_with(cfg: Config, peer: &[(u64, u64)]) -> Connection {
    ready(Role::Client, cfg, peer)
}
