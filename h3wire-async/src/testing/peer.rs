// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 mp0rta
//! `CorePeer`: a raw core `Connection` driven over any transport, as in the core's
//! rustdoc driving loop. Std only.

use crate::quic::{Connection as Quic, ReadError, RecvStream, SendStream, WriteError};
use bytes::Bytes;
use h3wire::frame::FrameHeaderParser;
use h3wire::{
    Action, Config, Connection, Datagram, Event, FieldRef, H3Code, HeaderBlockId, Recv, Role,
    StreamId, UniKind, UsageError,
};
use std::collections::{HashMap, HashSet, VecDeque};
use std::future::poll_fn;
use std::task::{Context, Poll};

/// One observation of a [`CorePeer`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PeerObs {
    /// A core event.
    Event(Event),
    /// A core action, as executed.
    Action(Action),
    /// A frame header received on a request stream.
    Frame {
        /// The stream.
        stream: StreamId,
        /// The frame type.
        ty: u64,
    },
    /// Body bytes delivered by the core (one `Recv::Body`).
    Body {
        /// The stream.
        stream: StreamId,
        /// Payload length.
        len: usize,
    },
    /// An HTTP datagram for a request stream.
    Datagram {
        /// The stream.
        stream: StreamId,
        /// Payload length.
        len: usize,
    },
}

/// Per-stream raw outgoing state.
#[derive(Default)]
struct Out {
    /// Body pieces not yet framed: `(payload, end)`.
    body: VecDeque<(Bytes, bool)>,
    /// The DATA frame being written: prefix and payload, fully written ones removed.
    frame: Vec<Bytes>,
    /// Raw bytes, written once the core has nothing queued on the stream.
    raw: VecDeque<Bytes>,
}

/// A raw core [`Connection`] driven over the transport `C`; test peer for the driver.
pub struct CorePeer<C: Quic> {
    conn: C,
    core: Connection,
    role: Role,
    sends: HashMap<StreamId, C::Send>,
    recvs: HashMap<StreamId, C::Recv>,
    /// Send halves the peer stopped: reported to the core once, never written again.
    stopped: HashSet<StreamId>,
    /// Received bytes the core has not consumed (it paused), with FIN.
    inbox: HashMap<StreamId, (Vec<u8>, bool)>,
    out: HashMap<StreamId, Out>,
    /// Frame skimmer per request stream: header parser and payload bytes left.
    skim: HashMap<StreamId, (FrameHeaderParser, u64)>,
    open_uni: VecDeque<UniKind>,
    defer_control: bool,
    deferred: Option<UniKind>,
    hold: bool,
    held: Vec<HeaderBlockId>,
    dead: bool,
    trace: Vec<PeerObs>,
    bodies: HashMap<StreamId, Vec<u8>>,
    heads: HashMap<StreamId, Vec<Vec<(String, String)>>>,
}

impl<C: Quic> std::fmt::Debug for CorePeer<C> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CorePeer")
            .field("role", &self.role)
            .finish_non_exhaustive()
    }
}

impl<C: Quic> CorePeer<C> {
    /// A peer of `role` over `conn`.
    pub fn new(role: Role, config: Config, conn: C) -> Self {
        CorePeer {
            conn,
            core: Connection::new(role, config),
            role,
            sends: HashMap::new(),
            recvs: HashMap::new(),
            stopped: HashSet::new(),
            inbox: HashMap::new(),
            out: HashMap::new(),
            skim: HashMap::new(),
            open_uni: VecDeque::new(),
            defer_control: false,
            deferred: None,
            hold: false,
            held: Vec::new(),
            dead: false,
            trace: Vec::new(),
            bodies: HashMap::new(),
            heads: HashMap::new(),
        }
    }

    /// The core connection.
    pub fn core(&self) -> &Connection {
        &self.core
    }

    /// Everything observed so far, in order.
    pub fn trace(&self) -> &[PeerObs] {
        &self.trace
    }

    /// Body bytes received on `s`.
    pub fn body(&self, s: StreamId) -> Vec<u8> {
        self.bodies.get(&s).cloned().unwrap_or_default()
    }

    /// Header blocks received on `s` (pseudo-headers included), in order.
    pub fn headers(&self, s: StreamId) -> Vec<Vec<(String, String)>> {
        self.heads.get(&s).cloned().unwrap_or_default()
    }

    /// Hold back the control stream (open it with [`Self::bind_control_now`]). Set it
    /// before the first step.
    pub fn defer_control(&mut self, on: bool) {
        self.defer_control = on;
    }

    /// Open and bind a deferred control stream on the next step.
    pub fn bind_control_now(&mut self) {
        self.defer_control = false;
        self.open_uni.extend(self.deferred.take());
    }

    /// Keep received header blocks unreleased (the stream pauses at its next HEADERS).
    pub fn hold_release(&mut self, on: bool) {
        self.hold = on;
    }

    /// Release every held header block.
    pub fn release_all(&mut self) {
        for b in self.held.drain(..) {
            self.core.release(b);
        }
    }

    /// Queue a HEADERS frame through the core.
    pub fn send_headers(
        &mut self,
        s: StreamId,
        fields: &[(&str, &str)],
        end: bool,
    ) -> Result<(), UsageError> {
        let f: Vec<FieldRef> = fields
            .iter()
            .map(|(n, v)| FieldRef::new(n.as_bytes(), v.as_bytes()))
            .collect();
        self.core.send_headers(s, &f, end)
    }

    /// Queue body bytes as one DATA frame (`end`: FIN after it; empty + `end` is FIN only).
    pub fn send_body(&mut self, s: StreamId, data: &[u8], end: bool) {
        let o = self.out.entry(s).or_default();
        o.body.push_back((Bytes::copy_from_slice(data), end));
    }

    /// Queue raw bytes on `s`, bypassing the core; each call is its own transport chunk.
    pub fn send_raw(&mut self, s: StreamId, data: &[u8]) {
        let o = self.out.entry(s).or_default();
        o.raw.push_back(Bytes::copy_from_slice(data));
    }

    /// QUIC STOP_SENDING on `s`, bypassing the core.
    pub fn stop_sending(&mut self, s: StreamId, code: H3Code) {
        if let Some(mut r) = self.recvs.remove(&s) {
            r.stop(code.0);
        }
    }

    /// QUIC RESET_STREAM on `s`, bypassing the core.
    pub fn reset(&mut self, s: StreamId, code: H3Code) {
        if let Some(mut w) = self.sends.remove(&s) {
            w.reset(code.0);
        }
    }

    /// Abort `s` through the core (both directions).
    pub fn abort(&mut self, s: StreamId, code: H3Code) -> Result<(), UsageError> {
        self.core.abort(s, code)
    }

    /// The core's `start_shutdown`.
    pub fn start_shutdown(&mut self) -> Result<(), UsageError> {
        self.core.start_shutdown()
    }

    /// The core's `finish_shutdown`.
    pub fn finish_shutdown(&mut self) -> Result<(), UsageError> {
        self.core.finish_shutdown()
    }

    /// Send an HTTP datagram for request stream `s`.
    pub fn send_datagram(&mut self, s: StreamId, payload: &[u8]) -> Result<(), UsageError> {
        let mut prefix = [0; 8];
        let n = self.core.datagram_prefix(s, &mut prefix)?;
        let mut d = prefix[..n].to_vec();
        d.extend_from_slice(payload);
        // Delivery is not promised; a transport refusal is like a loss.
        let _ = self.conn.send_datagram(d.into());
        Ok(())
    }

    /// Open a bidirectional stream, driving the connection while stream credit is
    /// exhausted.
    pub async fn open_bidi(&mut self) -> Result<StreamId, crate::quic::TransportError> {
        poll_fn(|cx| {
            loop {
                if let Poll::Ready(r) = self.conn.poll_open_bidi(cx) {
                    let (s, r) = r?;
                    let id = s.id();
                    self.sends.insert(id, s);
                    self.recvs.insert(id, r);
                    return Poll::Ready(Ok(id));
                }
                if self.poll_step(cx).is_pending() {
                    return Poll::Pending;
                }
            }
        })
        .await
    }

    /// Step until `pred` holds.
    pub async fn run_until(&mut self, mut pred: impl FnMut(&Self) -> bool) {
        poll_fn(|cx| {
            while !pred(self) {
                if self.poll_step(cx).is_pending() {
                    return Poll::Pending;
                }
            }
            Poll::Ready(())
        })
        .await
    }

    /// One pass of the driving loop: `Ready` if anything moved; `Pending` (with every
    /// waker registered) otherwise.
    pub fn poll_step(&mut self, cx: &mut Context<'_>) -> Poll<()> {
        if self.dead {
            return Poll::Pending;
        }
        let moved = self.actions(cx) | self.accept(cx) | self.write(cx) | self.read(cx);
        self.datagrams(cx);
        self.events();
        if moved {
            Poll::Ready(())
        } else {
            Poll::Pending
        }
    }

    fn transport_closed(&mut self) {
        self.dead = true;
        self.core.transport_closed();
        self.events();
    }

    fn actions(&mut self, cx: &mut Context<'_>) -> bool {
        let mut moved = false;
        while let Some(a) = self.core.poll_action() {
            moved = true;
            self.trace.push(PeerObs::Action(a));
            match a {
                Action::OpenUni(UniKind::Control) if self.defer_control => {
                    self.deferred = Some(UniKind::Control)
                }
                Action::OpenUni(k) => self.open_uni.push_back(k),
                Action::ResetStream { stream, code } => self.reset(stream, code),
                Action::StopSending { stream, code } => self.stop_sending(stream, code),
                Action::FinishStream(s) => {
                    if let Some(w) = self.sends.get_mut(&s) {
                        w.finish();
                    }
                }
                Action::CloseConnection { code, .. } => self.conn.close(code.0),
            }
        }
        while let Some(&k) = self.open_uni.front() {
            match self.conn.poll_open_uni(cx) {
                Poll::Pending => break,
                Poll::Ready(Err(_)) => {
                    self.transport_closed();
                    break;
                }
                Poll::Ready(Ok(s)) => {
                    self.open_uni.pop_front();
                    let _ = self.core.bind_uni(k, s.id());
                    self.sends.insert(s.id(), s);
                    moved = true;
                }
            }
        }
        moved
    }

    fn accept(&mut self, cx: &mut Context<'_>) -> bool {
        let mut moved = false;
        while let Poll::Ready(r) = self.conn.poll_accept_uni(cx) {
            let Ok(r) = r else {
                self.transport_closed();
                return true;
            };
            self.recvs.insert(r.id(), r);
            moved = true;
        }
        while self.role == Role::Server {
            let Poll::Ready(r) = self.conn.poll_accept_bidi(cx) else {
                break;
            };
            let Ok((s, r)) = r else {
                self.transport_closed();
                return true;
            };
            self.sends.insert(s.id(), s);
            self.recvs.insert(r.id(), r);
            moved = true;
        }
        moved
    }

    /// Write one batch of `bufs` on `s`; returns the bytes accepted (`None`: pending or
    /// failed). Fully written buffers are removed.
    fn write_bufs(
        &mut self,
        cx: &mut Context<'_>,
        s: StreamId,
        bufs: &mut Vec<Bytes>,
    ) -> Option<usize> {
        if self.stopped.contains(&s) {
            return None;
        }
        let w = self.sends.get_mut(&s)?;
        match w.poll_write_chunks(cx, bufs) {
            Poll::Pending => None,
            Poll::Ready(Ok(n)) => {
                bufs.drain(..n.chunks);
                Some(n.bytes)
            }
            Poll::Ready(Err(WriteError::Stopped(code))) => {
                self.stopped.insert(s);
                let _ = self.core.stop_sending_received(s, H3Code(code));
                None
            }
            Poll::Ready(Err(WriteError::Transport(_))) => {
                self.transport_closed();
                None
            }
            Poll::Ready(Err(_)) => None,
        }
    }

    fn write(&mut self, cx: &mut Context<'_>) -> bool {
        let mut moved = false;
        for s in self.core.sendable().collect::<Vec<_>>() {
            while let Some(b) = self.core.poll_send(s) {
                let mut bufs = vec![Bytes::copy_from_slice(b)];
                let offered = bufs[0].len();
                let Some(n) = self.write_bufs(cx, s, &mut bufs) else {
                    break;
                };
                let _ = self.core.sent(s, n);
                moved |= n > 0;
                if n < offered {
                    break;
                }
            }
        }
        let ids: Vec<StreamId> = self.out.keys().copied().collect();
        for s in ids {
            loop {
                let o = self.out.get_mut(&s).unwrap();
                if o.frame.is_empty() {
                    let Some((payload, end)) = o.body.pop_front() else {
                        break;
                    };
                    match self.core.send_data(s, payload.len() as u64, end) {
                        Ok(f) => {
                            o.frame = [Bytes::copy_from_slice(f.prefix()), payload]
                                .into_iter()
                                .filter(|b| !b.is_empty())
                                .collect();
                            moved = true;
                        }
                        Err(UsageError::Blocked) => {
                            o.body.push_front((payload, end));
                            break;
                        }
                        Err(UsageError::Closed(_) | UsageError::UnknownStream) => {
                            o.body.clear();
                            break;
                        }
                        Err(e) => panic!("CorePeer::send_body on {s:?}: {e:?}"),
                    }
                    continue;
                }
                let mut frame = std::mem::take(&mut o.frame);
                let n = self.write_bufs(cx, s, &mut frame);
                self.out.get_mut(&s).unwrap().frame = frame;
                let Some(n) = n else { break };
                let _ = self.core.data_written(s, n);
                moved |= n > 0;
            }
            let o = self.out.get_mut(&s).unwrap();
            let idle = o.frame.is_empty() && self.core.poll_send(s).is_none();
            if idle && !o.raw.is_empty() {
                let mut raw: Vec<Bytes> = o.raw.drain(..).collect();
                if self.write_bufs(cx, s, &mut raw).is_some() {
                    moved = true;
                }
                let o = self.out.get_mut(&s).unwrap();
                for b in raw.into_iter().rev() {
                    o.raw.push_front(b);
                }
            }
        }
        moved
    }

    fn read(&mut self, cx: &mut Context<'_>) -> bool {
        let mut moved = false;
        let ids: Vec<StreamId> = self.recvs.keys().copied().collect();
        for s in ids {
            loop {
                let (paused, fed) = self.feed(s);
                moved |= fed;
                if paused {
                    break; // wait for a release before reading more
                }
                let Some(r) = self.recvs.get_mut(&s) else {
                    break;
                };
                let Poll::Ready(res) = r.poll_read_chunk(cx, usize::MAX) else {
                    break;
                };
                moved = true;
                match res {
                    Ok(Some(chunk)) => {
                        self.skim(s, &chunk);
                        self.inbox.entry(s).or_default().0.extend_from_slice(&chunk);
                    }
                    Ok(None) => {
                        self.recvs.remove(&s);
                        self.inbox.entry(s).or_default().1 = true;
                    }
                    Err(ReadError::Reset(code)) => {
                        self.recvs.remove(&s);
                        self.inbox.remove(&s);
                        let _ = self.core.stream_reset_received(s, H3Code(code));
                    }
                    Err(ReadError::Transport(_)) => {
                        self.transport_closed();
                        return true;
                    }
                    Err(_) => {
                        self.recvs.remove(&s);
                    }
                }
            }
        }
        // Streams whose reader is gone may still hold paused bytes or a FIN.
        let rest: Vec<StreamId> = self.inbox.keys().copied().collect();
        for s in rest {
            moved |= self.feed(s).1;
        }
        moved
    }

    /// Feed `s`'s inbox to the core: (paused with bytes left, anything consumed).
    fn feed(&mut self, s: StreamId) -> (bool, bool) {
        let mut fed = false;
        let Some((buf, fin)) = self.inbox.get_mut(&s) else {
            return (false, fed);
        };
        loop {
            if buf.is_empty() && !*fin {
                return (false, fed);
            }
            let Ok(r) = self.core.recv(s, buf, *fin) else {
                self.inbox.remove(&s);
                return (false, true);
            };
            let n = match r {
                Recv::Paused => return (true, fed),
                Recv::Body { consumed, range } => {
                    self.bodies
                        .entry(s)
                        .or_default()
                        .extend_from_slice(&buf[range.clone()]);
                    self.trace.push(PeerObs::Body {
                        stream: s,
                        len: range.len(),
                    });
                    consumed
                }
                Recv::Consumed(n) | Recv::Raw { consumed: n, .. } => n,
                Recv::Frame { consumed: n, .. } => n,
            };
            fed = true;
            let ended = *fin && n == buf.len();
            buf.drain(..n);
            if ended {
                self.inbox.remove(&s);
                return (false, true);
            }
        }
    }

    /// Record the frame headers of a request stream's raw bytes.
    fn skim(&mut self, s: StreamId, mut bytes: &[u8]) {
        if !s.is_request() {
            return;
        }
        let (p, left) = self.skim.entry(s).or_default();
        while !bytes.is_empty() {
            if *left > 0 {
                let n = (*left).min(bytes.len() as u64);
                *left -= n;
                bytes = &bytes[n as usize..];
                continue;
            }
            let (n, h) = p.feed(bytes);
            bytes = &bytes[n..];
            if let Some(h) = h {
                *left = h.len;
                self.trace.push(PeerObs::Frame {
                    stream: s,
                    ty: h.ty,
                });
            }
        }
    }

    fn datagrams(&mut self, cx: &mut Context<'_>) {
        while let Poll::Ready(r) = self.conn.poll_recv_datagram(cx) {
            let Ok(d) = r else {
                self.transport_closed();
                return;
            };
            if let Ok(Datagram::Deliver(stream, range)) = self.core.parse_datagram(&d) {
                self.trace.push(PeerObs::Datagram {
                    stream,
                    len: range.len(),
                });
            }
        }
    }

    fn events(&mut self) {
        while let Some(e) = self.core.poll_event() {
            self.trace.push(PeerObs::Event(e));
            if let Event::Headers { stream, block, .. } = e {
                if let Ok(h) = self.core.headers(block) {
                    let fields = h
                        .all()
                        .map(|f| {
                            let s = |b: &[u8]| String::from_utf8_lossy(b).into_owned();
                            (s(f.name), s(f.value))
                        })
                        .collect();
                    self.heads.entry(stream).or_default().push(fields);
                }
                if self.hold {
                    self.held.push(block);
                } else {
                    self.core.release(block);
                }
            }
        }
    }
}
