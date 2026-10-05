//! Sans-I/O HTTP/3 ([RFC 9114]) and QPACK ([RFC 9204]) engine.
//!
//! A [`Connection`] is the HTTP/3 layer of one QUIC connection. It does no I/O, owns no
//! QUIC stream and keeps no clock: the caller (an adapter over a QUIC stack) feeds it the
//! bytes each stream received, writes out the bytes it asks to send, and executes the
//! [`Action`]s it emits. The application learns what happened from [`Event`]s.
//!
//! v0.1 uses the QPACK static table only (it leaves the dynamic table capacity and blocked
//! streams settings at their default of 0) and never enables server push.
//!
//! # Driving a connection
//!
//! Repeat until nothing moves:
//!
//! 1. **Actions.** Execute every [`Connection::poll_action`] on the QUIC connection. After
//!    [`Action::OpenUni`], open a unidirectional stream and hand its id to
//!    [`Connection::bind_uni`].
//! 2. **Send.** Collect [`Connection::sendable`] first (writing changes it), then for each
//!    stream offer [`Connection::poll_send`] to the transport and report what it took with
//!    [`Connection::sent`]; keep writing a stream until the transport accepts less than
//!    offered. Bodies never go through the core: [`Connection::send_data`] hands out a DATA
//!    frame prefix, the caller writes prefix then payload (`writev`) and reports progress
//!    with [`Connection::data_written`].
//! 3. **Receive.** Feed received bytes with [`Connection::recv`] (see its progress
//!    contract): each call consumes a prefix and the caller re-feeds the rest.
//! 4. **Events.** Handle every [`Connection::poll_event`]; read a header block with
//!    [`Connection::headers`] and [`Connection::release`] it when done.
//!
//! Caller contracts:
//!
//! - **FIN** is only ever set when the core emits [`Action::FinishStream`]; never finish a
//!   stream on your own.
//! - **Errors.** An `Err` from any call is a state notification only.
//!   [`Action::CloseConnection`] is the sole trigger for the wire effects of a connection
//!   error; after it (or [`Connection::transport_closed`]) keep draining
//!   [`Connection::poll_event`] and [`Connection::poll_action`] ([`Connection::peer_settings`]
//!   also keeps working); every other call returns `Err(Closed(code))` or does nothing.
//! - **Critical streams.** Read the peer's control and QPACK streams eagerly, regardless of
//!   application demand; otherwise SETTINGS could stall behind a paused request stream.
//!   QUIC flow-control credit is the adapter's job; the core only tracks what it consumed.
//! - **Stream events.** While the connection is open, every request stream gets exactly
//!   one terminal event, [`Event::Finished`] or [`Event::StreamAborted`]. A server can get
//!   `StreamAborted` for a request it never saw `Headers` on (rejected at a GOAWAY cutoff,
//!   malformed, or reset by the peer before any byte arrived). [`Event::Closed`] stands in
//!   for every stream still open.
//! - **Datagrams.** [`Connection::parse_datagram`] only routes; the caller decides whether
//!   to buffer [`Datagram::NotYetOpen`] payloads briefly, and which requests carry datagram
//!   semantics (abort the others with [`H3Code::DATAGRAM_ERROR`]).
//!
//! # Example
//!
//! A client and a server joined by an in-memory transport that accepts every write:
//!
//! ```
//! use h3wire::{Action, Config, Connection, Event, FieldRef, Recv, Role, StreamId};
//! use std::collections::BTreeMap;
//!
//! /// Bytes received and not yet consumed, and whether FIN followed them, per stream.
//! type Inbox = BTreeMap<StreamId, (Vec<u8>, bool)>;
//!
//! /// One pass of the driving loop; `out` is the peer's inbox. Returns whether anything moved.
//! fn step(c: &mut Connection, inbox: &mut Inbox, out: &mut Inbox, next_uni: &mut u64,
//!         body: &mut Vec<u8>) -> bool {
//!     let mut moved = false;
//!     while let Some(a) = c.poll_action() {
//!         moved = true;
//!         match a {
//!             Action::OpenUni(kind) => {
//!                 c.bind_uni(kind, StreamId(*next_uni)).unwrap();
//!                 *next_uni += 4;
//!             }
//!             Action::FinishStream(s) => out.entry(s).or_default().1 = true,
//!             a => panic!("not expected in this exchange: {a:?}"),
//!         }
//!     }
//!     for s in c.sendable().collect::<Vec<_>>() {
//!         let bytes = c.poll_send(s).unwrap();
//!         let n = bytes.len(); // a real transport may accept fewer
//!         out.entry(s).or_default().0.extend_from_slice(bytes);
//!         c.sent(s, n).unwrap();
//!         moved = true;
//!     }
//!     inbox.retain(|&s, (buf, fin)| loop {
//!         if buf.is_empty() && !*fin {
//!             return true;
//!         }
//!         let n = match c.recv(s, buf, *fin).unwrap() {
//!             Recv::Paused => return true, // feed again after `release`
//!             Recv::Body { consumed, range } => {
//!                 body.extend_from_slice(&buf[range]);
//!                 consumed
//!             }
//!             Recv::Consumed(n)
//!             | Recv::Frame { consumed: n, .. }
//!             | Recv::Raw { consumed: n, .. } => n,
//!         };
//!         moved = true;
//!         let ended = *fin && n == buf.len(); // FIN counts once everything is consumed
//!         buf.drain(..n);
//!         if ended {
//!             return false;
//!         }
//!     });
//!     moved
//! }
//!
//! let f = |n: &'static str, v: &'static str| FieldRef::new(n.as_bytes(), v.as_bytes());
//! let mut client = Connection::new(Role::Client, Config::default());
//! let mut server = Connection::new(Role::Server, Config::default());
//! let (mut to_client, mut to_server) = (Inbox::new(), Inbox::new());
//! let (mut client_uni, mut server_uni) = (2, 3);
//! let (mut client_body, mut server_body) = (Vec::new(), Vec::new());
//! let request = [
//!     f(":method", "GET"),
//!     f(":scheme", "https"),
//!     f(":authority", "a"),
//!     f(":path", "/"),
//! ];
//! client.send_headers(StreamId(0), &request, true).unwrap();
//!
//! let (mut respond, mut finished) = (None, false);
//! loop {
//!     let mut moved = step(&mut client, &mut to_client, &mut to_server, &mut client_uni,
//!                          &mut client_body);
//!     moved |= step(&mut server, &mut to_server, &mut to_client, &mut server_uni,
//!                   &mut server_body);
//!     while let Some(e) = server.poll_event() {
//!         if let Event::Headers { stream, block, .. } = e {
//!             assert_eq!(server.headers(block).unwrap().pseudo().path, Some(&b"/"[..]));
//!             server.release(block);
//!             server.send_headers(stream, &[f(":status", "200")], false).unwrap();
//!             respond = Some(stream);
//!         }
//!     }
//!     // DATA may start once the HEADERS bytes are written (`Blocked` until then).
//!     if let Some(s) = respond {
//!         if let Ok(frame) = server.send_data(s, 5, true) {
//!             let pipe = &mut to_client.entry(s).or_default().0;
//!             pipe.extend_from_slice(frame.prefix()); // writev(prefix, payload)
//!             pipe.extend_from_slice(b"hello");
//!             server.data_written(s, frame.prefix().len() + 5).unwrap();
//!             respond = None;
//!             moved = true;
//!         }
//!     }
//!     while let Some(e) = client.poll_event() {
//!         match e {
//!             Event::Headers { block, .. } => client.release(block),
//!             Event::Finished(s) => finished = s == StreamId(0),
//!             _ => {}
//!         }
//!     }
//!     if !moved {
//!         break;
//!     }
//! }
//! assert!(finished);
//! assert_eq!(client_body, b"hello");
//! ```
//!
//! [RFC 9114]: https://www.rfc-editor.org/rfc/rfc9114
//! [RFC 9204]: https://www.rfc-editor.org/rfc/rfc9204
#![forbid(unsafe_code)]
#![warn(missing_docs)]

mod error;
#[doc(hidden)]
pub mod frame;
mod headers;
#[doc(hidden)]
pub mod qpack;
#[doc(hidden)]
pub mod varint;
pub use error::*;
pub use headers::{FieldRef, HeaderBlockId, HeaderBlockRef, HeadersKind, Pseudo};
mod config;
mod settings;
pub use config::*;
pub use settings::PeerSettings;
#[doc(hidden)]
#[path = "invariants.rs"]
pub mod __invariants;
mod conn;
mod event;
mod stream;
pub use conn::{Connection, Role};
pub use event::{AbortSource, Action, DataFrame, Datagram, Event, Recv};
pub use stream::{StreamId, UniKind};
