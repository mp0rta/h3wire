mod support;

use h3wire::frame::FrameHeaderParser;
use h3wire::qpack::decoder::{Span, decode_field_section};
use h3wire::{Action, Config, Connection, FieldRef, StreamId, UsageError};
use support::{Obs, Pair, Side, client_ready, client_ready_with, server_ready};

const S0: StreamId = StreamId(0);

fn f(name: &'static str, value: &'static str) -> FieldRef<'static> {
    FieldRef::new(name.as_bytes(), value.as_bytes())
}

fn get() -> Vec<FieldRef<'static>> {
    vec![
        f(":method", "GET"),
        f(":scheme", "https"),
        f(":authority", "a"),
        f(":path", "/"),
    ]
}

fn post() -> Vec<FieldRef<'static>> {
    vec![
        f(":method", "POST"),
        f(":scheme", "https"),
        f(":authority", "a"),
        f(":path", "/"),
    ]
}

fn trailers() -> Vec<FieldRef<'static>> {
    vec![f("x-checksum", "abc")]
}

fn client() -> Connection {
    client_ready(Config::default())
}

/// Hand all core-owned bytes of `s` to the "transport".
fn drain(c: &mut Connection, s: StreamId) {
    let n = c.poll_send(s).map_or(0, <[u8]>::len);
    c.sent(s, n).unwrap();
}

fn actions(c: &mut Connection) -> Vec<Action> {
    std::iter::from_fn(|| c.poll_action()).collect()
}

/// Decode one complete HEADERS frame into (name, value) pairs.
fn decode_headers(bytes: &[u8]) -> Vec<(Vec<u8>, Vec<u8>)> {
    let (n, h) = FrameHeaderParser::new().feed(bytes);
    let h = h.expect("frame header");
    assert_eq!(h.ty, 0x01);
    assert_eq!((bytes.len() - n) as u64, h.len);
    let (mut arena, mut fields) = (Vec::new(), Vec::new());
    decode_field_section(&bytes[n..], &mut arena, &mut fields).unwrap();
    let span = |s: Span| match s {
        Span::Static(b) => b.to_vec(),
        Span::Arena(x, y) => arena[x as usize..y as usize].to_vec(),
    };
    fields
        .iter()
        .map(|d| (span(d.name), span(d.value)))
        .collect()
}

fn pairs(fields: &[FieldRef]) -> Vec<(Vec<u8>, Vec<u8>)> {
    fields
        .iter()
        .map(|f| (f.name.to_vec(), f.value.to_vec()))
        .collect()
}

#[test]
fn client_request_wire_bytes() {
    let mut c = client();
    c.send_headers(S0, &get(), true).unwrap();
    let bytes = c.poll_send(S0).unwrap().to_vec();
    assert_eq!(bytes[0], 0x01);
    assert_eq!(decode_headers(&bytes), pairs(&get()));
    assert_eq!(c.sendable().collect::<Vec<_>>(), vec![S0]);
    assert_eq!(c.poll_action(), None, "FIN before the HEADERS is written");
    c.sent(S0, bytes.len() - 1).unwrap();
    assert_eq!(c.poll_action(), None);
    c.sent(S0, 1).unwrap();
    assert_eq!(actions(&mut c), vec![Action::FinishStream(S0)]);
    assert_eq!(c.poll_send(S0), None);
}

#[test]
fn reused_stream_id_rejected() {
    let mut c = client();
    c.send_headers(S0, &get(), true).unwrap();
    drain(&mut c, S0);
    assert_eq!(actions(&mut c), vec![Action::FinishStream(S0)]);
    // Still tracked (the response is outstanding): the phase rule answers.
    assert_eq!(
        c.send_headers(S0, &get(), true),
        Err(UsageError::WrongPhase)
    );
    // The complete response reaps the stream; its id is never reused.
    let resp = support::wire::headers(&[(":status", "200")]);
    c.recv(S0, &resp, true).unwrap();
    while c.poll_event().is_some() {}
    assert_eq!(
        c.send_headers(S0, &get(), true),
        Err(UsageError::UnknownStream)
    );
    // Not a client-initiated bidirectional id: our control stream, a server bidi, a uni.
    // Also ids beyond the varint range (1 << 62 and above are never stream ids).
    for s in [2, 1, 3, 6, 1 << 62, u64::MAX - 3] {
        assert_eq!(
            c.send_headers(StreamId(s), &get(), true),
            Err(UsageError::UnknownStream),
            "{s}"
        );
    }
    c.send_headers(StreamId(4), &get(), true).unwrap();
    assert_eq!(c.poll_action(), None);
}

#[test]
fn request_body_and_trailers() {
    let mut c = client();
    c.send_headers(S0, &post(), false).unwrap();
    drain(&mut c, S0);
    let d = c.send_data(S0, 3, false).unwrap();
    assert_eq!(d.prefix(), &[0x00, 0x03]);
    c.data_written(S0, 5).unwrap();
    assert_eq!(c.poll_action(), None);
    c.send_headers(S0, &trailers(), true).unwrap();
    let bytes = c.poll_send(S0).unwrap().to_vec();
    assert_eq!(decode_headers(&bytes), pairs(&trailers()));
    assert_eq!(c.poll_action(), None);
    c.sent(S0, bytes.len()).unwrap();
    assert_eq!(actions(&mut c), vec![Action::FinishStream(S0)]);
}

#[test]
fn partial_writes_inside_prefix() {
    let mut c = client();
    c.send_headers(S0, &post(), false).unwrap();
    drain(&mut c, S0);
    let d = c.send_data(S0, 300, true).unwrap();
    assert_eq!(d.prefix(), &[0x00, 0x41, 0x2c]);
    for i in 0..303 {
        assert_eq!(c.poll_send(S0), None);
        assert!(!c.sendable().any(|s| s == S0));
        assert_eq!(c.poll_action(), None, "FIN before byte {i}");
        c.data_written(S0, 1).unwrap();
    }
    assert_eq!(actions(&mut c), vec![Action::FinishStream(S0)]);
    assert_eq!(c.data_written(S0, 1), Err(UsageError::WrongPhase));
}

#[test]
fn data_written_beyond_frame_or_without_frame() {
    let mut c = client();
    c.send_headers(S0, &post(), false).unwrap();
    drain(&mut c, S0);
    assert_eq!(c.data_written(S0, 1), Err(UsageError::WrongPhase));
    c.send_data(S0, 3, false).unwrap(); // 2 + 3 bytes
    c.data_written(S0, 4).unwrap();
    assert_eq!(c.data_written(S0, 2), Err(UsageError::WrongPhase));
    c.data_written(S0, 1).unwrap();
    assert_eq!(c.data_written(S0, 1), Err(UsageError::WrongPhase));
    assert_eq!(
        c.data_written(StreamId(8), 1),
        Err(UsageError::UnknownStream)
    );
}

#[test]
fn send_data_blocked_while_headers_queued() {
    let mut c = client();
    c.send_headers(S0, &post(), false).unwrap();
    assert_eq!(c.send_data(S0, 1, false), Err(UsageError::Blocked));
    assert_eq!(c.send_data(S0, 0, true), Err(UsageError::Blocked));
    c.sent(S0, 1).unwrap();
    assert_eq!(c.send_data(S0, 1, false), Err(UsageError::Blocked));
    drain(&mut c, S0);
    c.send_data(S0, 1, false).unwrap();
}

#[test]
fn second_send_data_while_in_flight_is_blocked() {
    let mut c = client();
    c.send_headers(S0, &post(), false).unwrap();
    drain(&mut c, S0);
    c.send_data(S0, 4, false).unwrap();
    c.data_written(S0, 3).unwrap();
    assert_eq!(c.send_data(S0, 4, false), Err(UsageError::Blocked));
    c.data_written(S0, 3).unwrap();
    c.send_data(S0, 4, false).unwrap();
}

/// Trailers may be queued while DATA is in flight; they reach the wire after it.
#[test]
fn trailers_queue_behind_in_flight_data() {
    let mut c = client();
    c.send_headers(S0, &post(), false).unwrap();
    drain(&mut c, S0);
    c.send_data(S0, 4, false).unwrap();
    c.data_written(S0, 3).unwrap();
    c.send_headers(S0, &trailers(), true).unwrap();
    assert_eq!(c.poll_send(S0), None);
    assert_eq!(c.poll_action(), None);
    c.data_written(S0, 3).unwrap();
    let bytes = c.poll_send(S0).unwrap().to_vec();
    assert_eq!(decode_headers(&bytes), pairs(&trailers()));
    assert_eq!(c.poll_action(), None);
    c.sent(S0, bytes.len()).unwrap();
    assert_eq!(actions(&mut c), vec![Action::FinishStream(S0)]);
}

#[test]
fn zero_length_end_data_is_fin_only() {
    let mut c = client();
    c.send_headers(S0, &post(), false).unwrap();
    drain(&mut c, S0);
    let d = c.send_data(S0, 0, true).unwrap();
    assert!(d.prefix().is_empty());
    assert_eq!(actions(&mut c), vec![Action::FinishStream(S0)]);
    assert_eq!(c.data_written(S0, 0), Err(UsageError::WrongPhase));
    assert_eq!(c.send_data(S0, 0, true), Err(UsageError::WrongPhase));
    assert_eq!(c.poll_action(), None);
}

#[test]
fn zero_length_data_without_end_is_an_empty_frame() {
    let mut c = client();
    c.send_headers(S0, &post(), false).unwrap();
    drain(&mut c, S0);
    let d = c.send_data(S0, 0, false).unwrap();
    assert_eq!(d.prefix(), &[0x00, 0x00]);
    c.data_written(S0, 2).unwrap();
    c.send_data(S0, 0, true).unwrap();
    assert_eq!(actions(&mut c), vec![Action::FinishStream(S0)]);
}

#[test]
fn trailers_require_end() {
    let mut c = client();
    c.send_headers(S0, &post(), false).unwrap();
    drain(&mut c, S0);
    assert_eq!(
        c.send_headers(S0, &trailers(), false),
        Err(UsageError::WrongPhase)
    );
    // Pseudo-headers in trailers are invalid.
    assert_eq!(
        c.send_headers(S0, &get(), true),
        Err(UsageError::InvalidField)
    );
    c.send_headers(S0, &trailers(), true).unwrap();
}

#[test]
fn nothing_after_trailers() {
    let mut c = client();
    c.send_headers(S0, &post(), false).unwrap();
    drain(&mut c, S0);
    c.send_headers(S0, &trailers(), true).unwrap();
    for _ in 0..2 {
        assert_eq!(c.send_data(S0, 1, false), Err(UsageError::WrongPhase));
        assert_eq!(c.send_data(S0, 0, true), Err(UsageError::WrongPhase));
        assert_eq!(
            c.send_headers(S0, &trailers(), true),
            Err(UsageError::WrongPhase)
        );
        drain(&mut c, S0); // second round: after FinishStream
    }
    assert_eq!(actions(&mut c), vec![Action::FinishStream(S0)]);
}

#[test]
fn no_send_after_end() {
    let mut c = client();
    c.send_headers(S0, &post(), false).unwrap();
    drain(&mut c, S0);
    c.send_data(S0, 5, true).unwrap();
    assert_eq!(
        c.send_headers(S0, &trailers(), true),
        Err(UsageError::WrongPhase)
    );
    assert_eq!(c.send_data(S0, 1, true), Err(UsageError::WrongPhase));
    c.data_written(S0, 7).unwrap();
    assert_eq!(actions(&mut c), vec![Action::FinishStream(S0)]);
}

#[test]
fn headers_with_end_latches_immediately() {
    let mut c = client();
    c.send_headers(S0, &get(), true).unwrap();
    assert_eq!(c.send_data(S0, 0, true), Err(UsageError::WrongPhase));
    assert_eq!(
        c.send_headers(S0, &trailers(), true),
        Err(UsageError::WrongPhase)
    );
}

#[test]
fn send_data_len_out_of_range() {
    let mut c = client();
    c.send_headers(S0, &post(), false).unwrap();
    drain(&mut c, S0);
    assert_eq!(c.send_data(S0, 1 << 62, false), Err(UsageError::OutOfRange));
    let d = c.send_data(S0, (1 << 62) - 1, false).unwrap();
    assert_eq!(d.prefix().len(), 9);
}

#[test]
fn send_data_unknown_or_idle_stream() {
    let mut c = client();
    assert_eq!(c.send_data(S0, 1, false), Err(UsageError::UnknownStream));
    // Our control stream exists but carries no request.
    assert_eq!(
        c.send_data(StreamId(2), 1, false),
        Err(UsageError::WrongPhase)
    );
}

#[test]
fn extended_connect_needs_peer_setting() {
    let ws = [
        f(":method", "CONNECT"),
        f(":protocol", "websocket"),
        f(":scheme", "https"),
        f(":authority", "a"),
        f(":path", "/chat"),
    ];
    let mut c = client_ready_with(Config::default(), &[]);
    assert_eq!(
        c.send_headers(S0, &ws, false),
        Err(UsageError::NotNegotiated)
    );
    assert_eq!(c.poll_send(S0), None);
    let mut c = client_ready_with(Config::default(), &[(0x08, 1)]);
    c.send_headers(S0, &ws, false).unwrap();
    // Before SETTINGS arrive the peer has not enabled it either.
    let mut fresh = Connection::new(h3wire::Role::Client, Config::default());
    assert_eq!(
        fresh.send_headers(S0, &ws, false),
        Err(UsageError::NotNegotiated)
    );
}

#[test]
fn invalid_outgoing_field_is_usage_error() {
    let mut c = client();
    let bad = [
        f(":method", "GET"),
        f(":scheme", "https"),
        f(":authority", "a"),
        f(":path", "/"),
        f("Upper", "x"),
    ];
    assert_eq!(
        c.send_headers(S0, &bad, true),
        Err(UsageError::InvalidField)
    );
    assert_eq!(c.poll_send(S0), None);
    // The id was not consumed.
    c.send_headers(S0, &get(), true).unwrap();
}

#[test]
fn server_send_headers_needs_received_request() {
    let mut s = server_ready(Config::default());
    let resp = [f(":status", "200")];
    assert_eq!(
        s.send_headers(S0, &resp, true),
        Err(UsageError::UnknownStream)
    );
    // The server's own control stream is not a request stream.
    assert_eq!(
        s.send_headers(StreamId(3), &resp, true),
        Err(UsageError::UnknownStream)
    );
}

/// One byte per transport write: a premature FinishStream trips the harness.
#[test]
fn pair_headers_body_trailers_one_byte_writes() {
    let mut p = Pair::new(Config::default(), Config::default());
    p.opts.max_write = Some(1);
    p.drive();
    p.client.send_headers(S0, &post(), false).unwrap();
    p.drive();
    p.send_body(Side::Client, S0, b"hello", false);
    p.client.send_headers(S0, &trailers(), true).unwrap();
    p.drive();
    let fins: Vec<&Obs> = p
        .trace
        .iter()
        .filter(|o| matches!(o, Obs::Action(Side::Client, Action::FinishStream(_))))
        .collect();
    assert_eq!(fins.len(), 1);
    assert!(matches!(fins[0], Obs::Action(_, Action::FinishStream(S0))));

    // DATA with end = true, written one byte at a time.
    let s4 = StreamId(4);
    p.client.send_headers(s4, &post(), false).unwrap();
    p.drive();
    p.send_body(Side::Client, s4, b"bye", true);
    p.drive();
    assert!(
        p.trace
            .iter()
            .any(|o| matches!(o, Obs::Action(Side::Client, Action::FinishStream(s)) if *s == s4))
    );
    assert!(p.closed.is_empty());
}
