mod support;

use h3wire::{
    AbortSource, Action, Config, Connection, ConnectionError, Contexts, Event, FieldRef,
    FrameExtension, H3Code, HeadersKind, Recv, StreamId, UsageError,
};
use support::wire::{frame, headers};
use support::{Pair, Side, client_ready, server_ready};

const S0: StreamId = StreamId(0);
const S4: StreamId = StreamId(4);

fn f(name: &'static str, value: &'static str) -> FieldRef<'static> {
    FieldRef::new(name.as_bytes(), value.as_bytes())
}

fn req(method: &'static str) -> Vec<FieldRef<'static>> {
    vec![
        f(":method", method),
        f(":scheme", "https"),
        f(":authority", "a"),
        f(":path", "/"),
    ]
}

fn connect() -> Vec<FieldRef<'static>> {
    vec![f(":method", "CONNECT"), f(":authority", "a:443")]
}

fn ext_connect() -> Vec<FieldRef<'static>> {
    vec![
        f(":method", "CONNECT"),
        f(":protocol", "websocket"),
        f(":scheme", "https"),
        f(":authority", "a"),
        f(":path", "/chat"),
    ]
}

/// Wire HEADERS of a GET request.
fn get_wire() -> Vec<u8> {
    headers(&[
        (":method", "GET"),
        (":scheme", "https"),
        (":authority", "a"),
        (":path", "/"),
    ])
}

fn status(code: &str) -> Vec<u8> {
    headers(&[(":status", code)])
}

fn data(payload: &[u8]) -> Vec<u8> {
    frame(0x00, payload)
}

fn consumed(r: &Recv) -> usize {
    match *r {
        Recv::Consumed(n)
        | Recv::Body { consumed: n, .. }
        | Recv::Frame { consumed: n, .. }
        | Recv::Raw { consumed: n, .. } => n,
        Recv::Paused => 0,
    }
}

fn events(c: &mut Connection) -> Vec<Event> {
    std::iter::from_fn(|| c.poll_event()).collect()
}

fn actions(c: &mut Connection) -> Vec<Action> {
    std::iter::from_fn(|| c.poll_action()).collect()
}

fn kinds(evs: &[Event]) -> Vec<HeadersKind> {
    evs.iter()
        .filter_map(|e| match e {
            Event::Headers { kind, .. } => Some(*kind),
            _ => None,
        })
        .collect()
}

fn drain(c: &mut Connection, s: StreamId) {
    let n = c.poll_send(s).map_or(0, <[u8]>::len);
    c.sent(s, n).unwrap();
}

/// A client whose request on S0 is sent and written; events/actions drained.
fn client_req(fields: &[FieldRef], end: bool) -> Connection {
    let mut c = client_ready(Config::default());
    c.send_headers(S0, fields, end).unwrap();
    drain(&mut c, S0);
    events(&mut c);
    actions(&mut c);
    c
}

fn server() -> Connection {
    server_ready(Config::default())
}

/// What one `run` saw: events (blocks released as they appear), body bytes, frame pieces.
#[derive(Default)]
struct Seen {
    events: Vec<Event>,
    body: Vec<u8>,
    frames: Vec<(u64, Vec<u8>, u64, u64)>,
    err: Option<ConnectionError>,
}

/// Feed `bytes` until consumed, releasing every header block right away.
fn run(c: &mut Connection, s: StreamId, bytes: &[u8], fin: bool) -> Seen {
    let mut seen = Seen::default();
    let mut rest = bytes;
    loop {
        let r = c.recv(s, rest, fin);
        while let Some(e) = c.poll_event() {
            if let Event::Headers { block, .. } = e {
                c.release(block);
            }
            seen.events.push(e);
        }
        let r = match r {
            Ok(r) => r,
            Err(e) => {
                seen.err = Some(e);
                return seen;
            }
        };
        assert_ne!(r, Recv::Paused, "paused although every block was released");
        let n = consumed(&r);
        assert!(n > 0 || rest.is_empty(), "no progress");
        assert!(n <= rest.len());
        match r {
            Recv::Body { range, .. } => seen.body.extend_from_slice(&rest[range]),
            Recv::Frame {
                ty,
                range,
                offset,
                frame_len,
                ..
            } => seen
                .frames
                .push((ty, rest[range].to_vec(), offset, frame_len)),
            _ => {}
        }
        rest = &rest[n..];
        if rest.is_empty() {
            return seen;
        }
    }
}

#[track_caller]
fn assert_aborted(seen: &Seen, code: H3Code) {
    assert_eq!(seen.err, None);
    assert!(
        seen.events.contains(&Event::StreamAborted {
            stream: S0,
            code,
            source: AbortSource::Local
        }),
        "{:?}",
        seen.events
    );
    assert!(!seen.events.contains(&Event::Finished(S0)));
}

#[track_caller]
fn assert_conn_error(c: &mut Connection, seen: &Seen, code: H3Code) {
    assert_eq!(seen.err, Some(ConnectionError::Closed(code)));
    assert!(
        actions(c)
            .iter()
            .any(|a| matches!(a, Action::CloseConnection { code: x, .. } if *x == code))
    );
    assert_eq!(seen.events.last(), Some(&Event::Closed { code }));
}

#[test]
fn paused_until_release_then_resumes_exactly() {
    let mut c = client_req(&req("GET"), true);
    let buf = [status("103"), status("200"), data(b"hello")].concat();
    let mut pos = 0;
    let mut body = Vec::new();
    let feed_until_pause = |c: &mut Connection, pos: &mut usize, body: &mut Vec<u8>| loop {
        let rest = &buf[*pos..];
        let r = c.recv(S0, rest, true).unwrap();
        if r == Recv::Paused {
            return true;
        }
        if let Recv::Body { range, .. } = &r {
            body.extend_from_slice(&rest[range.clone()]);
        }
        let n = consumed(&r);
        assert!(n > 0);
        *pos += n;
        if *pos == buf.len() {
            return false;
        }
    };
    assert!(feed_until_pause(&mut c, &mut pos, &mut body));
    assert!(pos < buf.len());
    let block = match c.poll_event() {
        Some(Event::Headers {
            stream: S0,
            block,
            kind: HeadersKind::Informational,
        }) => block,
        e => panic!("{e:?}"),
    };
    assert_eq!(c.poll_event(), None);
    assert_eq!(c.recv(S0, &buf[pos..], true), Ok(Recv::Paused));
    c.release(block);
    assert!(!feed_until_pause(&mut c, &mut pos, &mut body));
    let evs = events(&mut c);
    assert!(matches!(
        evs[0],
        Event::Headers {
            kind: HeadersKind::Response,
            ..
        }
    ));
    assert_eq!(evs[1..], [Event::Finished(S0)]);
    assert_eq!(body, b"hello");
    assert_eq!(pos, buf.len());
}

#[test]
fn fragmented_nonminimal_headers_type_then_pause() {
    let mut c = client_req(&req("GET"), true);
    let first = status("103");
    let second = status("200");
    // Type 0x01 re-encoded as the two-byte varint [0x40, 0x01].
    let piece1 = [&first[..], &[0x40]].concat();
    let piece2 = [&[0x01][..], &second[1..]].concat();

    let mut pos = 0;
    let mut last = Recv::Paused;
    while pos < piece1.len() {
        last = c.recv(S0, &piece1[pos..], false).unwrap();
        pos += consumed(&last);
    }
    assert_eq!(last, Recv::Consumed(1), "the last call covers 0x40");
    let block = match c.poll_event() {
        Some(Event::Headers {
            block,
            kind: HeadersKind::Informational,
            ..
        }) => block,
        e => panic!("{e:?}"),
    };
    assert_eq!(c.recv(S0, &piece2, false), Ok(Recv::Consumed(2)));
    assert_eq!(c.recv(S0, &piece2[2..], false), Ok(Recv::Paused));
    c.release(block);
    assert_eq!(
        c.recv(S0, &piece2[2..], false),
        Ok(Recv::Consumed(piece2.len() - 2))
    );
    assert!(matches!(
        c.poll_event(),
        Some(Event::Headers {
            kind: HeadersKind::Response,
            ..
        })
    ));
}

#[test]
fn server_receives_request_headers_event() {
    let mut c = server();
    let r = c.recv(S0, &get_wire(), true).unwrap();
    assert_eq!(r, Recv::Consumed(get_wire().len()));
    let evs = events(&mut c);
    let Event::Headers {
        stream: S0,
        block,
        kind: HeadersKind::Request,
    } = evs[0]
    else {
        panic!("{evs:?}")
    };
    assert_eq!(evs[1..], [Event::Finished(S0)]);
    let h = c.headers(block).unwrap();
    assert_eq!(h.pseudo().method, Some(&b"GET"[..]));
    assert_eq!(h.pseudo().path, Some(&b"/"[..]));
}

#[test]
fn data_before_headers_is_frame_unexpected() {
    let mut c = server();
    let seen = run(&mut c, S0, &data(b"x"), false);
    assert_conn_error(&mut c, &seen, H3Code::FRAME_UNEXPECTED);
    // Client: DATA before the final response.
    let mut c = client_req(&req("GET"), true);
    let seen = run(&mut c, S0, &[status("103"), data(b"x")].concat(), false);
    assert_conn_error(&mut c, &seen, H3Code::FRAME_UNEXPECTED);
}

#[test]
fn data_after_trailers_is_frame_unexpected() {
    let mut c = server();
    let buf = [get_wire(), headers(&[("x-t", "1")]), data(b"x")].concat();
    let seen = run(&mut c, S0, &buf, false);
    assert_conn_error(&mut c, &seen, H3Code::FRAME_UNEXPECTED);
}

#[test]
fn third_headers_is_frame_unexpected() {
    let mut c = server();
    let buf = [
        get_wire(),
        headers(&[("x-t", "1")]),
        headers(&[("x-u", "1")]),
    ]
    .concat();
    let seen = run(&mut c, S0, &buf, false);
    assert_eq!(
        kinds(&seen.events)[..2],
        [HeadersKind::Request, HeadersKind::Trailers]
    );
    assert_conn_error(&mut c, &seen, H3Code::FRAME_UNEXPECTED);
}

#[test]
fn fin_inside_frame_is_frame_error() {
    let w = get_wire();
    let mut c = server();
    let seen = run(&mut c, S0, &w[..w.len() - 1], true);
    assert_conn_error(&mut c, &seen, H3Code::FRAME_ERROR);
    // FIN inside a (non-minimal) frame header.
    let mut c = server();
    let seen = run(&mut c, S0, &[w.clone(), vec![0x40]].concat(), true);
    assert_conn_error(&mut c, &seen, H3Code::FRAME_ERROR);
    // FIN inside a DATA payload.
    let mut c = server();
    let d = data(b"abc");
    let seen = run(&mut c, S0, &[w, d[..3].to_vec()].concat(), true);
    assert_conn_error(&mut c, &seen, H3Code::FRAME_ERROR);
}

#[test]
fn empty_request_stream_fin_is_request_incomplete() {
    let mut c = server();
    assert_eq!(c.recv(S0, &[], true), Ok(Recv::Consumed(0)));
    let seen = Seen {
        events: events(&mut c),
        ..Seen::default()
    };
    assert_aborted(&seen, H3Code::REQUEST_INCOMPLETE);
    // Our send side is open; the receive side already ended with FIN.
    assert_eq!(
        actions(&mut c),
        [Action::ResetStream {
            stream: S0,
            code: H3Code::REQUEST_INCOMPLETE
        }]
    );
    // Later bytes on that stream are discarded.
    assert_eq!(
        c.recv(S0, &get_wire(), true),
        Ok(Recv::Consumed(get_wire().len()))
    );
    assert_eq!(c.poll_event(), None);
}

#[test]
fn fin_without_final_response_is_message_error() {
    let mut c = client_req(&req("GET"), true);
    let seen = run(&mut c, S0, &status("103"), true);
    assert_aborted(&seen, H3Code::MESSAGE_ERROR);
    // Request fully sent, response FIN received: no direction left to stop.
    assert_eq!(actions(&mut c), []);
}

#[test]
fn content_length_mismatch_is_message_error() {
    let post_cl = headers(&[
        (":method", "POST"),
        (":scheme", "https"),
        (":authority", "a"),
        (":path", "/"),
        ("content-length", "1"),
    ]);
    // Too short at FIN.
    let mut c = server();
    let seen = run(&mut c, S0, &post_cl, true);
    assert_aborted(&seen, H3Code::MESSAGE_ERROR);
    assert_eq!(
        actions(&mut c),
        [Action::ResetStream {
            stream: S0,
            code: H3Code::MESSAGE_ERROR
        }]
    );
    // Too long, detected before FIN: both directions are still open.
    let mut c = server();
    let seen = run(&mut c, S0, &[post_cl.clone(), data(b"ab")].concat(), false);
    assert_aborted(&seen, H3Code::MESSAGE_ERROR);
    assert!(seen.body.is_empty(), "excess bytes are not delivered");
    assert_eq!(
        actions(&mut c),
        [
            Action::ResetStream {
                stream: S0,
                code: H3Code::MESSAGE_ERROR
            },
            Action::StopSending {
                stream: S0,
                code: H3Code::MESSAGE_ERROR
            }
        ]
    );
    // Exact length: Finished.
    let mut c = server();
    let seen = run(&mut c, S0, &[post_cl, data(b"a")].concat(), true);
    assert_eq!(seen.body, b"a");
    assert_eq!(seen.events.last(), Some(&Event::Finished(S0)));
}

#[test]
fn content_length_ignored_for_head_204_304() {
    for (method, code) in [("HEAD", "200"), ("GET", "204"), ("GET", "304")] {
        let mut c = client_req(&req(method), true);
        let resp = headers(&[(":status", code), ("content-length", "10")]);
        let seen = run(&mut c, S0, &resp, true);
        assert_eq!(seen.err, None);
        assert_eq!(
            seen.events.last(),
            Some(&Event::Finished(S0)),
            "{method} {code}"
        );
    }
}

#[test]
fn head_request_content_length_checked() {
    let mut c = server();
    let head = headers(&[
        (":method", "HEAD"),
        (":scheme", "https"),
        (":authority", "a"),
        (":path", "/"),
        ("content-length", "1"),
    ]);
    let seen = run(&mut c, S0, &head, true);
    assert_aborted(&seen, H3Code::MESSAGE_ERROR);
}

#[test]
fn data_in_head_response_is_message_error() {
    let mut c = client_req(&req("HEAD"), true);
    let seen = run(&mut c, S0, &[status("200"), data(b"x")].concat(), false);
    assert_aborted(&seen, H3Code::MESSAGE_ERROR);
    assert!(seen.body.is_empty());
    // Zero-length DATA is not content.
    let mut c = client_req(&req("GET"), true);
    let seen = run(&mut c, S0, &[status("204"), data(b"")].concat(), true);
    assert_eq!(seen.events.last(), Some(&Event::Finished(S0)));
}

#[test]
fn connect_204_is_tunnel() {
    let mut c = client_req(&connect(), false);
    let seen = run(&mut c, S0, &[status("204"), data(b"xyz")].concat(), false);
    assert_eq!(seen.err, None);
    assert_eq!(seen.body, b"xyz");
    assert!(
        !seen
            .events
            .iter()
            .any(|e| matches!(e, Event::StreamAborted { .. }))
    );
}

#[test]
fn connect_200_content_length_ignored_in_tunnel() {
    let mut c = client_req(&connect(), false);
    let resp = headers(&[(":status", "200"), ("content-length", "0")]);
    let seen = run(&mut c, S0, &[resp, data(b"xyz")].concat(), true);
    assert_eq!(seen.err, None);
    assert_eq!(seen.body, b"xyz");
    assert_eq!(seen.events.last(), Some(&Event::Finished(S0)));
}

#[test]
fn oversized_headers_is_excessive_load() {
    let mut cfg = Config::default();
    cfg.max_encoded_field_section_size = 8;
    let mut c = server_ready(cfg);
    let w = headers(&[
        (":method", "GET"),
        (":scheme", "https"),
        (":authority", "a"),
        (":path", "/0123456789"),
    ]);
    assert!(
        w.len() > 10 && w[1] > 8 && w[1] < 64,
        "one-byte length over the bound"
    );
    // Only the frame header: rejected before any payload is buffered.
    let seen = run(&mut c, S0, &w[..2], false);
    assert_conn_error(&mut c, &seen, H3Code::EXCESSIVE_LOAD);
}

#[test]
fn qpack_dynamic_reference_is_decompression_failed() {
    let mut c = server();
    // Required Insert Count 0, Delta Base 0, then an indexed line with T=0 (dynamic table).
    let seen = run(&mut c, S0, &frame(0x01, &[0x00, 0x00, 0x80]), false);
    assert_conn_error(&mut c, &seen, H3Code::QPACK_DECOMPRESSION_FAILED);
    // An empty field section has no prefix, even while a block is unreleased.
    let mut c = client_req(&req("GET"), true);
    c.recv(S0, &status("103"), false).unwrap();
    let seen = run(&mut c, S0, &frame(0x01, &[]), false);
    assert_conn_error(&mut c, &seen, H3Code::QPACK_DECOMPRESSION_FAILED);
}

#[test]
fn malformed_request_is_stream_error_only() {
    let mut c = server();
    let bad = headers(&[
        (":method", "GET"),
        (":scheme", "https"),
        (":authority", "a"),
        (":path", "/"),
        ("X-Upper", "1"),
    ]);
    let seen = run(&mut c, S0, &bad, false);
    assert_aborted(&seen, H3Code::MESSAGE_ERROR);
    assert!(
        kinds(&seen.events).is_empty(),
        "no Headers for a malformed block"
    );
    let seen = run(&mut c, S4, &get_wire(), true);
    assert_eq!(seen.err, None);
    assert_eq!(kinds(&seen.events), [HeadersKind::Request]);
    assert_eq!(seen.events.last(), Some(&Event::Finished(S4)));
}

#[test]
fn extension_frame_delivered_as_frame_pieces() {
    let mut cfg = Config::default();
    cfg.register_frame(FrameExtension {
        ty: 0x2a,
        contexts: Contexts::REQUEST,
    })
    .unwrap();
    let mut c = server_ready(cfg);
    let payload = *b"0123456789";
    let w = frame(0x2a, &payload);
    let hdr = w.len() - 10;
    let r = c.recv(S0, &w[..hdr + 3], false).unwrap();
    assert_eq!(
        r,
        Recv::Frame {
            consumed: hdr + 3,
            ty: 0x2a,
            range: hdr..hdr + 3,
            offset: 0,
            frame_len: 10
        }
    );
    let r = c.recv(S0, &w[hdr + 3..], false).unwrap();
    assert_eq!(
        r,
        Recv::Frame {
            consumed: 7,
            ty: 0x2a,
            range: 0..7,
            offset: 3,
            frame_len: 10
        }
    );
    // A zero-length frame is still delivered (empty piece).
    let r = c.recv(S0, &frame(0x2a, &[]), false).unwrap();
    assert_eq!(
        r,
        Recv::Frame {
            consumed: 2,
            ty: 0x2a,
            range: 2..2,
            offset: 0,
            frame_len: 0
        }
    );
    // Request HEADERS may follow an extension frame.
    let seen = run(&mut c, S0, &get_wire(), true);
    assert_eq!(kinds(&seen.events), [HeadersKind::Request]);
    // Registered for REQUEST only: skipped in a response.
    let mut cfg = Config::default();
    cfg.register_frame(FrameExtension {
        ty: 0x2a,
        contexts: Contexts::REQUEST,
    })
    .unwrap();
    let mut c = client_ready(cfg);
    c.send_headers(S0, &req("GET"), true).unwrap();
    let seen = run(&mut c, S0, &[status("200"), w].concat(), true);
    assert!(seen.frames.is_empty());
    assert_eq!(seen.events.last(), Some(&Event::Finished(S0)));
}

#[test]
fn unknown_frame_skipped_between_data() {
    let mut c = client_req(&req("GET"), true);
    let buf = [
        status("200"),
        data(b"ab"),
        frame(0x21, b"grease"),
        frame(0x2b, b""),
        data(b"cd"),
    ]
    .concat();
    let seen = run(&mut c, S0, &buf, true);
    assert_eq!(seen.body, b"abcd");
    assert_eq!(seen.events.last(), Some(&Event::Finished(S0)));
}

#[test]
fn bare_fin_after_headers_finishes() {
    let mut c = server();
    let seen = run(&mut c, S0, &get_wire(), false);
    assert_eq!(kinds(&seen.events), [HeadersKind::Request]);
    assert_eq!(c.recv(S0, &[], true), Ok(Recv::Consumed(0)));
    assert_eq!(events(&mut c), [Event::Finished(S0)]);
}

#[test]
fn tunnel_rejects_headers_frame() {
    let mut c = client_req(&connect(), false);
    let buf = [status("200"), headers(&[("x-t", "1")])].concat();
    let seen = run(&mut c, S0, &buf, false);
    assert_conn_error(&mut c, &seen, H3Code::FRAME_UNEXPECTED);
}

#[test]
fn connect_non_2xx_returns_to_regular() {
    let mut c = client_req(&connect(), false);
    let buf = [status("407"), data(b"no"), headers(&[("x-t", "1")])].concat();
    let seen = run(&mut c, S0, &buf, true);
    assert_eq!(seen.err, None);
    assert_eq!(
        kinds(&seen.events),
        [HeadersKind::Response, HeadersKind::Trailers]
    );
    assert_eq!(seen.body, b"no");
    assert_eq!(seen.events.last(), Some(&Event::Finished(S0)));
    // The request side is a regular message again: trailers are allowed.
    c.send_headers(S0, &[f("x-t", "1")], true).unwrap();
}

#[test]
fn push_promise_by_role() {
    let push = frame(0x05, &[0x00, 0x00, 0x00]);
    let mut c = client_req(&req("GET"), true);
    let seen = run(&mut c, S0, &[status("200"), push.clone()].concat(), false);
    assert_conn_error(&mut c, &seen, H3Code::ID_ERROR);
    let mut c = server();
    let seen = run(&mut c, S0, &[get_wire(), push].concat(), false);
    assert_conn_error(&mut c, &seen, H3Code::FRAME_UNEXPECTED);
    // Control-stream and HTTP/2-only frame types.
    for ty in [0x02, 0x03, 0x04, 0x06, 0x07, 0x08, 0x09, 0x0d] {
        let mut c = server();
        let seen = run(&mut c, S0, &frame(ty, &[0x00]), false);
        assert_conn_error(&mut c, &seen, H3Code::FRAME_UNEXPECTED);
    }
}

#[test]
fn header_block_survives_fin() {
    let mut c = client_req(&req("GET"), true);
    assert_eq!(
        c.recv(S0, &status("200"), true),
        Ok(Recv::Consumed(status("200").len()))
    );
    let evs = events(&mut c);
    let Event::Headers { block, .. } = evs[0] else {
        panic!("{evs:?}")
    };
    assert_eq!(evs[1..], [Event::Finished(S0)]);
    assert_eq!(c.headers(block).unwrap().pseudo().status, Some(200));
    c.release(block);
    assert_eq!(c.headers(block).map(|_| ()), Err(UsageError::StaleBlock));
}

// ---- Server-role send, end to end through `Pair` ----

/// Drive until quiet, releasing every received header block.
fn settle(p: &mut Pair) {
    let mut seen = usize::MAX;
    while p.trace.len() != seen {
        seen = p.trace.len();
        p.drive();
        for side in [Side::Client, Side::Server] {
            for e in p.events(side) {
                if let Event::Headers { block, .. } = e {
                    p.conn(side).release(block);
                }
            }
        }
    }
}

fn pair() -> Pair {
    let mut p = Pair::new(Config::default(), Config::default());
    p.drive();
    p
}

/// A pair with the client's request on S0 delivered to the server.
fn pair_with(fields: &[FieldRef], end: bool) -> Pair {
    let mut p = pair();
    p.client.send_headers(S0, fields, end).unwrap();
    settle(&mut p);
    assert!(
        kinds(&p.events(Side::Server)).contains(&HeadersKind::Request),
        "{:?}",
        p.events(Side::Server)
    );
    p
}

#[test]
fn request_response_roundtrip() {
    let mut p = pair_with(&req("GET"), true);
    p.server
        .send_headers(S0, &[f(":status", "200")], false)
        .unwrap();
    settle(&mut p);
    p.send_body(Side::Server, S0, b"abc", false);
    p.server.send_headers(S0, &[f("x-t", "1")], true).unwrap();
    settle(&mut p);
    let evs = p.events(Side::Client);
    assert_eq!(kinds(&evs), [HeadersKind::Response, HeadersKind::Trailers]);
    assert_eq!(evs.last(), Some(&Event::Finished(S0)));
    assert_eq!(p.bodies[&(Side::Client, S0)], b"abc");
    assert_eq!(p.events(Side::Server).last(), Some(&Event::Finished(S0)));
    assert!(p.closed.is_empty());
}

#[test]
fn partial_writes_roundtrip() {
    let mut p = pair();
    p.opts.max_write = Some(1);
    let up: Vec<u8> = (0..300u32).map(|i| i as u8).collect();
    let down: Vec<u8> = (0..300u32).map(|i| (i * 7) as u8).collect();
    p.client.send_headers(S0, &req("POST"), false).unwrap();
    settle(&mut p);
    p.send_body(Side::Client, S0, &up, true);
    p.server
        .send_headers(S0, &[f(":status", "200")], false)
        .unwrap();
    settle(&mut p);
    p.send_body(Side::Server, S0, &down, true);
    settle(&mut p);
    assert_eq!(p.bodies[&(Side::Server, S0)], up);
    assert_eq!(p.bodies[&(Side::Client, S0)], down);
    assert_eq!(p.events(Side::Server).last(), Some(&Event::Finished(S0)));
    assert_eq!(p.events(Side::Client).last(), Some(&Event::Finished(S0)));
}

#[test]
fn data_before_final_response_is_wrong_phase() {
    let mut p = pair_with(&req("GET"), true);
    p.server
        .send_headers(S0, &[f(":status", "103")], false)
        .unwrap();
    settle(&mut p);
    assert_eq!(
        p.server.send_data(S0, 1, false),
        Err(UsageError::WrongPhase)
    );
}

#[test]
fn no_content_response_rejects_data() {
    for (method, code) in [("HEAD", "200"), ("GET", "204")] {
        let mut p = pair_with(&req(method), true);
        p.server
            .send_headers(S0, &[f(":status", code)], false)
            .unwrap();
        settle(&mut p);
        assert_eq!(
            p.server.send_data(S0, 1, true),
            Err(UsageError::WrongPhase),
            "{method} {code}"
        );
        p.server.send_data(S0, 0, true).unwrap();
        settle(&mut p);
        assert_eq!(p.events(Side::Client).last(), Some(&Event::Finished(S0)));
    }
    let mut p = pair_with(&connect(), false);
    p.server
        .send_headers(S0, &[f(":status", "204")], false)
        .unwrap();
    settle(&mut p);
    p.server.send_data(S0, 3, false).unwrap();
}

#[test]
fn informational_cannot_end_stream() {
    let mut p = pair_with(&req("GET"), true);
    assert_eq!(
        p.server.send_headers(S0, &[f(":status", "103")], true),
        Err(UsageError::WrongPhase)
    );
}

#[test]
fn server_rejects_unadvertised_protocol() {
    let mut p = pair();
    let w = headers(&[
        (":method", "CONNECT"),
        (":protocol", "websocket"),
        (":scheme", "https"),
        (":authority", "a"),
        (":path", "/chat"),
    ]);
    p.feed(Side::Server, S0, &w, false);
    settle(&mut p);
    assert!(p.events(Side::Server).contains(&Event::StreamAborted {
        stream: S0,
        code: H3Code::MESSAGE_ERROR,
        source: AbortSource::Local
    }));
    assert!(p.closed.is_empty());
}

#[test]
fn tunnel_bytes_flow_both_ways() {
    let mut server_cfg = Config::default();
    server_cfg.enable_connect_protocol = true;
    let mut p = Pair::new(Config::default(), server_cfg);
    p.drive();
    p.client.send_headers(S0, &ext_connect(), false).unwrap();
    settle(&mut p);
    p.server
        .send_headers(S0, &[f(":status", "200")], false)
        .unwrap();
    settle(&mut p);
    p.send_body(Side::Client, S0, b"ping", false);
    p.send_body(Side::Server, S0, b"pong!", false);
    settle(&mut p);
    assert_eq!(p.bodies[&(Side::Server, S0)], b"ping");
    assert_eq!(p.bodies[&(Side::Client, S0)], b"pong!");
    assert!(p.closed.is_empty());
}

#[test]
fn tunnel_send_headers_is_wrong_phase() {
    let mut p = pair_with(&connect(), false);
    p.server
        .send_headers(S0, &[f(":status", "200")], false)
        .unwrap();
    settle(&mut p);
    assert_eq!(
        p.client.send_headers(S0, &[f("x-t", "1")], true),
        Err(UsageError::WrongPhase)
    );
    assert_eq!(
        p.server.send_headers(S0, &[f("x-t", "1")], true),
        Err(UsageError::WrongPhase)
    );
}

#[test]
fn server_rejects_trailers_in_tunnel() {
    let mut p = pair_with(&connect(), false);
    p.server
        .send_headers(S0, &[f(":status", "200")], false)
        .unwrap();
    settle(&mut p);
    p.feed(Side::Server, S0, &headers(&[("x-t", "1")]), false);
    settle(&mut p);
    assert_eq!(p.closed, [(Side::Server, H3Code::FRAME_UNEXPECTED)]);
}

#[test]
fn never_index_survives_roundtrip() {
    let mut p = pair();
    let mut fields = req("GET");
    fields.push(FieldRef {
        never_index: true,
        ..f("authorization", "secret")
    });
    p.client.send_headers(S0, &fields, true).unwrap();
    p.drive();
    let evs = p.events(Side::Server);
    let Some(block) = evs.iter().find_map(|e| match e {
        Event::Headers { block, .. } => Some(*block),
        _ => None,
    }) else {
        panic!("{evs:?}")
    };
    let h = p.server.headers(block).unwrap();
    let auth = h
        .iter()
        .find(|x| x.name == b"authorization")
        .expect("authorization");
    assert!(auth.never_index);
    assert_eq!(auth.value, b"secret");
}
