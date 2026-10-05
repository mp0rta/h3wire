mod support;

use h3wire::{
    AbortSource, Action, Config, Connection, ConnectionError, Event, FieldRef, H3Code, HeadersKind,
    Recv, StreamId, UsageError,
};
use support::wire::{frame, headers};
use support::{Obs, Pair, Side, client_ready, feed_all, server_ready};

const S0: StreamId = StreamId(0);
const S4: StreamId = StreamId(4);
/// Control + QPACK encoder + QPACK decoder: the local uni streams live in the stream map.
const CRITICAL: usize = 3;

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

fn events(c: &mut Connection) -> Vec<Event> {
    std::iter::from_fn(|| c.poll_event()).collect()
}

fn actions(c: &mut Connection) -> Vec<Action> {
    std::iter::from_fn(|| c.poll_action()).collect()
}

fn drain(c: &mut Connection, s: StreamId) {
    let n = c.poll_send(s).map_or(0, <[u8]>::len);
    c.sent(s, n).unwrap();
}

fn aborted(stream: StreamId, code: H3Code, source: AbortSource) -> Event {
    Event::StreamAborted {
        stream,
        code,
        source,
    }
}

fn terminal_count(evs: &[Event], s: StreamId) -> usize {
    evs.iter()
        .filter(
            |e| matches!(e, Event::Finished(x) | Event::StreamAborted { stream: x, .. } if *x == s),
        )
        .count()
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

/// A server that received `bytes` on S0; header blocks released; returns its events.
fn server_got(bytes: &[u8], fin: bool) -> (Connection, Vec<Event>) {
    let mut c = server_ready(Config::default());
    feed_all(&mut c, S0, bytes, fin);
    let evs = events(&mut c);
    for e in &evs {
        if let Event::Headers { block, .. } = e {
            c.release(*block);
        }
    }
    assert_eq!(actions(&mut c), []);
    (c, evs)
}

/// Feed `bytes` until consumed, releasing every header block; returns events and body.
fn run(c: &mut Connection, s: StreamId, bytes: &[u8], fin: bool) -> (Vec<Event>, Vec<u8>) {
    let (mut evs, mut body) = (Vec::new(), Vec::new());
    let mut rest = bytes;
    loop {
        let r = c.recv(s, rest, fin).unwrap();
        while let Some(e) = c.poll_event() {
            if let Event::Headers { block, .. } = e {
                c.release(block);
            }
            evs.push(e);
        }
        let n = match r {
            Recv::Body { consumed, range } => {
                body.extend_from_slice(&rest[range]);
                consumed
            }
            Recv::Consumed(n) => n,
            other => panic!("{other:?}"),
        };
        rest = &rest[n..];
        if rest.is_empty() {
            return (evs, body);
        }
    }
}

#[test]
fn stop_sending_then_complete_response_delivered() {
    let mut c = client_req(&req("POST"), false);
    c.send_data(S0, 3, false).unwrap();
    c.data_written(S0, 2).unwrap();
    c.stop_sending_received(S0, H3Code::NO_ERROR).unwrap();
    assert_eq!(
        events(&mut c),
        [Event::SendStopped {
            stream: S0,
            code: H3Code::NO_ERROR
        }]
    );
    assert_eq!(
        actions(&mut c),
        [Action::ResetStream {
            stream: S0,
            code: H3Code::NO_ERROR
        }]
    );
    // Queued bytes and the in-flight DATA frame are gone; sending is over.
    assert_eq!(c.data_written(S0, 3), Err(UsageError::WrongPhase));
    assert_eq!(c.poll_send(S0), None);
    assert_eq!(c.send_data(S0, 0, true), Err(UsageError::WrongPhase));
    // A second STOP_SENDING changes nothing.
    c.stop_sending_received(S0, H3Code::NO_ERROR).unwrap();
    assert_eq!(events(&mut c), []);
    assert_eq!(actions(&mut c), []);

    let resp = [status("200"), data(b"hi")].concat();
    let (evs, body) = run(&mut c, S0, &resp, true);
    assert!(
        matches!(
            evs[..],
            [
                Event::Headers {
                    kind: HeadersKind::Response,
                    ..
                },
                Event::Finished(S0)
            ]
        ),
        "{evs:?}"
    );
    assert_eq!(body, b"hi");
    assert_eq!(actions(&mut c), []);
    assert_eq!(c.debug_stream_count(), CRITICAL, "reaped");
}

#[test]
fn peer_reset_aborts_stream() {
    let mut c = client_req(&req("POST"), false);
    c.stream_reset_received(S0, H3Code::REQUEST_CANCELLED)
        .unwrap();
    assert_eq!(
        events(&mut c),
        [aborted(S0, H3Code::REQUEST_CANCELLED, AbortSource::Peer)]
    );
    // The reset direction gets no STOP_SENDING; our open send side is reset.
    assert_eq!(
        actions(&mut c),
        [Action::ResetStream {
            stream: S0,
            code: H3Code::REQUEST_CANCELLED
        }]
    );
    assert_eq!(
        c.recv(S0, &status("200"), true),
        Ok(Recv::Consumed(status("200").len()))
    );
    c.stream_reset_received(S0, H3Code::REQUEST_CANCELLED)
        .unwrap();
    c.stop_sending_received(S0, H3Code::REQUEST_CANCELLED)
        .unwrap();
    assert_eq!(events(&mut c), []);
    assert_eq!(actions(&mut c), []);
}

#[test]
fn local_abort_emits_both_directions() {
    let mut c = client_req(&req("POST"), false);
    c.abort(S0, H3Code::REQUEST_CANCELLED).unwrap();
    assert_eq!(
        actions(&mut c),
        [
            Action::ResetStream {
                stream: S0,
                code: H3Code::REQUEST_CANCELLED
            },
            Action::StopSending {
                stream: S0,
                code: H3Code::REQUEST_CANCELLED
            }
        ]
    );
    assert_eq!(
        events(&mut c),
        [aborted(S0, H3Code::REQUEST_CANCELLED, AbortSource::Local)]
    );
}

#[test]
fn peer_reset_after_request_fin() {
    let mut c = client_req(&req("GET"), true);
    let (evs, _) = run(&mut c, S0, &status("200"), false);
    assert_eq!(evs.len(), 1, "{evs:?}");
    c.stream_reset_received(S0, H3Code::REQUEST_CANCELLED)
        .unwrap();
    assert_eq!(
        events(&mut c),
        [aborted(S0, H3Code::REQUEST_CANCELLED, AbortSource::Peer)]
    );
    assert_eq!(actions(&mut c), []);
}

#[test]
fn abort_after_request_fin_resets_response() {
    let (mut c, evs) = server_got(&get_wire(), true);
    assert_eq!(evs.last(), Some(&Event::Finished(S0)));
    c.send_headers(S0, &[f(":status", "200")], false).unwrap();
    drain(&mut c, S0);
    assert_eq!(actions(&mut c), []);
    c.abort(S0, H3Code::REQUEST_CANCELLED).unwrap();
    assert_eq!(
        actions(&mut c),
        [Action::ResetStream {
            stream: S0,
            code: H3Code::REQUEST_CANCELLED
        }]
    );
    assert_eq!(events(&mut c), []);
    assert_eq!(c.debug_stream_count(), CRITICAL);
}

#[test]
fn no_reset_for_finished_send_side() {
    let mut c = client_req(&req("GET"), true);
    c.abort(S0, H3Code::REQUEST_CANCELLED).unwrap();
    assert_eq!(
        actions(&mut c),
        [Action::StopSending {
            stream: S0,
            code: H3Code::REQUEST_CANCELLED
        }]
    );
    assert_eq!(
        events(&mut c),
        [aborted(S0, H3Code::REQUEST_CANCELLED, AbortSource::Local)]
    );
}

#[test]
fn abort_is_idempotent() {
    let mut c = client_req(&req("POST"), false);
    c.abort(S0, H3Code::REQUEST_CANCELLED).unwrap();
    events(&mut c);
    actions(&mut c);
    assert_eq!(c.abort(S0, H3Code::REQUEST_CANCELLED), Ok(()));
    assert_eq!(events(&mut c), []);
    assert_eq!(actions(&mut c), []);
    // Never opened, not a request stream, not a valid stream id.
    for s in [8, 2, 1, u64::MAX, 1 << 62] {
        assert_eq!(
            c.abort(StreamId(s), H3Code::REQUEST_CANCELLED),
            Err(UsageError::UnknownStream),
            "{s}"
        );
    }
}

#[test]
fn client_abort_with_rejected_is_forbidden() {
    let mut c = client_req(&req("POST"), false);
    assert_eq!(
        c.abort(S0, H3Code::REQUEST_REJECTED),
        Err(UsageError::ForbiddenCode)
    );
    assert_eq!(events(&mut c), []);
    assert_eq!(actions(&mut c), []);
    c.abort(S0, H3Code::REQUEST_CANCELLED).unwrap();
}

#[test]
fn peer_rejected_reset_not_echoed_when_processed() {
    let (mut c, _) = server_got(&get_wire(), false);
    c.stream_reset_received(S0, H3Code::REQUEST_REJECTED)
        .unwrap();
    assert_eq!(
        actions(&mut c),
        [Action::ResetStream {
            stream: S0,
            code: H3Code::REQUEST_CANCELLED
        }]
    );
    assert_eq!(
        events(&mut c),
        [aborted(S0, H3Code::REQUEST_REJECTED, AbortSource::Peer)]
    );
    // Not processed yet (only part of a frame header): echoed as is.
    let (mut c, _) = server_got(&get_wire()[..1], false);
    c.stream_reset_received(S0, H3Code::REQUEST_REJECTED)
        .unwrap();
    assert_eq!(
        actions(&mut c),
        [Action::ResetStream {
            stream: S0,
            code: H3Code::REQUEST_REJECTED
        }]
    );
}

#[test]
fn client_never_sends_rejected() {
    let mut c = client_req(&req("POST"), false);
    c.stop_sending_received(S0, H3Code::REQUEST_REJECTED)
        .unwrap();
    assert_eq!(
        actions(&mut c),
        [Action::ResetStream {
            stream: S0,
            code: H3Code::REQUEST_CANCELLED
        }]
    );
    assert_eq!(
        events(&mut c),
        [Event::SendStopped {
            stream: S0,
            code: H3Code::REQUEST_REJECTED
        }]
    );
    c.send_headers(S4, &req("POST"), false).unwrap();
    drain(&mut c, S4);
    c.stream_reset_received(S4, H3Code::REQUEST_REJECTED)
        .unwrap();
    assert_eq!(
        actions(&mut c),
        [Action::ResetStream {
            stream: S4,
            code: H3Code::REQUEST_CANCELLED
        }]
    );
    assert_eq!(
        events(&mut c),
        [aborted(S4, H3Code::REQUEST_REJECTED, AbortSource::Peer)]
    );
}

#[test]
fn server_abort_rejected_after_processing_is_forbidden() {
    let (mut c, _) = server_got(&get_wire(), false);
    assert_eq!(
        c.abort(S0, H3Code::REQUEST_REJECTED),
        Err(UsageError::ForbiddenCode)
    );
    assert_eq!(actions(&mut c), []);
    // Before the request HEADERS were decoded it is allowed.
    let (mut c, _) = server_got(&get_wire()[..1], false);
    c.abort(S0, H3Code::REQUEST_REJECTED).unwrap();
    assert_eq!(
        actions(&mut c),
        [
            Action::ResetStream {
                stream: S0,
                code: H3Code::REQUEST_REJECTED
            },
            Action::StopSending {
                stream: S0,
                code: H3Code::REQUEST_REJECTED
            }
        ]
    );
    assert_eq!(
        events(&mut c),
        [aborted(S0, H3Code::REQUEST_REJECTED, AbortSource::Local)]
    );
}

#[test]
fn abort_code_out_of_range() {
    let mut c = client_req(&req("POST"), false);
    assert_eq!(c.abort(S0, H3Code(1 << 62)), Err(UsageError::OutOfRange));
    assert_eq!(actions(&mut c), []);
    c.abort(S0, H3Code((1 << 62) - 1)).unwrap();
}

#[test]
fn recv_after_abort_discards() {
    let (mut c, _) = server_got(
        &headers(&[
            (":method", "POST"),
            (":scheme", "https"),
            (":authority", "a"),
            (":path", "/"),
        ]),
        false,
    );
    c.abort(S0, H3Code::REQUEST_CANCELLED).unwrap();
    events(&mut c);
    actions(&mut c);
    let late = [data(b"abc"), get_wire()].concat();
    assert_eq!(c.recv(S0, &late, true), Ok(Recv::Consumed(late.len())));
    assert_eq!(events(&mut c), []);
    assert_eq!(actions(&mut c), []);
    assert_eq!(c.debug_stream_count(), CRITICAL);
}

/// Drive until quiet, releasing every header block observed after `*seen`.
fn settle(p: &mut Pair, seen: &mut usize) {
    loop {
        p.drive();
        if *seen == p.trace.len() {
            return;
        }
        let new: Vec<(Side, Event)> = p.trace[*seen..]
            .iter()
            .filter_map(|o| match o {
                Obs::Event(s, e) => Some((*s, *e)),
                _ => None,
            })
            .collect();
        *seen = p.trace.len();
        for (side, e) in new {
            if let Event::Headers { block, .. } = e {
                p.conn(side).release(block);
            }
        }
    }
}

fn pair() -> (Pair, usize) {
    let mut p = Pair::new(Config::default(), Config::default());
    let mut seen = 0;
    settle(&mut p, &mut seen);
    (p, seen)
}

/// One GET/200 exchange on `s`, both directions ending with FIN.
fn exchange(p: &mut Pair, seen: &mut usize, s: StreamId) {
    p.client.send_headers(s, &req("GET"), true).unwrap();
    settle(p, seen);
    p.server
        .send_headers(s, &[f(":status", "200")], true)
        .unwrap();
    settle(p, seen);
}

#[test]
fn stream_error_isolated() {
    let (mut p, mut seen) = pair();
    p.client.send_headers(S4, &req("GET"), true).unwrap();
    // No :path: malformed.
    let bad = headers(&[
        (":method", "GET"),
        (":scheme", "https"),
        (":authority", "a"),
    ]);
    p.feed(Side::Server, S0, &bad, false);
    settle(&mut p, &mut seen);
    let evs = p.events(Side::Server);
    assert!(
        evs.contains(&aborted(S0, H3Code::MESSAGE_ERROR, AbortSource::Local)),
        "{evs:?}"
    );
    assert_eq!(evs.last(), Some(&Event::Finished(S4)));
    p.server
        .send_headers(S4, &[f(":status", "200")], true)
        .unwrap();
    settle(&mut p, &mut seen);
    assert_eq!(p.events(Side::Client).last(), Some(&Event::Finished(S4)));
    assert!(p.closed.is_empty());
}

#[test]
fn completed_streams_are_reaped() {
    let (mut p, mut seen) = pair();
    for i in 0..1000 {
        let s = StreamId(4 * i);
        exchange(&mut p, &mut seen, s);
        assert_eq!(p.events(Side::Client).last(), Some(&Event::Finished(s)));
        // Only the local critical uni streams remain (peer uni state is kept apart).
        assert_eq!(p.client.debug_stream_count(), CRITICAL, "client {i}");
        assert_eq!(p.server.debug_stream_count(), CRITICAL, "server {i}");
    }
    assert!(p.closed.is_empty());
    // Late bytes for a reaped id never recreate the stream.
    let w = get_wire();
    assert_eq!(p.server.recv(S0, &w, true), Ok(Recv::Consumed(w.len())));
    assert_eq!(p.server.poll_event(), None);
    assert_eq!(p.server.poll_action(), None);
    assert_eq!(p.server.debug_stream_count(), CRITICAL);
    let st = status("200");
    assert_eq!(p.client.recv(S0, &st, true), Ok(Recv::Consumed(st.len())));
    assert_eq!(p.client.poll_event(), None);
    assert_eq!(
        p.client.send_headers(S0, &req("GET"), true),
        Err(UsageError::UnknownStream)
    );
    assert_eq!(
        p.server.send_headers(S0, &[f(":status", "200")], true),
        Err(UsageError::UnknownStream)
    );
}

#[test]
fn closed_history_stays_small() {
    let (mut p, mut seen) = pair();
    p.client.send_headers(S0, &req("POST"), false).unwrap();
    settle(&mut p, &mut seen);
    for i in 1..=1000 {
        exchange(&mut p, &mut seen, StreamId(4 * i));
    }
    assert!(p.client.debug_closed_ranges() <= 2);
    assert!(p.server.debug_closed_ranges() <= 2);
    assert_eq!(p.client.debug_stream_count(), CRITICAL + 1);
    assert_eq!(p.server.debug_stream_count(), CRITICAL + 1);
    // Finishing S0 merges everything into one range.
    p.send_body(Side::Client, S0, b"", true);
    p.server
        .send_headers(S0, &[f(":status", "200")], true)
        .unwrap();
    settle(&mut p, &mut seen);
    assert_eq!(p.client.debug_closed_ranges(), 1);
    assert_eq!(p.server.debug_closed_ranges(), 1);
    assert_eq!(p.server.debug_stream_count(), CRITICAL);
    assert!(p.closed.is_empty());
}

#[test]
fn transport_closed_emits_closed_only() {
    let mut c = client_ready(Config::default());
    for s in [S0, S4] {
        c.send_headers(s, &req("POST"), false).unwrap();
        drain(&mut c, s);
    }
    c.transport_closed();
    c.transport_closed();
    assert_eq!(
        events(&mut c),
        [Event::Closed {
            code: H3Code::NO_ERROR
        }]
    );
    assert_eq!(actions(&mut c), []);
    assert_eq!(
        c.abort(S0, H3Code::REQUEST_CANCELLED),
        Err(UsageError::Closed(H3Code::NO_ERROR))
    );
    assert_eq!(
        c.recv(S0, &status("200"), false),
        Err(ConnectionError::Closed(H3Code::NO_ERROR))
    );
    // After a connection error it is a no-op too.
    let mut c = client_ready(Config::default());
    assert!(c.recv(StreamId(1), b"x", false).is_err());
    c.transport_closed();
    assert_eq!(
        events(&mut c),
        [Event::Closed {
            code: H3Code::STREAM_CREATION_ERROR
        }]
    );
}

#[test]
fn exactly_one_terminal_event() {
    let (mut p, mut seen) = pair();
    let s8 = StreamId(8);
    let s12 = StreamId(12);
    let s16 = StreamId(16);
    // S0 completes; S4 client-aborted mid-request; S8 server-aborted after the request
    // finished; S12 a malformed request; S16 server stops the upload, then responds.
    for (s, m, end) in [(S0, "GET", true), (S4, "POST", false), (s8, "GET", true)] {
        p.client.send_headers(s, &req(m), end).unwrap();
    }
    p.client.send_headers(s16, &req("POST"), false).unwrap();
    p.feed(Side::Server, s12, &headers(&[(":method", "GET")]), true);
    settle(&mut p, &mut seen);
    p.client.abort(S4, H3Code::REQUEST_CANCELLED).unwrap();
    for s in [S0, s8, s16] {
        p.server
            .send_headers(s, &[f(":status", "200")], false)
            .unwrap();
    }
    settle(&mut p, &mut seen);
    p.server.abort(s8, H3Code::REQUEST_CANCELLED).unwrap();
    p.send_body(Side::Server, S0, b"ok", true);
    p.client
        .stop_sending_received(s16, H3Code::NO_ERROR)
        .unwrap();
    p.send_body(Side::Server, s16, b"done", true);
    settle(&mut p, &mut seen);
    // Repeat every termination input; nothing new may appear.
    for s in [S0, S4, s8, s12, s16] {
        for side in [Side::Client, Side::Server] {
            let c = p.conn(side);
            let _ = c.abort(s, H3Code::REQUEST_CANCELLED);
            c.stream_reset_received(s, H3Code::REQUEST_CANCELLED)
                .unwrap();
            c.stop_sending_received(s, H3Code::REQUEST_CANCELLED)
                .unwrap();
        }
    }
    settle(&mut p, &mut seen);
    assert!(p.closed.is_empty());
    let client = p.events(Side::Client);
    let server = p.events(Side::Server);
    for s in [S0, S4, s8, s16] {
        assert_eq!(terminal_count(&client, s), 1, "client {s:?}: {client:?}");
    }
    for s in [S0, S4, s8, s12, s16] {
        assert_eq!(terminal_count(&server, s), 1, "server {s:?}: {server:?}");
    }
    assert!(client.contains(&Event::Finished(S0)));
    assert!(client.contains(&Event::Finished(s16)));
    assert!(client.contains(&aborted(S4, H3Code::REQUEST_CANCELLED, AbortSource::Local)));
    assert!(client.contains(&aborted(s8, H3Code::REQUEST_CANCELLED, AbortSource::Peer)));
    assert!(server.contains(&Event::Finished(s8)));
    assert!(server.contains(&aborted(S4, H3Code::REQUEST_CANCELLED, AbortSource::Peer)));
    assert_eq!(p.bodies[&(Side::Client, s16)], b"done");
    for side in [Side::Client, Side::Server] {
        assert_eq!(p.conn(side).debug_stream_count(), CRITICAL, "{side:?}");
    }
}

#[test]
fn huge_ids_are_never_streams() {
    for (mut c, role) in [
        (client_ready(Config::default()), "client"),
        (server_ready(Config::default()), "server"),
    ] {
        for id in [1 << 62, u64::MAX - 3] {
            let s = StreamId(id);
            assert_eq!(
                c.send_headers(s, &req("GET"), true),
                Err(UsageError::UnknownStream),
                "{role} {id}"
            );
            assert_eq!(
                c.recv(s, &get_wire(), true),
                Ok(Recv::Consumed(get_wire().len())),
                "{role} {id}"
            );
            c.stream_reset_received(s, H3Code::REQUEST_CANCELLED)
                .unwrap();
            c.stop_sending_received(s, H3Code::REQUEST_CANCELLED)
                .unwrap();
            assert_eq!(
                c.abort(s, H3Code::REQUEST_CANCELLED),
                Err(UsageError::UnknownStream)
            );
        }
        assert_eq!(events(&mut c), [], "{role}");
        assert_eq!(actions(&mut c), [], "{role}");
        assert_eq!(c.debug_stream_count(), CRITICAL, "{role}");
        // Any other id: whatever the verdict, no panic.
        for id in [u64::MAX, u64::MAX - 1, (1 << 62) + 1] {
            let s = StreamId(id);
            let _ = c.send_headers(s, &req("GET"), true);
            let _ = c.recv(s, &get_wire(), true);
            let _ = c.stream_reset_received(s, H3Code::REQUEST_CANCELLED);
            let _ = c.stop_sending_received(s, H3Code::REQUEST_CANCELLED);
            let _ = c.abort(s, H3Code::REQUEST_CANCELLED);
        }
    }
}

#[test]
fn server_reset_before_first_byte_resets_our_half() {
    let mut c = server_ready(Config::default());
    c.stream_reset_received(S0, H3Code::REQUEST_CANCELLED)
        .unwrap();
    // The RESET_STREAM opened the bidi stream: our half is reset so its credit returns.
    assert_eq!(
        actions(&mut c),
        [Action::ResetStream {
            stream: S0,
            code: H3Code::REQUEST_CANCELLED
        }]
    );
    assert_eq!(
        events(&mut c),
        [aborted(S0, H3Code::REQUEST_CANCELLED, AbortSource::Peer)]
    );
    let w = get_wire();
    assert_eq!(c.recv(S0, &w, true), Ok(Recv::Consumed(w.len())));
    assert_eq!(events(&mut c), []);
    assert_eq!(c.debug_stream_count(), CRITICAL);
}

#[test]
fn server_stop_sending_before_request_still_receives() {
    let mut c = server_ready(Config::default());
    c.stop_sending_received(S0, H3Code::REQUEST_CANCELLED)
        .unwrap();
    assert_eq!(
        actions(&mut c),
        [Action::ResetStream {
            stream: S0,
            code: H3Code::REQUEST_CANCELLED
        }]
    );
    assert_eq!(
        events(&mut c),
        [Event::SendStopped {
            stream: S0,
            code: H3Code::REQUEST_CANCELLED
        }]
    );
    c.stop_sending_received(S0, H3Code::REQUEST_CANCELLED)
        .unwrap();
    assert_eq!(events(&mut c), []);
    let (evs, _) = run(&mut c, S0, &get_wire(), true);
    assert!(
        matches!(
            evs[..],
            [
                Event::Headers {
                    kind: HeadersKind::Request,
                    ..
                },
                Event::Finished(S0)
            ]
        ),
        "{evs:?}"
    );
    assert_eq!(actions(&mut c), []);
    assert_eq!(c.debug_stream_count(), CRITICAL, "reaped");
}

#[test]
fn peer_reset_after_finished_resets_response_only() {
    let (mut c, evs) = server_got(&get_wire(), true);
    assert_eq!(evs.last(), Some(&Event::Finished(S0)));
    c.send_headers(S0, &[f(":status", "200")], false).unwrap();
    drain(&mut c, S0);
    c.stream_reset_received(S0, H3Code::REQUEST_CANCELLED)
        .unwrap();
    assert_eq!(
        actions(&mut c),
        [Action::ResetStream {
            stream: S0,
            code: H3Code::REQUEST_CANCELLED
        }]
    );
    assert_eq!(events(&mut c), []);
    assert_eq!(c.debug_stream_count(), CRITICAL);
}
