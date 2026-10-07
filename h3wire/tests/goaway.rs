// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 mp0rta
mod support;

use h3wire::{
    AbortSource, Action, Config, Connection, ConnectionError, Contexts, Event, FieldRef,
    FrameExtension, H3Code, HeadersKind, Recv, Role, StreamId, UniKind, UsageError,
};
use support::wire::{frame, headers, varint};
use support::{client_ready, feed_all, server_ready};

const S0: StreamId = StreamId(0);
const S4: StreamId = StreamId(4);
const S8: StreamId = StreamId(8);
const S12: StreamId = StreamId(12);
/// The last client-initiated bidirectional stream id.
const LAST: u64 = (1 << 62) - 4;
/// Local control streams as bound by the `*_ready` helpers.
const SERVER_CONTROL: StreamId = StreamId(3);
const CLIENT_CONTROL: StreamId = StreamId(2);
const GOAWAY: u64 = 0x07;

fn f(name: &'static str, value: &'static str) -> FieldRef<'static> {
    FieldRef::new(name.as_bytes(), value.as_bytes())
}

fn req() -> Vec<FieldRef<'static>> {
    vec![
        f(":method", "GET"),
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

fn goaway(id: u64) -> Vec<u8> {
    frame(GOAWAY, &varint(id))
}

fn events(c: &mut Connection) -> Vec<Event> {
    std::iter::from_fn(|| c.poll_event()).collect()
}

fn actions(c: &mut Connection) -> Vec<Action> {
    std::iter::from_fn(|| c.poll_action()).collect()
}

/// Everything queued on stream `s`, marked as written.
fn take(c: &mut Connection, s: StreamId) -> Vec<u8> {
    let out = c.poll_send(s).map(<[u8]>::to_vec).unwrap_or_default();
    c.sent(s, out.len()).unwrap();
    out
}

fn aborted(stream: StreamId, code: H3Code, source: AbortSource) -> Event {
    Event::StreamAborted {
        stream,
        code,
        source,
    }
}

fn has_headers(evs: &[Event], s: StreamId) -> bool {
    evs.iter()
        .any(|e| matches!(e, Event::Headers { stream, .. } if *stream == s))
}

/// A server that received (processed) the request HEADERS of each of `ids`.
fn server_processed(cfg: Config, ids: &[u64]) -> Connection {
    let mut c = server_ready(cfg);
    for &id in ids {
        feed_all(&mut c, StreamId(id), &get_wire(), false);
    }
    events(&mut c);
    actions(&mut c);
    c
}

/// A client with requests (not ended) open on each of `ids`; queues drained.
fn client_requests(ids: &[u64]) -> Connection {
    let mut c = client_ready(Config::default());
    for &id in ids {
        c.send_headers(StreamId(id), &req(), false).unwrap();
        take(&mut c, StreamId(id));
    }
    events(&mut c);
    actions(&mut c);
    c
}

#[test]
fn server_two_phase_goaway() {
    let mut c = server_ready(Config::default());
    c.start_shutdown().unwrap();
    assert_eq!(take(&mut c, SERVER_CONTROL), goaway(LAST));
    feed_all(&mut c, S0, &get_wire(), false);
    feed_all(&mut c, S4, &get_wire(), false);
    c.finish_shutdown().unwrap();
    assert_eq!(take(&mut c, SERVER_CONTROL), goaway(8));
    // Both requests were processed: neither is rejected.
    assert!(
        !actions(&mut c)
            .iter()
            .any(|a| matches!(a, Action::ResetStream { .. } | Action::StopSending { .. }))
    );
}

#[test]
fn start_after_finish_does_not_increase() {
    let mut c = server_ready(Config::default());
    c.start_shutdown().unwrap();
    feed_all(&mut c, S0, &get_wire(), false);
    feed_all(&mut c, S4, &get_wire(), false);
    c.finish_shutdown().unwrap();
    c.start_shutdown().unwrap();
    c.finish_shutdown().unwrap();
    assert_eq!(
        take(&mut c, SERVER_CONTROL),
        [goaway(LAST), goaway(8)].concat()
    );
}

#[test]
fn request_above_cutoff_rejected_before_delivery() {
    let mut c = server_processed(Config::default(), &[0, 4]);
    c.finish_shutdown().unwrap();
    feed_all(&mut c, S8, &get_wire(), false);
    let evs = events(&mut c);
    assert!(!has_headers(&evs, S8));
    assert_eq!(
        evs,
        [aborted(S8, H3Code::REQUEST_REJECTED, AbortSource::Local)]
    );
    assert!(actions(&mut c).contains(&Action::ResetStream {
        stream: S8,
        code: H3Code::REQUEST_REJECTED
    }));
}

#[test]
fn partial_stream_crossing_cutoff_rejected() {
    let mut c = server_ready(Config::default());
    let w = get_wire();
    assert_eq!(c.recv(S8, &w[..1], false).unwrap(), Recv::Consumed(1));
    feed_all(&mut c, S0, &get_wire(), false);
    events(&mut c);
    c.finish_shutdown().unwrap();
    assert_eq!(take(&mut c, SERVER_CONTROL), goaway(4));
    assert_eq!(
        actions(&mut c),
        [
            Action::ResetStream {
                stream: S8,
                code: H3Code::REQUEST_REJECTED
            },
            Action::StopSending {
                stream: S8,
                code: H3Code::REQUEST_REJECTED
            },
        ]
    );
    assert_eq!(
        events(&mut c),
        [aborted(S8, H3Code::REQUEST_REJECTED, AbortSource::Local)]
    );
    feed_all(&mut c, S8, &w[1..], false);
    assert!(events(&mut c).is_empty());
}

#[test]
fn processed_by_extension_frame() {
    let mut cfg = Config::default();
    cfg.register_frame(FrameExtension {
        ty: 0x2a,
        contexts: Contexts::REQUEST,
    })
    .unwrap();
    let mut c = server_ready(cfg);
    let r = c.recv(S8, &frame(0x2a, b"x"), false).unwrap();
    assert!(matches!(r, Recv::Frame { ty: 0x2a, .. }));
    c.finish_shutdown().unwrap();
    assert_eq!(take(&mut c, SERVER_CONTROL), goaway(12));
    // Processed: its HEADERS are still delivered.
    feed_all(&mut c, S8, &get_wire(), false);
    assert!(has_headers(&events(&mut c), S8));
}

#[test]
fn exhausted_ids_send_no_goaway() {
    type Method = fn(&mut Connection) -> Result<(), UsageError>;
    for m in [
        Connection::start_shutdown as Method,
        Connection::finish_shutdown,
    ] {
        let mut c = server_processed(Config::default(), &[LAST]);
        m(&mut c).unwrap();
        assert_eq!(c.poll_send(SERVER_CONTROL), None);
        assert!(actions(&mut c).is_empty());
    }
}

#[test]
fn goaway_before_control_bound_follows_settings() {
    let mut cfg = Config::default();
    cfg.grease = false;
    let mut plain = Connection::new(Role::Server, cfg.clone());
    plain.bind_uni(UniKind::Control, SERVER_CONTROL).unwrap();
    let settings = take(&mut plain, SERVER_CONTROL);
    let mut c = Connection::new(Role::Server, cfg);
    c.start_shutdown().unwrap();
    c.finish_shutdown().unwrap();
    c.bind_uni(UniKind::Control, SERVER_CONTROL).unwrap();
    // Only the lowest (last) cutoff goes out: it supersedes the earlier one.
    assert_eq!(take(&mut c, SERVER_CONTROL), [settings, goaway(0)].concat());
}

#[test]
fn client_sends_goaway_zero_once() {
    let mut c = client_requests(&[0]);
    c.start_shutdown().unwrap();
    c.finish_shutdown().unwrap();
    c.start_shutdown().unwrap();
    assert_eq!(take(&mut c, CLIENT_CONTROL), goaway(0));
    // Requests are unaffected.
    assert!(actions(&mut c).is_empty());
    c.send_headers(S4, &req(), true).unwrap();
}

#[test]
fn client_goaway_increase_is_id_error() {
    let mut c = client_ready(Config::default());
    feed_all(&mut c, SERVER_CONTROL, &goaway(4), false);
    assert_eq!(events(&mut c), [Event::GoAway { id: 4 }]);
    assert_eq!(
        c.recv(SERVER_CONTROL, &goaway(8), false),
        Err(ConnectionError::Closed(H3Code::ID_ERROR))
    );
    assert!(matches!(
        actions(&mut c)[..],
        [Action::CloseConnection {
            code: H3Code::ID_ERROR,
            ..
        }]
    ));
}

#[test]
fn client_goaway_non_bidi_id_is_id_error() {
    let mut c = client_ready(Config::default());
    assert_eq!(
        c.recv(SERVER_CONTROL, &goaway(2), false),
        Err(ConnectionError::Closed(H3Code::ID_ERROR))
    );
    assert_eq!(
        events(&mut c),
        [Event::Closed {
            code: H3Code::ID_ERROR
        }]
    );
}

#[test]
fn client_rejects_requests_at_or_above() {
    let mut c = client_requests(&[0, 4, 8]);
    feed_all(&mut c, SERVER_CONTROL, &goaway(4), false);
    let evs = events(&mut c);
    let rejected = |s| aborted(s, H3Code::REQUEST_REJECTED, AbortSource::GoAway);
    assert_eq!(evs, [Event::GoAway { id: 4 }, rejected(S4), rejected(S8)]);
    assert!(evs[1..].iter().all(Event::retryable));
    let cancelled = H3Code::REQUEST_CANCELLED;
    assert_eq!(
        actions(&mut c),
        [
            Action::ResetStream {
                stream: S4,
                code: cancelled
            },
            Action::StopSending {
                stream: S4,
                code: cancelled
            },
            Action::ResetStream {
                stream: S8,
                code: cancelled
            },
            Action::StopSending {
                stream: S8,
                code: cancelled
            },
        ]
    );
    // Stream 0 is unaffected.
    c.send_headers(S0, &[f("x-t", "1")], true).unwrap();
}

#[test]
fn client_goaway_spares_stream_with_response() {
    let mut c = client_requests(&[0, 4, 8, 12]);
    feed_all(&mut c, S8, &headers(&[(":status", "200")]), false);
    // A 1xx counts as response data delivered.
    feed_all(&mut c, S12, &headers(&[(":status", "103")]), false);
    let evs = events(&mut c);
    assert!(has_headers(&evs, S8) && has_headers(&evs, S12));
    feed_all(&mut c, SERVER_CONTROL, &goaway(4), false);
    assert_eq!(
        events(&mut c),
        [
            Event::GoAway { id: 4 },
            aborted(S4, H3Code::REQUEST_REJECTED, AbortSource::GoAway)
        ]
    );
    // Stream 8 keeps receiving.
    feed_all(&mut c, S8, &frame(0x00, b"ok"), true);
    assert_eq!(events(&mut c), [Event::Finished(S8)]);
}

#[test]
fn client_cannot_start_request_after_goaway() {
    let mut c = client_ready(Config::default());
    feed_all(&mut c, SERVER_CONTROL, &goaway(8), false);
    assert_eq!(c.send_headers(S0, &req(), true), Err(UsageError::GoingAway));
}

#[test]
fn server_ignores_client_goaway_for_requests() {
    let mut c = server_processed(Config::default(), &[0]);
    let mut s4 = get_wire();
    let tail = s4.split_off(1);
    feed_all(&mut c, S4, &s4, false);
    // A push ID: any value, decreasing or equal.
    for id in [7, 3, 3] {
        feed_all(&mut c, CLIENT_CONTROL, &goaway(id), false);
        assert_eq!(events(&mut c), [Event::GoAway { id }]);
    }
    assert!(actions(&mut c).is_empty());
    feed_all(&mut c, S4, &tail, false);
    let evs = events(&mut c);
    assert!(matches!(
        evs[..],
        [Event::Headers {
            stream: S4,
            kind: HeadersKind::Request,
            ..
        }]
    ));
    c.send_headers(S0, &[f(":status", "200")], true).unwrap();
    assert_eq!(
        c.recv(CLIENT_CONTROL, &goaway(4), false),
        Err(ConnectionError::Closed(H3Code::ID_ERROR))
    );
}

#[test]
fn peer_rejected_is_retryable_cancelled_is_not() {
    let mut c = client_requests(&[0, 4, 8]);
    c.stream_reset_received(S0, H3Code::REQUEST_REJECTED)
        .unwrap();
    c.stream_reset_received(S4, H3Code::REQUEST_CANCELLED)
        .unwrap();
    c.abort(S8, H3Code::REQUEST_CANCELLED).unwrap();
    let evs = events(&mut c);
    assert_eq!(
        evs,
        [
            aborted(S0, H3Code::REQUEST_REJECTED, AbortSource::Peer),
            aborted(S4, H3Code::REQUEST_CANCELLED, AbortSource::Peer),
            aborted(S8, H3Code::REQUEST_CANCELLED, AbortSource::Local),
        ]
    );
    assert_eq!(
        evs.iter().map(Event::retryable).collect::<Vec<_>>(),
        [true, false, false]
    );
    assert!(!Event::Finished(S0).retryable());
    assert!(
        !Event::Closed {
            code: H3Code::NO_ERROR
        }
        .retryable()
    );
}

#[test]
fn server_send_headers_before_request_headers_is_wrong_phase() {
    let mut c = server_ready(Config::default());
    // Partially received request HEADERS.
    assert_eq!(
        c.recv(S0, &get_wire()[..1], false).unwrap(),
        Recv::Consumed(1)
    );
    assert_eq!(
        c.send_headers(S0, &[f(":status", "200")], true),
        Err(UsageError::WrongPhase)
    );
}
