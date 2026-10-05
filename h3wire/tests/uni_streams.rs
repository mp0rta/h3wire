mod support;

use h3wire::{
    Action, Config, Connection, ConnectionError, Event, H3Code, Recv, Role, StreamId, UsageError,
};
use support::wire::{frame, settings, varint};
use support::{client_ready, server_ready};

const MAX_PUSH_ID: u64 = 0x0d;
const CANCEL_PUSH: u64 = 0x03;
const GOAWAY: u64 = 0x07;

/// Peer control stream of a `server_ready` / `client_ready` connection.
const CLIENT_CONTROL: StreamId = StreamId(2);
const SERVER_CONTROL: StreamId = StreamId(3);

fn server() -> Connection {
    server_ready(Config::default())
}

fn client() -> Connection {
    client_ready(Config::default())
}

/// `r` is the connection error `code`, and the close action and event were queued.
#[track_caller]
fn assert_closed<T: std::fmt::Debug>(
    c: &mut Connection,
    r: Result<T, ConnectionError>,
    code: H3Code,
) {
    assert_eq!(r.unwrap_err(), ConnectionError::Closed(code));
    let actions: Vec<Action> = std::iter::from_fn(|| c.poll_action()).collect();
    assert!(
        matches!(actions.last(), Some(Action::CloseConnection { code: c, .. }) if *c == code),
        "{actions:?}"
    );
    let events: Vec<Event> = std::iter::from_fn(|| c.poll_event()).collect();
    assert_eq!(events.last(), Some(&Event::Closed { code }));
}

#[track_caller]
fn assert_quiet(c: &mut Connection) {
    assert_eq!(c.poll_action(), None);
    assert_eq!(c.poll_event(), None);
}

#[test]
fn first_frame_not_settings_is_missing_settings() {
    for first in [frame(GOAWAY, &[0x00]), frame(0x21, &[]), frame(0x40, &[])] {
        let mut c = Connection::new(Role::Server, Config::default());
        while c.poll_action().is_some() {}
        let r = c.recv(CLIENT_CONTROL, &[&[0x00][..], &first].concat(), false);
        assert_closed(&mut c, r, H3Code::MISSING_SETTINGS);
    }
}

#[test]
fn second_settings_is_frame_unexpected() {
    let mut c = server();
    let r = c.recv(CLIENT_CONTROL, &settings(&[]), false);
    assert_closed(&mut c, r, H3Code::FRAME_UNEXPECTED);
}

#[test]
fn data_on_control_is_frame_unexpected() {
    // DATA, HEADERS, PUSH_PROMISE.
    for ty in [0x00, 0x01, 0x05] {
        let mut c = server();
        let r = c.recv(CLIENT_CONTROL, &frame(ty, b"x"), false);
        assert_closed(&mut c, r, H3Code::FRAME_UNEXPECTED);
    }
}

#[test]
fn h2_reserved_frame_on_control_is_frame_unexpected() {
    for ty in [0x02, 0x06, 0x08, 0x09] {
        let mut c = client();
        let r = c.recv(SERVER_CONTROL, &frame(ty, &[]), false);
        assert_closed(&mut c, r, H3Code::FRAME_UNEXPECTED);
    }
}

#[test]
fn oversized_settings_is_excessive_load() {
    let mut c = Connection::new(Role::Server, Config::default());
    while c.poll_action().is_some() {}
    let bytes = [&[0x00, 0x04][..], &varint((1 << 62) - 1)].concat();
    let r = c.recv(CLIENT_CONTROL, &bytes, false);
    assert_closed(&mut c, r, H3Code::EXCESSIVE_LOAD);
}

#[test]
fn invalid_settings_is_settings_error() {
    let mut c = Connection::new(Role::Client, Config::default());
    while c.poll_action().is_some() {}
    let bytes = [&[0x00][..], &settings(&[(0x08, 2)])].concat();
    let r = c.recv(SERVER_CONTROL, &bytes, false);
    assert_closed(&mut c, r, H3Code::SETTINGS_ERROR);
}

#[test]
fn goaway_len_9_is_frame_error() {
    let mut c = server();
    let r = c.recv(CLIENT_CONTROL, &[GOAWAY as u8, 0x09], false);
    assert_closed(&mut c, r, H3Code::FRAME_ERROR);
}

#[test]
fn goaway_trailing_bytes_is_frame_error() {
    let mut c = client();
    let r = c.recv(SERVER_CONTROL, &frame(GOAWAY, &[0x04, 0x00]), false);
    assert_closed(&mut c, r, H3Code::FRAME_ERROR);
}

#[test]
fn client_gets_max_push_id_frame_unexpected() {
    let mut c = client();
    let r = c.recv(SERVER_CONTROL, &frame(MAX_PUSH_ID, &[0x04]), false);
    assert_closed(&mut c, r, H3Code::FRAME_UNEXPECTED);
}

#[test]
fn decreasing_max_push_id_is_id_error() {
    let mut c = server();
    let f = frame(MAX_PUSH_ID, &[0x04]);
    assert_eq!(
        c.recv(CLIENT_CONTROL, &f, false),
        Ok(Recv::Consumed(f.len()))
    );
    assert_quiet(&mut c);
    let r = c.recv(CLIENT_CONTROL, &frame(MAX_PUSH_ID, &[0x03]), false);
    assert_closed(&mut c, r, H3Code::ID_ERROR);
}

#[test]
fn cancel_push_is_id_error() {
    let mut c = server();
    let r = c.recv(CLIENT_CONTROL, &frame(CANCEL_PUSH, &[0x00]), false);
    assert_closed(&mut c, r, H3Code::ID_ERROR);
    let mut c = client();
    let r = c.recv(SERVER_CONTROL, &frame(CANCEL_PUSH, &[0x00]), false);
    assert_closed(&mut c, r, H3Code::ID_ERROR);
}

#[test]
fn duplicate_control_stream_is_stream_creation_error() {
    let mut c = server();
    let r = c.recv(StreamId(6), &[0x00], false);
    assert_closed(&mut c, r, H3Code::STREAM_CREATION_ERROR);
    for ty in [0x02, 0x03] {
        let mut c = client();
        assert_eq!(c.recv(StreamId(7), &[ty], false), Ok(Recv::Consumed(1)));
        let r = c.recv(StreamId(11), &[ty], false);
        assert_closed(&mut c, r, H3Code::STREAM_CREATION_ERROR);
    }
}

#[test]
fn control_fin_is_closed_critical_stream() {
    let mut c = server();
    let r = c.recv(CLIENT_CONTROL, &[], true);
    assert_closed(&mut c, r, H3Code::CLOSED_CRITICAL_STREAM);
    for ty in [0x02, 0x03] {
        let mut c = server();
        let r = c.recv(StreamId(6), &[ty], true);
        assert_closed(&mut c, r, H3Code::CLOSED_CRITICAL_STREAM);
    }
}

#[test]
fn qpack_encoder_reset_is_closed_critical_stream() {
    let mut c = server();
    assert_eq!(c.recv(StreamId(6), &[0x02], false), Ok(Recv::Consumed(1)));
    let r = c.stream_reset_received(StreamId(6), H3Code::NO_ERROR);
    assert_closed(&mut c, r, H3Code::CLOSED_CRITICAL_STREAM);
    let mut c = client();
    let r = c.stream_reset_received(SERVER_CONTROL, H3Code::NO_ERROR);
    assert_closed(&mut c, r, H3Code::CLOSED_CRITICAL_STREAM);
}

#[test]
fn stop_sending_on_own_control_is_closed_critical_stream() {
    // server_ready binds its control/encoder/decoder streams to 3, 7, 11.
    for s in [3, 7, 11] {
        let mut c = server();
        let r = c.stop_sending_received(StreamId(s), H3Code::NO_ERROR);
        assert_closed(&mut c, r, H3Code::CLOSED_CRITICAL_STREAM);
    }
}

#[test]
fn push_stream_by_role() {
    let mut c = client();
    let r = c.recv(StreamId(7), &[0x01, 0x00], false);
    assert_closed(&mut c, r, H3Code::ID_ERROR);
    let mut c = server();
    let r = c.recv(StreamId(6), &[0x01, 0x00], false);
    assert_closed(&mut c, r, H3Code::STREAM_CREATION_ERROR);
}

#[test]
fn encoder_insert_is_qpack_encoder_stream_error() {
    let mut c = server();
    let r = c.recv(StreamId(6), &[0x02, 0xc1, 0x01, b'a'], false);
    assert_closed(&mut c, r, H3Code::QPACK_ENCODER_STREAM_ERROR);
    let mut c = server();
    let r = c.recv(StreamId(6), &[0x03, 0x84], false);
    assert_closed(&mut c, r, H3Code::QPACK_DECODER_STREAM_ERROR);
}

#[test]
fn encoder_set_capacity_zero_tolerated() {
    let mut c = server();
    assert_eq!(
        c.recv(StreamId(6), &[0x02, 0x20], false),
        Ok(Recv::Consumed(2))
    );
    assert_eq!(c.recv(StreamId(6), &[0x20], false), Ok(Recv::Consumed(1)));
    assert_quiet(&mut c);
}

#[test]
fn server_bidi_to_client_is_stream_creation_error() {
    let mut c = client();
    let r = c.recv(StreamId(1), b"x", false);
    assert_closed(&mut c, r, H3Code::STREAM_CREATION_ERROR);
}

#[test]
fn unknown_uni_type_gets_stop_sending() {
    let mut c = server();
    assert_eq!(
        c.recv(StreamId(6), &[0x21, 1, 2], false),
        Ok(Recv::Consumed(3))
    );
    assert_eq!(
        c.poll_action(),
        Some(Action::StopSending {
            stream: StreamId(6),
            code: H3Code::STREAM_CREATION_ERROR
        })
    );
    assert_eq!(c.recv(StreamId(6), &[3, 4], false), Ok(Recv::Consumed(2)));
    assert_eq!(c.recv(StreamId(6), &[5], true), Ok(Recv::Consumed(1)));
    assert_quiet(&mut c);
    // Still open.
    let f = frame(MAX_PUSH_ID, &[0x04]);
    assert_eq!(
        c.recv(CLIENT_CONTROL, &f, false),
        Ok(Recv::Consumed(f.len()))
    );
}

#[test]
fn uni_closed_before_type_is_ignored() {
    let mut c = server();
    assert_eq!(c.recv(StreamId(6), &[0x40], true), Ok(Recv::Consumed(1)));
    assert_quiet(&mut c);
    assert_eq!(c.recv(StreamId(10), &[0x40], false), Ok(Recv::Consumed(1)));
    assert_eq!(
        c.stream_reset_received(StreamId(10), H3Code::NO_ERROR),
        Ok(())
    );
    assert_quiet(&mut c);
}

#[test]
fn registered_uni_stream_yields_event_then_raw() {
    let mut cfg = Config::default();
    cfg.register_uni_stream(0x54).unwrap();
    let mut c = server_ready(cfg);
    // Type varint 0x54 encoded in two bytes, then payload in the same chunk.
    assert_eq!(
        c.recv(StreamId(6), &[0x40, 0x54, b'h', b'i'], false),
        Ok(Recv::Raw {
            consumed: 4,
            range: 2..4
        })
    );
    assert_eq!(
        c.poll_event(),
        Some(Event::UniStream {
            stream: StreamId(6),
            ty: 0x54
        })
    );
    assert_eq!(
        c.recv(StreamId(6), b"xyz", false),
        Ok(Recv::Raw {
            consumed: 3,
            range: 0..3
        })
    );
    // Type split across calls.
    assert_eq!(c.recv(StreamId(10), &[0x40], false), Ok(Recv::Consumed(1)));
    assert_eq!(
        c.recv(StreamId(10), &[0x54, b'a'], true),
        Ok(Recv::Raw {
            consumed: 2,
            range: 1..2
        })
    );
    assert_eq!(
        c.poll_event(),
        Some(Event::UniStream {
            stream: StreamId(10),
            ty: 0x54
        })
    );
    assert_eq!(c.recv(StreamId(6), &[], true), Ok(Recv::Consumed(0)));
    assert_quiet(&mut c);
}

#[test]
fn unknown_control_frames_are_streamed() {
    let mut c = server();
    let mut f = Vec::new();
    h3wire::frame::encode_header(0x21 + 0x1f * 5, 1 << 20, &mut f);
    f.resize(f.len() + (1 << 20), 0xab);
    for piece in f.chunks(1024) {
        let mut rest = piece;
        while !rest.is_empty() {
            match c.recv(CLIENT_CONTROL, rest, false) {
                Ok(Recv::Consumed(n)) if n > 0 && n <= rest.len() => rest = &rest[n..],
                r => panic!("{r:?}"),
            }
        }
    }
    assert_quiet(&mut c);
    // The next frame is parsed normally.
    let r = c.recv(CLIENT_CONTROL, &settings(&[]), false);
    assert_closed(&mut c, r, H3Code::FRAME_UNEXPECTED);
}

#[test]
fn priority_update_is_ignored() {
    let mut c = server();
    for ty in [0xf0700, 0xf0701] {
        let f = frame(ty, &[0x00, 0x01]);
        assert_eq!(
            c.recv(CLIENT_CONTROL, &f, false),
            Ok(Recv::Consumed(f.len()))
        );
    }
    assert_quiet(&mut c);
}

#[test]
fn after_close_every_call_is_closed() {
    let mut c = server();
    let code = H3Code::FRAME_UNEXPECTED;
    let _ = c.recv(CLIENT_CONTROL, &settings(&[]), false);
    let closed = ConnectionError::Closed(code);
    let usage = UsageError::Closed(code);
    let s = StreamId(0);
    assert_eq!(c.recv(s, b"x", false), Err(closed));
    assert_eq!(c.recv(StreamId(6), &[0x02], false), Err(closed));
    assert_eq!(c.send_headers(s, &[], true), Err(usage));
    assert_eq!(c.send_data(s, 1, true), Err(usage));
    assert_eq!(c.data_written(s, 1), Err(usage));
    assert_eq!(c.abort(s, H3Code::REQUEST_CANCELLED), Err(usage));
    assert_eq!(c.stream_reset_received(s, H3Code::NO_ERROR), Err(closed));
    assert_eq!(c.stop_sending_received(s, H3Code::NO_ERROR), Err(closed));
    assert_eq!(c.start_shutdown(), Err(usage));
    assert_eq!(c.finish_shutdown(), Err(usage));
    assert_eq!(c.datagram_prefix(s, &mut [0; 8]), Err(usage));
    assert_eq!(c.parse_datagram(&[0x00]), Err(closed));
    assert_eq!(
        c.bind_uni(h3wire::UniKind::Control, StreamId(15)),
        Err(usage)
    );
    assert_eq!(c.sent(StreamId(3), 0), Err(usage));
    assert_eq!(c.sendable().count(), 0);
    assert_eq!(c.poll_send(StreamId(3)), None);
    c.transport_closed();
    assert!(c.peer_settings().is_some());
    // The queues still drain: one CloseConnection, one Closed, nothing else.
    assert!(matches!(
        c.poll_action(),
        Some(Action::CloseConnection { code: c, .. }) if c == code
    ));
    assert_eq!(c.poll_event(), Some(Event::Closed { code }));
    assert_quiet(&mut c);
}
