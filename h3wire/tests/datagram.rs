mod support;

use h3wire::{
    Action, Config, Connection, ConnectionError, Datagram, Event, FieldRef, H3Code, Role, StreamId,
    UsageError,
};
use support::wire::{headers, settings};
use support::{client_ready_with, feed_all, server_ready};

const S0: StreamId = StreamId(0);
const S4: StreamId = StreamId(4);
const S8: StreamId = StreamId(8);
const DG: u64 = 0x33;

fn cfg(on: bool) -> Config {
    let mut c = Config::default();
    c.h3_datagram = on;
    c
}

fn req() -> Vec<FieldRef<'static>> {
    [
        (":method", "GET"),
        (":scheme", "https"),
        (":authority", "a"),
        (":path", "/"),
    ]
    .map(|(n, v)| FieldRef::new(n.as_bytes(), v.as_bytes()))
    .to_vec()
}

fn get_wire() -> Vec<u8> {
    headers(&[
        (":method", "GET"),
        (":scheme", "https"),
        (":authority", "a"),
        (":path", "/"),
    ])
}

fn drain(c: &mut Connection, s: StreamId) {
    let n = c.poll_send(s).map_or(0, <[u8]>::len);
    c.sent(s, n).unwrap();
}

fn closed_with(c: &mut Connection) -> Option<H3Code> {
    std::iter::from_fn(|| c.poll_action()).find_map(|a| match a {
        Action::CloseConnection { code, .. } => Some(code),
        _ => None,
    })
}

#[test]
fn prefix_requires_both_settings() {
    let mut buf = [0u8; 8];
    let mut c = client_ready_with(cfg(false), &[(DG, 1)]);
    c.send_headers(S4, &req(), false).unwrap();
    assert_eq!(
        c.datagram_prefix(S4, &mut buf),
        Err(UsageError::NotNegotiated)
    );
    let mut c = client_ready_with(cfg(true), &[]);
    c.send_headers(S4, &req(), false).unwrap();
    assert_eq!(
        c.datagram_prefix(S4, &mut buf),
        Err(UsageError::NotNegotiated)
    );
    let mut c = client_ready_with(cfg(true), &[(DG, 1)]);
    c.send_headers(S4, &req(), false).unwrap();
    assert_eq!(c.datagram_prefix(S4, &mut buf), Ok(1));
    assert_eq!(buf[0], 1);
}

#[test]
fn prefix_kind_and_unknown_stream() {
    let mut buf = [0u8; 8];
    let c = client_ready_with(cfg(true), &[(DG, 1)]);
    assert_eq!(
        c.datagram_prefix(StreamId(2), &mut buf),
        Err(UsageError::WrongStreamKind)
    );
    assert_eq!(c.datagram_prefix(S4, &mut buf), Err(UsageError::WrongPhase));
}

#[test]
fn prefix_needs_local_settings_written() {
    let mut c = Connection::new(Role::Client, cfg(true));
    let mut next = 2;
    while let Some(a) = c.poll_action() {
        if let Action::OpenUni(k) = a {
            c.bind_uni(k, StreamId(next)).unwrap();
            next += 4;
        }
    }
    let control = [&[0x00][..], &settings(&[(DG, 1)])].concat();
    feed_all(&mut c, StreamId(3), &control, false);
    c.send_headers(S4, &req(), false).unwrap();
    let mut buf = [0u8; 8];
    assert_eq!(
        c.datagram_prefix(S4, &mut buf),
        Err(UsageError::NotNegotiated)
    );
    let ids: Vec<StreamId> = c.sendable().collect();
    for s in ids {
        drain(&mut c, s);
    }
    assert_eq!(c.datagram_prefix(S4, &mut buf), Ok(1));
}

#[test]
fn prefix_refused_after_send_side_closed() {
    let mut c = client_ready_with(cfg(true), &[(DG, 1)]);
    c.send_headers(S4, &req(), true).unwrap();
    drain(&mut c, S4);
    assert!(std::iter::from_fn(|| c.poll_action()).any(|a| a == Action::FinishStream(S4)));
    let mut buf = [0u8; 8];
    assert_eq!(c.datagram_prefix(S4, &mut buf), Err(UsageError::WrongPhase));
}

#[test]
fn deliver_routes_by_quarter_id() {
    let mut c = server_ready(cfg(true));
    feed_all(&mut c, S4, &get_wire(), false);
    assert_eq!(
        c.parse_datagram(&[0x01, 0xaa, 0xbb]),
        Ok(Datagram::Deliver(S4, 1..3))
    );
}

#[test]
fn early_datagram_not_yet_open() {
    let mut c = server_ready(cfg(true));
    assert_eq!(
        c.parse_datagram(&[0x01, 0xaa]),
        Ok(Datagram::NotYetOpen(S4, 1..2))
    );
}

#[test]
fn unseen_lower_stream_is_not_yet_open() {
    let mut c = server_ready(cfg(true));
    feed_all(&mut c, S8, &get_wire(), false);
    assert_eq!(
        c.parse_datagram(&[0x00, 0x01]),
        Ok(Datagram::NotYetOpen(S0, 1..2))
    );
    assert_eq!(
        c.parse_datagram(&[0x02, 0x01]),
        Ok(Datagram::Deliver(S8, 1..2))
    );
}

#[test]
fn after_receive_close_dropped() {
    let mut c = server_ready(cfg(true));
    feed_all(&mut c, S4, &get_wire(), true);
    assert_eq!(c.parse_datagram(&[0x01, 0xaa]), Ok(Datagram::Drop));
}

#[test]
fn reaped_stream_dropped() {
    let mut c = server_ready(cfg(true));
    feed_all(&mut c, S4, &get_wire(), true);
    c.send_headers(S4, &[FieldRef::new(b":status", b"200")], true)
        .unwrap();
    drain(&mut c, S4);
    assert_eq!(c.debug_closed_ranges(), 1);
    assert_eq!(c.parse_datagram(&[0x01, 0xaa]), Ok(Datagram::Drop));
}

#[test]
fn disabled_locally_drops() {
    let mut c = server_ready(cfg(false));
    feed_all(&mut c, S4, &get_wire(), false);
    assert_eq!(c.parse_datagram(&[0x01, 0xaa]), Ok(Datagram::Drop));
    // Malformed ids are errors even when datagrams are off.
    assert_eq!(
        c.parse_datagram(&[0x40]),
        Err(ConnectionError::Closed(H3Code::DATAGRAM_ERROR))
    );
}

#[test]
fn truncated_quarter_id_is_datagram_error() {
    for p in [&[0x40][..], &[]] {
        let mut c = server_ready(cfg(true));
        assert_eq!(
            c.parse_datagram(p),
            Err(ConnectionError::Closed(H3Code::DATAGRAM_ERROR))
        );
        assert_eq!(closed_with(&mut c), Some(H3Code::DATAGRAM_ERROR));
        assert_eq!(
            c.parse_datagram(&[0x01]),
            Err(ConnectionError::Closed(H3Code::DATAGRAM_ERROR))
        );
    }
}

#[test]
fn quarter_id_over_limit_is_datagram_error() {
    let mut c = server_ready(cfg(true));
    assert_eq!(
        c.parse_datagram(&[0xd0, 0, 0, 0, 0, 0, 0, 0]),
        Err(ConnectionError::Closed(H3Code::DATAGRAM_ERROR))
    );
    let mut c = server_ready(cfg(true));
    assert_eq!(
        c.parse_datagram(&[0xcf, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff]),
        Ok(Datagram::NotYetOpen(StreamId(((1u64 << 60) - 1) * 4), 8..8))
    );
}

#[test]
fn bad_h3_datagram_setting_value() {
    let mut c = Connection::new(Role::Server, cfg(true));
    let control = [&[0x00][..], &settings(&[(DG, 2)])].concat();
    let r = c.recv(StreamId(2), &control, false);
    assert_eq!(r, Err(ConnectionError::Closed(H3Code::SETTINGS_ERROR)));
    assert_eq!(closed_with(&mut c), Some(H3Code::SETTINGS_ERROR));
    assert!(std::iter::from_fn(|| c.poll_event()).any(|e| matches!(e, Event::Closed { .. })));
}
