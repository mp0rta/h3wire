mod support;

use h3wire::{Action, Config, Connection, Event, Role, StreamId, UniKind, UsageError};
use support::{Obs, Pair};

#[test]
#[ignore = "enabled in Task 10"]
fn startup_actions_and_settings_exchange() {
    let mut p = Pair::new(Config::default(), Config::default());
    p.drive();
    assert!(p.client.peer_settings().is_some() && p.server.peer_settings().is_some());
    let n = p
        .trace
        .iter()
        .filter(|o| matches!(o, Obs::Event(_, Event::PeerSettings)))
        .count();
    assert_eq!(n, 2);
    assert!(p.closed.is_empty());
}

#[test]
fn control_stream_starts_with_type_then_settings() {
    let mut cfg = Config::default();
    cfg.grease = false;
    let mut c = Connection::new(Role::Client, cfg);
    assert_eq!(c.poll_action(), Some(Action::OpenUni(UniKind::Control)));
    c.bind_uni(UniKind::Control, StreamId(2)).unwrap();
    assert_eq!(c.poll_send(StreamId(2)), Some(&[0x00, 0x04, 0x00][..]));
}

#[test]
fn blocked_stream_does_not_stall_others() {
    let mut c = Connection::new(Role::Client, Config::default());
    while c.poll_action().is_some() {}
    for (k, id) in [
        (UniKind::Control, 2),
        (UniKind::QpackEncoder, 6),
        (UniKind::QpackDecoder, 10),
    ] {
        c.bind_uni(k, StreamId(id)).unwrap();
    }
    assert_eq!(
        c.sendable().collect::<Vec<_>>(),
        vec![StreamId(2), StreamId(6), StreamId(10)]
    );
    // stream 2 accepts nothing; 6 and 10 can still be fully written
    for s in [StreamId(6), StreamId(10)] {
        let n = c.poll_send(s).unwrap().len();
        c.sent(s, n).unwrap();
    }
    assert_eq!(c.sendable().collect::<Vec<_>>(), vec![StreamId(2)]);
}

#[test]
fn bind_uni_rejects_wrong_stream() {
    let mut c = Connection::new(Role::Client, Config::default());
    assert_eq!(
        c.bind_uni(UniKind::Control, StreamId(0)),
        Err(UsageError::WrongStreamKind)
    );
    assert_eq!(
        c.bind_uni(UniKind::Control, StreamId(3)),
        Err(UsageError::WrongStreamKind)
    ); // server-initiated
}

#[test]
fn pair_drive_binds_and_writes_uni_streams() {
    let mut p = Pair::new(Config::default(), Config::default());
    p.opts.max_write = Some(1);
    p.opts.recv_chunk = Some(1);
    p.drive();
    for side in [support::Side::Client, support::Side::Server] {
        let opened = p
            .trace
            .iter()
            .filter(|o| matches!(o, Obs::Action(s, Action::OpenUni(_)) if *s == side))
            .count();
        assert_eq!(opened, 3);
        assert_eq!(p.conn(side).sendable().count(), 0);
    }
    assert!(p.closed.is_empty());
}
