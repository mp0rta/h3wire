//! v0.1 acceptance index (spec section 5.2, gate (a) of spec section 1.2).
//!
//! Every bullet of the "v0.1 acceptance suite" and the test(s) that cover it.
//! `file::name` is `h3wire/tests/file.rs`; `src/...` names a unit test.
//!
//! - Extended CONNECT
//!   - negotiated success -> tunnel: `recv_request::tunnel_bytes_flow_both_ways`
//!   - attempt without the peer setting, client `UsageError`:
//!     `send_request::extended_connect_needs_peer_setting`
//!   - attempt without the peer setting, server `H3_MESSAGE_ERROR`:
//!     `recv_request::server_rejects_unadvertised_protocol`
//!   - non-2xx final response returns to regular message:
//!     `recv_request::connect_non_2xx_returns_to_regular`,
//!     `src/conn/send.rs::server_connect_2xx_is_tunnel`
//!   - 1xx before 2xx: `acceptance::ext_connect_1xx_then_2xx`
//! - HTTP Datagrams
//!   - both-sides gating: `datagram::prefix_requires_both_settings`,
//!     `datagram::prefix_needs_local_settings_written`, `datagram::disabled_locally_drops`
//!   - send-side-closed refusal: `datagram::prefix_refused_after_send_side_closed`
//!   - early arrival (`NotYetOpen`): `datagram::early_datagram_not_yet_open`,
//!     `datagram::unseen_lower_stream_is_not_yet_open`
//!   - after receive-side close (`Drop`): `datagram::after_receive_close_dropped`,
//!     `datagram::reaped_stream_dropped`
//!   - bad Quarter Stream ID: `datagram::truncated_quarter_id_is_datagram_error`,
//!     `datagram::quarter_id_over_limit_is_datagram_error`
//!   - bad setting value: `datagram::bad_h3_datagram_setting_value`
//! - Directional termination
//!   - peer STOP_SENDING then a complete response (delivered):
//!     `termination::stop_sending_then_complete_response_delivered`
//!   - peer RESET: `termination::peer_reset_aborts_stream`
//!   - local `abort`: `termination::local_abort_emits_both_directions`
//! - GOAWAY in both directions, including invalid ids:
//!   `acceptance::goaway_both_directions_in_one_pair`, `goaway::server_two_phase_goaway`,
//!   `goaway::client_sends_goaway_zero_once`, `goaway::client_rejects_requests_at_or_above`;
//!   invalid ids: `goaway::client_goaway_increase_is_id_error`,
//!   `goaway::client_goaway_non_bidi_id_is_id_error`,
//!   `goaway::server_ignores_client_goaway_for_requests` (increasing push ID)
//! - Critical streams
//!   - FIN: `uni_streams::control_fin_is_closed_critical_stream`
//!   - RESET: `uni_streams::qpack_encoder_reset_is_closed_critical_stream`
//!   - STOP_SENDING: `uni_streams::stop_sending_on_own_control_is_closed_critical_stream`
//!   - duplicate critical stream: `uni_streams::duplicate_control_stream_is_stream_creation_error`
//!   - unknown uni stream: `uni_streams::unknown_uni_type_gets_stop_sending`
//!   - early-closed uni stream: `uni_streams::uni_closed_before_type_is_ignored`
//!   - push matrix by role: `uni_streams::push_stream_by_role`,
//!     `recv_request::push_promise_by_role`
//! - Incomplete message at FIN (both roles):
//!   `recv_request::empty_request_stream_fin_is_request_incomplete` (server),
//!   `recv_request::fin_without_final_response_is_message_error` (client)
//! - Content-Length with HEAD/204/304: `recv_request::content_length_ignored_for_head_204_304`,
//!   `recv_request::head_request_content_length_checked`,
//!   `recv_request::data_in_head_response_is_message_error`
//! - QPACK 'N' bit round trip (wire-level): `recv_request::never_index_survives_roundtrip`,
//!   `src/qpack/encoder.rs::encode_never_index_uses_n_bit`
//! - One write-blocked stream does not stall others: `setup::blocked_stream_does_not_stall_others`,
//!   `acceptance::write_blocked_stream_in_pair`
//!
//! Also here: `memory_bound_holds_after_release` (spec section 5.3, "no unbounded memory
//! growth": the bound the `api_ops` fuzz target asserts).

mod support;

use h3wire::{Config, Event, FieldRef, HeadersKind, StreamId, UsageError};
use support::wire::frame;
use support::{Pair, Seen, Side, feed_all, server_ready};

const S0: StreamId = StreamId(0);
const S4: StreamId = StreamId(4);
const CLIENT_CONTROL: StreamId = StreamId(2);

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

fn kinds(seen: &[Seen], s: StreamId) -> Vec<HeadersKind> {
    seen.iter()
        .filter_map(|e| match e {
            Seen::Headers { stream, kind, .. } if *stream == s => Some(*kind),
            _ => None,
        })
        .collect()
}

fn status(seen: &[Seen]) -> Vec<Vec<u8>> {
    seen.iter()
        .filter_map(|e| match e {
            Seen::Headers { fields, .. } => fields
                .iter()
                .find(|(n, _, _)| n == b":status")
                .map(|(_, v, _)| v.clone()),
            _ => None,
        })
        .collect()
}

#[test]
fn ext_connect_1xx_then_2xx() {
    let mut server_cfg = Config::default();
    server_cfg.enable_connect_protocol = true;
    let mut p = Pair::new(Config::default(), server_cfg);
    p.run_to_completion_resolving();
    let connect = [
        f(":method", "CONNECT"),
        f(":protocol", "websocket"),
        f(":scheme", "https"),
        f(":authority", "a"),
        f(":path", "/chat"),
    ];
    p.client.send_headers(S0, &connect, false).unwrap();
    p.run_to_completion_resolving();
    assert_eq!(kinds(&p.seen_by(Side::Server), S0), [HeadersKind::Request]);
    p.server
        .send_headers(S0, &[f(":status", "100")], false)
        .unwrap();
    p.run_to_completion_resolving();
    p.server
        .send_headers(S0, &[f(":status", "200")], false)
        .unwrap();
    p.run_to_completion_resolving();
    let client = p.seen_by(Side::Client);
    assert_eq!(
        kinds(&client, S0),
        [HeadersKind::Informational, HeadersKind::Response]
    );
    assert_eq!(status(&client), [b"100".to_vec(), b"200".to_vec()]);
    // Tunnel: DATA both ways, no Content-Length framing, no trailers.
    p.send_body(Side::Client, S0, b"ping", false);
    p.send_body(Side::Server, S0, b"pong!", false);
    p.run_to_completion_resolving();
    assert_eq!(p.bodies[&(Side::Server, S0)], b"ping");
    assert_eq!(p.bodies[&(Side::Client, S0)], b"pong!");
    assert_eq!(
        p.client.send_headers(S0, &[f("x-t", "1")], true),
        Err(UsageError::WrongPhase)
    );
    assert!(p.closed.is_empty());
}

#[test]
fn goaway_both_directions_in_one_pair() {
    let mut p = Pair::new(Config::default(), Config::default());
    p.run_to_completion_resolving();
    p.client.send_headers(S0, &get(), true).unwrap();
    p.run_to_completion_resolving();
    // Client GOAWAY carries a push ID (0); the server keeps serving requests.
    p.client.start_shutdown().unwrap();
    // Server: announce, then the actual cutoff after the processed request 0.
    p.server.start_shutdown().unwrap();
    p.run_to_completion_resolving();
    p.server.finish_shutdown().unwrap();
    p.run_to_completion_resolving();
    let goaways = |side| -> Vec<u64> {
        p.events(side)
            .into_iter()
            .filter_map(|e| match e {
                Event::GoAway { id } => Some(id),
                _ => None,
            })
            .collect()
    };
    assert_eq!(goaways(Side::Server), [0]);
    assert_eq!(goaways(Side::Client), [(1 << 62) - 4, 4]);
    // Request 0 is below the cutoff: it completes.
    p.server
        .send_headers(S0, &[f(":status", "200")], true)
        .unwrap();
    p.run_to_completion_resolving();
    assert_eq!(p.events(Side::Client).last(), Some(&Event::Finished(S0)));
    // No new request after the peer's GOAWAY.
    assert_eq!(
        p.client.send_headers(S4, &get(), true),
        Err(UsageError::GoingAway)
    );
    assert!(p.closed.is_empty());
}

#[test]
fn write_blocked_stream_in_pair() {
    let mut p = Pair::new(Config::default(), Config::default());
    p.opts.write_blocked.insert((Side::Client, CLIENT_CONTROL));
    p.client.send_headers(S0, &get(), true).unwrap();
    p.run_to_completion_resolving();
    // The request went through although the client's SETTINGS are stuck.
    assert_eq!(kinds(&p.seen_by(Side::Server), S0), [HeadersKind::Request]);
    assert!(p.server.peer_settings().is_none());
    p.opts.write_blocked.clear();
    p.server
        .send_headers(S0, &[f(":status", "200")], true)
        .unwrap();
    p.run_to_completion_resolving();
    assert_eq!(p.events(Side::Client).last(), Some(&Event::Finished(S0)));
    assert!(p.events(Side::Server).contains(&Event::Finished(S0)));
    // Unblocked, the client's SETTINGS arrive last.
    assert_eq!(p.events(Side::Server).last(), Some(&Event::PeerSettings));
    assert!(p.closed.is_empty());
}

#[test]
fn memory_bound_holds_after_release() {
    // 65,536-byte section: GET https / authority "a", then 65,528 `accept: */*` (static 29).
    let mut section = vec![0x00, 0x00, 0xd1, 0xd7, 0xc1, 0x50, 0x01, 0x61];
    section.resize(65_536, 0xdd);
    let wire = frame(0x01, &section);
    let mut c = server_ready(Config::default());
    let ids: Vec<StreamId> = (0..7).map(|i| StreamId(4 * i)).collect();
    for &s in &ids {
        feed_all(&mut c, s, &wire, false);
    }
    let blocks: Vec<_> = std::iter::from_fn(|| c.poll_event())
        .filter_map(|e| match e {
            Event::Headers { block, .. } => Some(block),
            _ => None,
        })
        .collect();
    assert_eq!(blocks.len(), 7);
    assert!(c.poll_action().is_none());
    // Seven decoded sections are really accounted for.
    assert!(c.debug_buffered_bytes() >= 7 * 65_536);
    assert!(c.debug_buffered_bytes() <= c.debug_bound());
    for b in blocks {
        c.release(b);
    }
    assert!(c.debug_buffered_bytes() <= c.debug_bound());
}
