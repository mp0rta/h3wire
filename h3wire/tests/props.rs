//! Split / partial-write / fragmentation properties (spec section 5.2) and the trace
//! invariant checker.

mod support;

use h3wire::__invariants::check;
use h3wire::{
    AbortSource, Action, Config, Connection, Event, FieldRef, H3Code, HeadersKind, Recv, StreamId,
};
use proptest::prelude::*;
use support::{
    Field, Obs, Opts, Pair, Seen, Side, client_ready, consumed, see, server_ready, wire,
};

const S0: StreamId = StreamId(0);

/// Names the generators must avoid: connection-specific, or with semantics that would
/// change the outcome (Content-Length, Host).
const RESERVED: [&str; 8] = [
    "connection",
    "keep-alive",
    "proxy-connection",
    "transfer-encoding",
    "upgrade",
    "te",
    "content-length",
    "host",
];

#[derive(Clone, Debug)]
struct Msg {
    head: Vec<Field>,
    body: Vec<u8>,
    trailers: Option<Vec<Field>>,
}

#[derive(Clone, Debug)]
struct Exchange {
    req: Msg,
    info: Option<Vec<Field>>,
    resp: Msg,
}

fn field(n: &str, v: &str) -> Field {
    (n.as_bytes().to_vec(), v.as_bytes().to_vec(), false)
}

fn refs(fields: &[Field]) -> Vec<FieldRef<'_>> {
    fields
        .iter()
        .map(|(n, v, ni)| FieldRef {
            name: n,
            value: v,
            never_index: *ni,
        })
        .collect()
}

// ---- Generators ----

/// Lowercase `tchar` names.
fn name() -> impl Strategy<Value = Vec<u8>> {
    "[a-z0-9!#$%&'*+.^_`|~-]{1,12}"
        .prop_filter("reserved name", |n| !RESERVED.contains(&n.as_str()))
        .prop_map(String::into_bytes)
}

/// `field-content` bytes: no leading/trailing SP/HTAB. Half the time Huffman-friendly text.
fn value() -> impl Strategy<Value = Vec<u8>> {
    let byte = prop_oneof![0x21u8..=0x7e, 0x80u8..=0xff, Just(b' '), Just(b'\t')];
    prop_oneof![
        "[a-z0-9 ./=-]{0,40}".prop_map(String::into_bytes),
        prop::collection::vec(byte, 0..40),
    ]
    .prop_map(|v| v.trim_ascii().to_vec())
}

fn fields(max: usize) -> impl Strategy<Value = Vec<Field>> {
    prop::collection::vec((name(), value(), any::<bool>()), 0..max)
}

fn body() -> impl Strategy<Value = Vec<u8>> {
    prop::collection::vec(any::<u8>(), 0..=4096)
}

fn with(mut head: Vec<Field>, extra: Vec<Field>) -> Vec<Field> {
    head.extend(extra);
    head
}

fn request_head(method: &str, extra: Vec<Field>) -> Vec<Field> {
    let pseudo = vec![
        field(":method", method),
        field(":scheme", "https"),
        field(":authority", "example.com"),
        field(":path", "/index.html"),
    ];
    with(pseudo, extra)
}

fn msg(head: Vec<Field>) -> impl Strategy<Value = Msg> {
    (body(), prop::option::of(fields(4))).prop_map(move |(body, trailers)| Msg {
        head: head.clone(),
        body,
        trailers,
    })
}

fn exchange() -> impl Strategy<Value = Exchange> {
    let req = (prop_oneof![Just("GET"), Just("POST")], fields(6))
        .prop_flat_map(|(m, f)| msg(request_head(m, f)));
    let resp = fields(6).prop_flat_map(|f| msg(with(vec![field(":status", "200")], f)));
    let info = prop::option::of(fields(3).prop_map(|f| with(vec![field(":status", "103")], f)));
    (req, info, resp).prop_map(|(req, info, resp)| Exchange { req, info, resp })
}

// ---- Running an exchange ----

/// Send `m` (after the optional 1xx) from `side` on S0, letting the pair settle after each step.
fn send(p: &mut Pair, side: Side, info: Option<&Vec<Field>>, m: &Msg) {
    if let Some(i) = info {
        p.conn(side).send_headers(S0, &refs(i), false).unwrap();
        p.run_to_completion_resolving();
    }
    let more = !m.body.is_empty() || m.trailers.is_some();
    p.conn(side)
        .send_headers(S0, &refs(&m.head), !more)
        .unwrap();
    p.run_to_completion_resolving();
    if !m.body.is_empty() {
        p.send_body(side, S0, &m.body, m.trailers.is_none());
        p.run_to_completion_resolving();
    }
    if let Some(t) = &m.trailers {
        p.conn(side).send_headers(S0, &refs(t), true).unwrap();
        p.run_to_completion_resolving();
    }
}

fn run(x: &Exchange, opts: Opts, cfg: &Config) -> Pair {
    let mut p = Pair::new(cfg.clone(), cfg.clone());
    p.opts = opts;
    p.run_to_completion_resolving();
    send(&mut p, Side::Client, None, &x.req);
    send(&mut p, Side::Server, x.info.as_ref(), &x.resp);
    assert!(p.closed.is_empty(), "{:?}", p.closed);
    p
}

/// The events the receiver of `m` should see on S0.
fn expected(info: Option<&Vec<Field>>, m: &Msg, kind: HeadersKind) -> Vec<Seen> {
    let h = |kind, fields: &Vec<Field>| Seen::Headers {
        stream: S0,
        kind,
        fields: fields.clone(),
    };
    let mut out = Vec::new();
    out.extend(info.map(|i| h(HeadersKind::Informational, i)));
    out.push(h(kind, &m.head));
    out.extend(m.trailers.as_ref().map(|t| h(HeadersKind::Trailers, t)));
    out.push(Seen::Event(Event::Finished(S0)));
    out
}

/// `side`'s resolved events, without connection-level `PeerSettings`.
fn stream_seen(p: &Pair, side: Side) -> Vec<Seen> {
    let mut v = p.seen_by(side);
    v.retain(|e| *e != Seen::Event(Event::PeerSettings));
    v
}

fn body_of(p: &Pair, side: Side) -> &[u8] {
    p.bodies.get(&(side, S0)).map_or(&[], Vec::as_slice)
}

/// Feed `bytes` to `c` on `s` in pieces split at the ascending `cuts` (FIN on the last piece),
/// resolving and releasing header blocks after every `recv`; returns events and body bytes.
fn feed_pieces(
    c: &mut Connection,
    s: StreamId,
    bytes: &[u8],
    cuts: &[usize],
) -> (Vec<Seen>, Vec<u8>) {
    let (mut seen, mut body) = (Vec::new(), Vec::new());
    let mut start = 0;
    let ends: Vec<usize> = cuts.iter().copied().chain([bytes.len()]).collect();
    for (i, &end) in ends.iter().enumerate() {
        let fin = i + 1 == ends.len();
        let mut rest = &bytes[start..end];
        loop {
            let r = c.recv(s, rest, fin).unwrap();
            assert_ne!(r, Recv::Paused, "blocks are released after every recv");
            if let Recv::Body { range, .. } = &r {
                body.extend_from_slice(&rest[range.clone()]);
            }
            rest = &rest[consumed(&r)..];
            while let Some(e) = c.poll_event() {
                seen.push(see(c, e));
            }
            if rest.is_empty() {
                break;
            }
        }
        start = end;
    }
    (seen, body)
}

// ---- Properties ----

proptest! {
    #[test]
    fn split_invariance(x in exchange(), chunk in 1usize..64) {
        let cfg = Config::default();
        let whole = run(&x, Opts::default(), &cfg);
        let split = run(&x, Opts { recv_chunk: Some(chunk), ..Opts::default() }, &cfg);
        prop_assert_eq!(
            stream_seen(&whole, Side::Server),
            expected(None, &x.req, HeadersKind::Request)
        );
        prop_assert_eq!(
            stream_seen(&whole, Side::Client),
            expected(x.info.as_ref(), &x.resp, HeadersKind::Response)
        );
        prop_assert_eq!(body_of(&whole, Side::Server), &x.req.body[..]);
        prop_assert_eq!(body_of(&whole, Side::Client), &x.resp.body[..]);
        for side in [Side::Client, Side::Server] {
            prop_assert_eq!(whole.seen_by(side), split.seen_by(side));
        }
        prop_assert_eq!(&whole.bodies, &split.bodies);
    }

    #[test]
    fn partial_write_invariance(x in exchange(), max in 1usize..32) {
        // GREASE values are random per connection; off so the wire bytes are reproducible.
        let mut cfg = Config::default();
        cfg.grease = false;
        let full = run(&x, Opts::default(), &cfg);
        let partial = run(&x, Opts { max_write: Some(max), ..Opts::default() }, &cfg);
        prop_assert_eq!(&full.wire, &partial.wire);
    }

    #[test]
    fn qpack_fragmentation(
        extra in fields(8),
        cuts in prop::collection::vec(any::<prop::sample::Index>(), 0..8),
    ) {
        let head = request_head("GET", extra);
        let mut block = Vec::new();
        h3wire::qpack::encoder::encode_field_section(&refs(&head), &mut block);
        let bytes = wire::frame(0x01, &block);
        let mut cuts: Vec<usize> = cuts.iter().map(|i| i.index(bytes.len() + 1)).collect();
        cuts.sort_unstable();
        let mut c = server_ready(Config::default());
        let (seen, body) = feed_pieces(&mut c, S0, &bytes, &cuts);
        let m = Msg { head, body: Vec::new(), trailers: None };
        prop_assert_eq!(seen, expected(None, &m, HeadersKind::Request));
        prop_assert!(body.is_empty());
    }
}

/// A message exercising multi-byte varints and prefix integers and Huffman-coded strings.
fn fixed_exchange() -> Exchange {
    let long = "abcdefghij".repeat(30); // Huffman, >127 bytes: multi-byte string length
    let hv = |extra: &[Field]| {
        let mut v = vec![
            field("user-agent", "h3wire test agent"), // static name ref, index > 15
            field("x-custom-header-name", "hello world"), // literal name, length > 7
            (b"authorization".to_vec(), b"secret-token".to_vec(), true),
        ];
        v.extend_from_slice(extra);
        v
    };
    let body: Vec<u8> = (0..300u32).map(|i| (i * 31) as u8).collect(); // 2-byte DATA length
    Exchange {
        req: Msg {
            head: request_head("POST", hv(&[field("x-long", &long)])),
            body: body.clone(),
            trailers: Some(vec![field("x-checksum", "deadbeef")]),
        },
        info: Some(vec![
            field(":status", "103"),
            field("link", "</style.css>; rel=preload"),
        ]),
        resp: Msg {
            head: with(vec![field(":status", "200")], hv(&[field("x-long", &long)])),
            body,
            trailers: Some(vec![field("x-checksum", "cafebabe")]),
        },
    }
}

#[test]
fn deterministic_splits() {
    let x = fixed_exchange();
    let p = run(&x, Opts::default(), &Config::default());
    let up = &p.wire[&(Side::Client, S0)];
    let down = &p.wire[&(Side::Server, S0)];

    let want = (
        expected(None, &x.req, HeadersKind::Request),
        x.req.body.clone(),
    );
    for k in 0..=up.len() {
        let mut c = server_ready(Config::default());
        assert_eq!(
            feed_pieces(&mut c, S0, up, &[k]),
            want,
            "server-bound split at {k}"
        );
    }

    let want = (
        expected(x.info.as_ref(), &x.resp, HeadersKind::Response),
        x.resp.body.clone(),
    );
    for k in 0..=down.len() {
        let mut c = client_ready(Config::default());
        c.send_headers(S0, &refs(&request_head("GET", Vec::new())), true)
            .unwrap();
        assert_eq!(
            feed_pieces(&mut c, S0, down, &[k]),
            want,
            "client-bound split at {k}"
        );
    }
}

// ---- The checker itself ----

#[test]
fn checker_catches_violations() {
    use Obs::{Action as A, Body, Event as E};
    use Side::{Client, Server};
    let aborted = Event::StreamAborted {
        stream: S0,
        code: H3Code::REQUEST_CANCELLED,
        source: AbortSource::Peer,
    };
    let rejected = H3Code::REQUEST_REJECTED;
    // A real block id, for hand-built Headers events.
    let mut c = server_ready(Config::default());
    let req = wire::headers(&[
        (":method", "GET"),
        (":scheme", "https"),
        (":authority", "a"),
        (":path", "/"),
    ]);
    c.recv(S0, &req, false).unwrap();
    let Some(Event::Headers { block, .. }) = c.poll_event() else {
        panic!("no Headers")
    };
    let headers = |kind| Event::Headers {
        stream: S0,
        block,
        kind,
    };
    let body = |side| Body {
        side,
        stream: S0,
        len: 1,
    };

    let ok: Vec<Vec<Obs>> = vec![
        vec![
            E(Client, headers(HeadersKind::Informational)),
            E(Client, headers(HeadersKind::Response)),
            body(Client),
            E(Client, headers(HeadersKind::Trailers)),
            E(Client, Event::Finished(S0)),
            // The other side and other streams are independent.
            E(Server, aborted),
            E(Client, Event::Finished(StreamId(4))),
        ],
        vec![
            E(Client, Event::GoAway { id: 8 }),
            E(Client, Event::GoAway { id: 8 }),
            E(Client, Event::GoAway { id: 4 }),
            E(Server, Event::GoAway { id: 100 }),
        ],
        vec![
            A(
                Server,
                Action::ResetStream {
                    stream: S0,
                    code: rejected,
                },
            ),
            A(
                Client,
                Action::CloseConnection {
                    code: H3Code::NO_ERROR,
                    reason: "",
                },
            ),
            A(Server, Action::FinishStream(S0)),
            E(
                Client,
                Event::Closed {
                    code: H3Code::NO_ERROR,
                },
            ),
        ],
    ];
    for t in ok {
        assert_eq!(check(&t), Ok(()), "{t:?}");
    }

    let bad: Vec<(&str, Vec<Obs>)> = vec![
        (
            "duplicate terminal",
            vec![E(Server, Event::Finished(S0)), E(Server, aborted)],
        ),
        (
            "Body after Finished",
            vec![
                E(Server, headers(HeadersKind::Request)),
                E(Server, Event::Finished(S0)),
                body(Server),
            ],
        ),
        (
            "Headers after abort",
            vec![
                E(Client, aborted),
                E(Client, headers(HeadersKind::Response)),
            ],
        ),
        (
            "Frame after Finished",
            vec![
                E(Server, Event::Finished(S0)),
                Obs::Frame {
                    side: Server,
                    stream: S0,
                },
            ],
        ),
        (
            "increasing GOAWAY",
            vec![
                E(Client, Event::GoAway { id: 4 }),
                E(Client, Event::GoAway { id: 8 }),
            ],
        ),
        (
            "event after Closed",
            vec![
                E(
                    Client,
                    Event::Closed {
                        code: H3Code::NO_ERROR,
                    },
                ),
                E(Client, Event::Finished(S0)),
            ],
        ),
        (
            "trailers before response",
            vec![E(Client, headers(HeadersKind::Trailers))],
        ),
        (
            "response after trailers",
            vec![
                E(Client, headers(HeadersKind::Response)),
                E(Client, headers(HeadersKind::Trailers)),
                E(Client, headers(HeadersKind::Response)),
            ],
        ),
        (
            "second request head",
            vec![
                E(Server, headers(HeadersKind::Request)),
                E(Server, headers(HeadersKind::Request)),
            ],
        ),
        (
            "response on the server",
            vec![E(Server, headers(HeadersKind::Response))],
        ),
        ("Body before headers", vec![body(Server)]),
        (
            "action after CloseConnection",
            vec![
                A(
                    Server,
                    Action::CloseConnection {
                        code: H3Code::NO_ERROR,
                        reason: "",
                    },
                ),
                A(Server, Action::FinishStream(S0)),
            ],
        ),
        (
            "processed request rejected",
            vec![
                E(Server, headers(HeadersKind::Request)),
                A(
                    Server,
                    Action::ResetStream {
                        stream: S0,
                        code: rejected,
                    },
                ),
            ],
        ),
        (
            "frame then rejected",
            vec![
                Obs::Frame {
                    side: Server,
                    stream: S0,
                },
                A(
                    Server,
                    Action::ResetStream {
                        stream: S0,
                        code: rejected,
                    },
                ),
            ],
        ),
        (
            "client reset REJECTED",
            vec![A(
                Client,
                Action::ResetStream {
                    stream: S0,
                    code: rejected,
                },
            )],
        ),
        (
            "client stop REJECTED",
            vec![A(
                Client,
                Action::StopSending {
                    stream: S0,
                    code: rejected,
                },
            )],
        ),
    ];
    for (what, t) in bad {
        assert!(check(&t).is_err(), "{what}: {t:?}");
    }
}
