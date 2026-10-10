// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 mp0rta
use crate::ext::Protocol;
use crate::http_map::*;
use h3wire::{Action, Config, Connection, Event, FieldRef, H3Code, HeaderBlockRef, Role, StreamId};
use http::{HeaderValue, Method, Request, Response, Version};

const S0: StreamId = StreamId(0);

fn frame(ty: u64, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    h3wire::frame::encode_header(ty, payload.len() as u64, &mut out);
    out.extend_from_slice(payload);
    out
}

/// A connection with uni streams bound and the peer's (empty) SETTINGS received.
fn ready(role: Role, cfg: Config) -> Connection {
    let mut c = Connection::new(role, cfg);
    let (mut next, peer_control) = match role {
        Role::Client => (2, StreamId(3)),
        Role::Server => (3, StreamId(2)),
    };
    while let Some(a) = c.poll_action() {
        if let Action::OpenUni(kind) = a {
            c.bind_uni(kind, StreamId(next)).unwrap();
            next += 4;
        }
    }
    let ids: Vec<StreamId> = c.sendable().collect();
    for s in ids {
        let n = c.poll_send(s).map_or(0, <[u8]>::len);
        c.sent(s, n).unwrap();
    }
    let control = [&[0x00][..], &frame(0x04, &[])].concat();
    c.recv(peer_control, &control, false).unwrap();
    while c.poll_event().is_some() || c.poll_action().is_some() {}
    c
}

/// Feed `fields` as a HEADERS frame on stream 0 of `c` and run `f` on the delivered block.
fn with_block<R>(
    mut c: Connection,
    fields: &[FieldRef<'_>],
    f: impl FnOnce(&HeaderBlockRef<'_>) -> R,
) -> R {
    let mut block = Vec::new();
    h3wire::qpack::encoder::encode_field_section(fields, &mut block);
    c.recv(S0, &frame(0x01, &block), false).unwrap();
    while let Some(e) = c.poll_event() {
        if let Event::Headers { block, .. } = e {
            return f(&c.headers(block).unwrap());
        }
    }
    panic!("no headers event")
}

fn server() -> Connection {
    let mut cfg = Config::default();
    cfg.enable_connect_protocol = true;
    ready(Role::Server, cfg)
}

/// A client that has sent a request, so a response on stream 0 is accepted.
fn client() -> Connection {
    let mut c = ready(Role::Client, Config::default());
    let get = [
        FieldRef::new(b":method", b"GET"),
        FieldRef::new(b":scheme", b"https"),
        FieldRef::new(b":authority", b"a"),
        FieldRef::new(b":path", b"/"),
    ];
    c.send_headers(S0, &get, true).unwrap();
    c
}

fn parts(r: Request<()>) -> http::request::Parts {
    r.into_parts().0
}

fn names(f: &Fields) -> Vec<(String, String, bool)> {
    f.as_refs()
        .iter()
        .map(|r| {
            (
                String::from_utf8_lossy(r.name).into_owned(),
                String::from_utf8_lossy(r.value).into_owned(),
                r.never_index,
            )
        })
        .collect()
}

#[test]
fn request_roundtrip_preserves_order_and_sensitivity() {
    let mut secret = HeaderValue::from_static("s3cret");
    secret.set_sensitive(true);
    let req = Request::builder()
        .method(Method::POST)
        .uri("https://example.com/a?b=1")
        .header("x-one", "1")
        .header("authorization", secret)
        .header("x-two", "2")
        .body(())
        .unwrap();
    let fields = request_fields(&parts(req)).unwrap();
    let n = names(&fields);
    assert_eq!(n[0].0, ":method");
    assert_eq!(n[1], (":scheme".into(), "https".into(), false));
    assert_eq!(n[2], (":authority".into(), "example.com".into(), false));
    assert_eq!(n[3], (":path".into(), "/a?b=1".into(), false));
    let refs = fields.as_refs();
    let got = with_block(server(), &refs, |b| request_from_block(b).unwrap());
    assert_eq!(got.version(), Version::HTTP_3);
    assert_eq!(got.method(), Method::POST);
    assert_eq!(got.uri(), "https://example.com/a?b=1");
    let h: Vec<_> = got.headers().iter().map(|(k, _)| k.as_str()).collect();
    assert_eq!(h, ["x-one", "authorization", "x-two"]);
    assert!(got.headers()["authorization"].is_sensitive());
    assert!(!got.headers()["x-one"].is_sensitive());
}

fn scheme_authority_path(r: Request<()>) -> Result<(String, String, String), ()> {
    let f = request_fields(&parts(r)).map_err(|_| ())?;
    let n = names(&f);
    assert!(n.iter().all(|x| x.0 != "host"));
    let get = |k: &str| n.iter().find(|x| x.0 == k).unwrap().1.clone();
    Ok((get(":scheme"), get(":authority"), get(":path")))
}

#[test]
fn request_uri_forms() {
    let t = |s: &str| s.to_string();
    let r = Request::get("https://a/x").body(()).unwrap();
    assert_eq!(scheme_authority_path(r), Ok((t("https"), t("a"), t("/x"))));
    let r = Request::get("/x").header("host", "b").body(()).unwrap();
    assert_eq!(scheme_authority_path(r), Ok((t("https"), t("b"), t("/x"))));
    let r = Request::get("/x").body(()).unwrap();
    assert!(request_fields(&parts(r)).is_err());
    let r = Request::get("/x").header("host", "b").body(()).unwrap();
    assert_eq!(parts(r).uri.to_string(), "/x");
}

#[test]
fn connect_and_extended_connect_fields() {
    let r = Request::connect("proxy.example:443").body(()).unwrap();
    let f = request_fields(&parts(r)).unwrap();
    let n: Vec<_> = names(&f).into_iter().map(|x| x.0).collect();
    assert_eq!(n, [":method", ":authority"]);

    let mut r = Request::builder()
        .method(Method::CONNECT)
        .uri("https://a/chat")
        .body(())
        .unwrap();
    r.extensions_mut()
        .insert(Protocol::from_static("websocket"));
    let f = request_fields(&parts(r)).unwrap();
    let n: Vec<_> = names(&f).into_iter().map(|x| x.0).collect();
    assert_eq!(
        n,
        [":method", ":scheme", ":authority", ":path", ":protocol"]
    );
    let refs = f.as_refs();
    let got = with_block(server(), &refs, |b| request_from_block(b).unwrap());
    assert_eq!(
        got.extensions().get::<Protocol>().unwrap().as_bytes(),
        b"websocket"
    );
    assert_eq!(got.uri(), "https://a/chat");
}

#[test]
fn connection_specific_headers_are_stripped() {
    let r = Request::get("https://a/")
        .header("connection", "close")
        .header("keep-alive", "5")
        .header("proxy-connection", "x")
        .header("transfer-encoding", "chunked")
        .header("upgrade", "h2c")
        .header("te", "gzip")
        .header("x-keep", "1")
        .body(())
        .unwrap();
    let f = request_fields(&parts(r)).unwrap();
    let n: Vec<_> = names(&f).into_iter().map(|x| x.0).collect();
    assert_eq!(n, [":method", ":scheme", ":authority", ":path", "x-keep"]);

    let r = Request::get("https://a/")
        .header("te", "trailers")
        .body(())
        .unwrap();
    let f = request_fields(&parts(r)).unwrap();
    assert!(names(&f).iter().any(|x| x.0 == "te" && x.1 == "trailers"));

    let resp = Response::builder()
        .header("connection", "close")
        .header("transfer-encoding", "chunked")
        .header("x-keep", "1")
        .body(())
        .unwrap();
    let f = response_fields(&resp.into_parts().0);
    let n: Vec<_> = names(&f).into_iter().map(|x| x.0).collect();
    assert_eq!(n, [":status", "x-keep"]);

    let mut m = http::HeaderMap::new();
    m.insert("keep-alive", HeaderValue::from_static("1"));
    m.insert("x-t", HeaderValue::from_static("v"));
    let n: Vec<_> = names(&trailer_fields(&m))
        .into_iter()
        .map(|x| x.0)
        .collect();
    assert_eq!(n, ["x-t"]);
}

#[test]
fn response_status_roundtrip() {
    let mut v = HeaderValue::from_static("c=1");
    v.set_sensitive(true);
    let resp = Response::builder()
        .status(404)
        .header("set-cookie", v)
        .body(())
        .unwrap();
    let f = response_fields(&resp.into_parts().0);
    let refs = f.as_refs();
    let got = with_block(client(), &refs, |b| response_from_block(b).unwrap());
    assert_eq!(got.status(), 404);
    assert_eq!(got.version(), Version::HTTP_3);
    assert!(got.headers()["set-cookie"].is_sensitive());
}

#[test]
fn invalid_received_value_is_message_error() {
    // The core accepts any authority bytes; the `http` crate does not.
    let fields = [
        FieldRef::new(b":method", b"GET"),
        FieldRef::new(b":scheme", b"https"),
        FieldRef::new(b":authority", b"bad host"),
        FieldRef::new(b":path", b"/"),
    ];
    let r = with_block(server(), &fields, request_from_block);
    assert_eq!(r.unwrap_err(), H3Code::MESSAGE_ERROR);
}
