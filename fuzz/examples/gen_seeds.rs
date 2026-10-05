//! Writes the committed seed inputs in `fuzz/seeds/<target>/`.
//!
//! Regenerate with `cargo run --manifest-path fuzz/Cargo.toml --example gen_seeds`.
//!
//! `wire` and `api_ops` decode their input with `arbitrary` 1.4: `Enc` below writes that
//! format by hand, and every seed is decoded back and compared before it is written, so a
//! format change fails here instead of silently producing useless seeds.

use arbitrary::{Arbitrary, Unstructured};
use h3wire::FieldRef;
use h3wire_fuzz::{IDS, Op, WireOp};
use std::fmt::Debug;
use std::path::Path;

/// The `arbitrary` 1.4 encoding of a value.
trait Enc {
    fn enc(&self, out: &mut Vec<u8>);
}

impl Enc for u8 {
    fn enc(&self, out: &mut Vec<u8>) {
        out.push(*self);
    }
}

impl Enc for u16 {
    fn enc(&self, out: &mut Vec<u8>) {
        out.extend(self.to_le_bytes());
    }
}

impl Enc for bool {
    fn enc(&self, out: &mut Vec<u8>) {
        out.push(u8::from(*self));
    }
}

/// Each element behind a "continue" byte, then a "stop" byte.
impl<T: Enc> Enc for Vec<T> {
    fn enc(&self, out: &mut Vec<u8>) {
        for x in self {
            out.push(1);
            x.enc(out);
        }
        out.push(0);
    }
}

impl<A: Enc, B: Enc, C: Enc> Enc for (A, B, C) {
    fn enc(&self, out: &mut Vec<u8>) {
        self.0.enc(out);
        self.1.enc(out);
        self.2.enc(out);
    }
}

/// Derived enums pick variant `(u32 * count) >> 32`.
fn variant(i: u64, count: u64, out: &mut Vec<u8>) {
    let v = (i << 32).div_ceil(count);
    out.extend((v as u32).to_le_bytes());
}

impl Enc for WireOp {
    fn enc(&self, out: &mut Vec<u8>) {
        match self {
            WireOp::Recv { stream, bytes, fin } => {
                variant(0, 4, out);
                (*stream, bytes.clone(), *fin).enc(out);
            }
            WireOp::Reset { stream, code } | WireOp::StopSending { stream, code } => {
                variant(
                    if matches!(self, WireOp::Reset { .. }) {
                        1
                    } else {
                        2
                    },
                    4,
                    out,
                );
                stream.enc(out);
                code.enc(out);
            }
            WireOp::Datagram(payload) => {
                variant(3, 4, out);
                payload.enc(out);
            }
        }
    }
}

impl Enc for Op {
    fn enc(&self, out: &mut Vec<u8>) {
        let v = |i, out: &mut Vec<u8>| variant(i, 13, out);
        match self {
            Op::Recv { stream, bytes, fin } => {
                v(0, out);
                (*stream, bytes.clone(), *fin).enc(out);
            }
            Op::Reset { stream, code } => {
                v(1, out);
                stream.enc(out);
                code.enc(out);
            }
            Op::StopSending { stream, code } => {
                v(2, out);
                stream.enc(out);
                code.enc(out);
            }
            Op::SendHeaders {
                stream,
                fields,
                end,
            } => {
                v(3, out);
                stream.enc(out);
                fields.enc(out);
                end.enc(out);
            }
            Op::SendData { stream, len, end } => {
                v(4, out);
                stream.enc(out);
                len.enc(out);
                end.enc(out);
            }
            Op::Sent { stream, n } => {
                v(5, out);
                stream.enc(out);
                n.enc(out);
            }
            Op::DataWritten { stream, n } => {
                v(6, out);
                stream.enc(out);
                n.enc(out);
            }
            Op::OpenUni(x) => {
                v(7, out);
                x.enc(out);
            }
            Op::Release(n) => {
                v(8, out);
                n.enc(out);
            }
            Op::Abort { stream, code } => {
                v(9, out);
                stream.enc(out);
                code.enc(out);
            }
            Op::StartShutdown => v(10, out),
            Op::FinishShutdown => v(11, out),
            Op::TransportClosed => v(12, out),
        }
    }
}

/// A top-level `Vec<T>` input (`arbitrary_take_rest`), checked by decoding it back.
fn ops<T>(list: &[T]) -> Vec<u8>
where
    T: Enc + Debug + for<'a> Arbitrary<'a>,
{
    let mut out = Vec::new();
    for op in list {
        out.push(1);
        op.enc(&mut out);
    }
    let back = Vec::<T>::arbitrary_take_rest(Unstructured::new(&out)).unwrap();
    assert_eq!(
        format!("{back:?}"),
        format!("{list:?}"),
        "arbitrary format changed"
    );
    out
}

/// Index into `IDS` of stream `id`.
fn s(id: u64) -> u8 {
    IDS.iter().position(|&x| x == id).unwrap() as u8
}

fn varint(v: u64) -> Vec<u8> {
    let mut out = Vec::new();
    h3wire::varint::encode(v, &mut out);
    out
}

fn frame(ty: u64, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    h3wire::frame::encode_header(ty, payload.len() as u64, &mut out);
    out.extend_from_slice(payload);
    out
}

fn section(fields: &[(&str, &str)]) -> Vec<u8> {
    let refs: Vec<FieldRef> = fields
        .iter()
        .map(|(n, v)| FieldRef {
            name: n.as_bytes(),
            value: v.as_bytes(),
            never_index: n.starts_with("authorization"),
        })
        .collect();
    let mut out = Vec::new();
    h3wire::qpack::encoder::encode_field_section(&refs, &mut out);
    out
}

fn headers(fields: &[(&str, &str)]) -> Vec<u8> {
    frame(0x01, &section(fields))
}

const GET: [(&str, &str); 4] = [
    (":method", "GET"),
    (":scheme", "https"),
    (":authority", "example.com"),
    (":path", "/index.html"),
];

/// Control stream: type, then SETTINGS (connect protocol, datagrams, an unknown one).
fn control() -> Vec<u8> {
    let params: Vec<u8> = [(0x08, 1), (0x33, 1), (0x06, 16_384), (0x2b60_3742, 7)]
        .iter()
        .flat_map(|&(id, v)| [varint(id), varint(v)].concat())
        .collect();
    [vec![0x00], frame(0x04, &params)].concat()
}

fn response() -> Vec<u8> {
    [
        headers(&[(":status", "103"), ("link", "</a.css>; rel=preload")]),
        headers(&[
            (":status", "200"),
            ("content-type", "text/html"),
            ("content-length", "5"),
        ]),
        frame(0x00, b"hello"),
        headers(&[("x-checksum", "abc")]),
    ]
    .concat()
}

fn request() -> Vec<u8> {
    let post = [
        (":method", "POST"),
        (":scheme", "https"),
        (":authority", "example.com"),
        (":path", "/upload"),
        ("authorization", "secret"),
        ("content-length", "4"),
    ];
    [headers(&post), frame(0x00, b"da"), frame(0x00, b"ta")].concat()
}

fn connect_tunnel() -> Vec<u8> {
    let connect = [
        (":method", "CONNECT"),
        (":protocol", "connect-udp"),
        (":scheme", "https"),
        (":authority", "proxy.example"),
        (":path", "/.well-known/masque/udp/192.0.2.6/443/"),
    ];
    [
        frame(0x30, b"ext"),
        headers(&connect),
        frame(0x00, b"\x00\x04ping"),
    ]
    .concat()
}

fn recv(stream: u64, bytes: Vec<u8>, fin: bool) -> WireOp {
    WireOp::Recv {
        stream: s(stream),
        bytes,
        fin,
    }
}

fn wire_seeds() -> Vec<(&'static str, Vec<u8>)> {
    let client_streams = || {
        vec![
            recv(2, control(), false),
            recv(6, vec![0x02], false),
            recv(10, vec![0x03], false),
        ]
    };
    let server_streams = || {
        vec![
            recv(3, control(), false),
            recv(7, vec![0x02, 0x20], false),
            recv(11, vec![0x03], false),
        ]
    };
    let mut get_split = client_streams();
    let get = headers(&GET);
    for chunk in get.chunks(3) {
        get_split.push(recv(0, chunk.to_vec(), false));
    }
    get_split.push(recv(0, Vec::new(), true));
    let mut upload = client_streams();
    upload.extend([
        recv(4, request(), true),
        WireOp::Datagram(vec![0x01, 0xaa, 0xbb]),
        // First sight of a partial request.
        recv(8, headers(&GET)[..5].to_vec(), false),
    ]);
    // Client uni stream 10 carries the registered type 0x54 here.
    let mut tunnel = vec![recv(2, control(), false), recv(6, vec![0x02], false)];
    tunnel.extend([
        recv(0, connect_tunnel(), false),
        WireOp::Datagram(vec![0x00, 0x00, 0x01]),
        recv(10, [varint(0x54), b"raw".to_vec()].concat(), false),
        WireOp::StopSending {
            stream: s(0),
            code: 0x10c,
        },
        WireOp::Reset {
            stream: s(0),
            code: 0x10c,
        },
    ]);
    let mut response_side = server_streams();
    response_side.extend([
        recv(0, response(), true),
        recv(3, frame(0x07, &varint(4)), false),
        WireOp::Datagram(vec![0x02]),
    ]);
    let mut goaway = client_streams();
    goaway.extend([
        recv(0, headers(&GET), true),
        recv(
            2,
            [frame(0x0d, &varint(8)), frame(0x07, &varint(0))].concat(),
            false,
        ),
        recv(4, headers(&GET), false),
    ]);
    [
        ("get_split", get_split),
        ("upload", upload),
        ("tunnel", tunnel),
        ("response", response_side),
        ("goaway", goaway),
    ]
    .into_iter()
    .map(|(name, list)| (name, ops(&list)))
    .collect()
}

/// `OpenUni` ops binding all three local uni streams, for both roles.
fn bind_all() -> Vec<Op> {
    // Client ids 2, 6, 10; server ids 3, 7, 11. `OpenUni(x)`: kind `x % 3`, id `IDS[x / 3]`.
    [(2, 0), (6, 1), (10, 2), (3, 0), (7, 1), (11, 2)]
        .into_iter()
        .map(|(id, kind)| Op::OpenUni(s(id) * 3 + kind))
        .collect()
}

/// `Sent` ops that write exactly what is pending on `id`, if that is under 256 bytes: a
/// `Sent` larger than what is pending is refused, so descending powers of two drain it.
fn flush(id: u64) -> [Op; 8] {
    [128, 64, 32, 16, 8, 4, 2, 1].map(|n| Op::Sent { stream: s(id), n })
}

/// Write out everything pending on the local uni streams of either role.
fn flush_uni() -> Vec<Op> {
    [2, 6, 10, 3, 7, 11].into_iter().flat_map(flush).collect()
}

fn op_recv(stream: u64, bytes: Vec<u8>, fin: bool) -> Op {
    Op::Recv {
        stream: s(stream),
        bytes,
        fin,
    }
}

/// `SendHeaders` with fields (empty: the canned request or 200 response of `api_ops`).
fn send_headers(stream: u64, fields: &[(&str, &str)], end: bool) -> Op {
    Op::SendHeaders {
        stream: s(stream),
        fields: fields
            .iter()
            .map(|(n, v)| {
                let never_index = *n == "authorization";
                (n.as_bytes().to_vec(), v.as_bytes().to_vec(), never_index)
            })
            .collect(),
        end,
    }
}

/// `send_data` of `len` bytes and every byte of it written (prefix included).
fn send_body(stream: u64, len: u16, end: bool) -> [Op; 3] {
    let prefix = 1 + varint(len.into()).len() as u16;
    [
        Op::SendData {
            stream: s(stream),
            len,
            end,
        },
        Op::DataWritten {
            stream: s(stream),
            n: 1,
        },
        Op::DataWritten {
            stream: s(stream),
            n: prefix + len - 1,
        },
    ]
}

/// Both roles run every seed: the client's request is stream 0 and its peer input goes
/// there; the server's peer input arrives on stream 4 (or 8), which the client never
/// opened and ignores. The ops meant for one role are refused or harmless in the other.
fn api_seeds() -> Vec<(&'static str, Vec<u8>)> {
    let setup = || {
        [
            bind_all(),
            flush_uni(),
            vec![op_recv(3, control(), false), op_recv(2, control(), false)],
        ]
        .concat()
    };
    // A full exchange each way, the response with a 1xx, a body and trailers.
    let mut exchange = setup();
    exchange.push(send_headers(0, &[], false));
    exchange.extend(flush(0));
    exchange.extend(send_body(0, 5, true));
    exchange.push(op_recv(4, request(), true));
    exchange.push(send_headers(4, &[], false));
    exchange.extend(flush(4));
    exchange.extend(send_body(4, 5, true));
    exchange.extend([
        op_recv(0, headers(&[(":status", "103")]), false),
        Op::Release(0),
        op_recv(
            0,
            [
                headers(&[(":status", "200"), ("content-length", "5")]),
                frame(0x00, b"hello"),
            ]
            .concat(),
            false,
        ),
        Op::Release(1),
        op_recv(0, headers(&[("x-checksum", "abc")]), true),
        Op::Release(2),
    ]);
    // Custom fields with the 'N' bit, trailers, a send-side stop, an abort.
    let mut fields = setup();
    let custom: Vec<(&str, &str)> = GET
        .iter()
        .copied()
        .chain([("x-custom", "v"), ("authorization", "t")])
        .collect();
    fields.push(send_headers(0, &custom, false));
    fields.push(send_headers(0, &[("x-trailer", "1")], true));
    fields.extend(flush(0));
    fields.push(op_recv(8, request(), false));
    fields.push(send_headers(8, &[], false));
    fields.extend(flush(8));
    fields.extend([
        Op::StopSending {
            stream: s(8),
            code: 0x10c,
        },
        send_headers(8, &[("x-trailer", "1")], true),
        op_recv(0, headers(&[(":status", "204")]), true),
        Op::Release(0),
        Op::Abort {
            stream: s(8),
            code: 0x10c,
        },
    ]);
    // GOAWAY both ways, rejections, and a transport close.
    let mut shutdown = setup();
    shutdown.extend([
        op_recv(0, headers(&GET), false),
        op_recv(4, headers(&GET), false),
        Op::StartShutdown,
        Op::Reset {
            stream: s(8),
            code: 0x10b,
        },
        Op::FinishShutdown,
        op_recv(3, frame(0x07, &varint(4)), false),
        op_recv(2, frame(0x07, &varint(0)), false),
        send_headers(8, &[], true),
        Op::TransportClosed,
    ]);
    // Extended CONNECT: tunnel bytes both ways.
    let mut tunnel = setup();
    let connect = [
        (":method", "CONNECT"),
        (":protocol", "websocket"),
        (":scheme", "https"),
        (":authority", "example.com"),
        (":path", "/chat"),
    ];
    tunnel.push(send_headers(0, &connect, false));
    tunnel.extend(flush(0));
    tunnel.push(op_recv(4, connect_tunnel(), false));
    tunnel.push(send_headers(4, &[], false));
    tunnel.extend(flush(4));
    tunnel.extend(send_body(4, 300, false));
    tunnel.extend([
        op_recv(0, headers(&[(":status", "200")]), false),
        Op::Release(0),
        op_recv(
            0,
            [frame(0x30, b"x"), frame(0x00, b"tunnel")].concat(),
            false,
        ),
    ]);
    tunnel.extend(send_body(0, 300, false));
    [
        ("exchange", exchange),
        ("fields", fields),
        ("shutdown", shutdown),
        ("tunnel", tunnel),
    ]
    .into_iter()
    .map(|(name, list)| (name, ops(&list)))
    .collect()
}

fn frame_seeds() -> Vec<(&'static str, Vec<u8>)> {
    let headers_only = |frames: &[(u64, u64)]| -> Vec<u8> {
        let mut out = Vec::new();
        for &(ty, len) in frames {
            h3wire::frame::encode_header(ty, len, &mut out);
        }
        out
    };
    let mixed = headers_only(&[
        (0x00, 5),
        (0x01, 300),
        (0x04, 0),
        (0x07, 1),
        (0x21, 0),
        (0x2b60_3742, 1 << 20),
        ((1 << 62) - 1, (1 << 62) - 1),
    ]);
    // Non-minimal varints: an 8-byte type 0x01 and a 4-byte length.
    let non_minimal = [
        0xc0, 0, 0, 0, 0, 0, 0, 0x01, 0x80, 0, 0, 0x10, 0x40, 0x00, 0x40, 0x3f,
    ];
    vec![
        ("mixed_whole", [vec![0], mixed.clone()].concat()),
        ("mixed_split_1", [vec![1], mixed.clone()].concat()),
        ("mixed_split_5", [vec![5], mixed].concat()),
        ("non_minimal", [&[3][..], &non_minimal].concat()),
    ]
}

fn qpack_seeds() -> Vec<(&'static str, Vec<u8>)> {
    vec![
        ("get", section(&GET)),
        (
            "response_literals",
            section(&[
                (":status", "200"),
                ("content-type", "text/html; charset=utf-8"),
                ("x-unknown-name", "some value"),
                ("authorization", "secret"),
            ]),
        ),
        (
            "trailers",
            section(&[("x-checksum", "abc"), ("grpc-status", "0")]),
        ),
        // Section Acknowledgment, Stream Cancellation, Insert Count Increment.
        ("decoder_instructions", vec![0x80, 0xff, 0x05, 0x41, 0x01]),
        // Set Dynamic Table Capacity 0.
        ("encoder_set_capacity", vec![0x20]),
    ]
}

fn main() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("seeds");
    let targets = [
        ("frame", frame_seeds()),
        ("qpack_decoder", qpack_seeds()),
        ("wire", wire_seeds()),
        ("api_ops", api_seeds()),
    ];
    for (target, seeds) in targets {
        let dir = root.join(target);
        std::fs::create_dir_all(&dir).unwrap();
        for (name, bytes) in seeds {
            std::fs::write(dir.join(name), &bytes).unwrap();
            println!("{target}/{name}: {} bytes", bytes.len());
        }
    }
}
