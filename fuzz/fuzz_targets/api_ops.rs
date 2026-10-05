#![no_main]

use arbitrary::Arbitrary;
use h3wire::{FieldRef, H3Code, Role, UniKind};
use h3wire_fuzz::{IDS, Peer, id};
use libfuzzer_sys::fuzz_target;

/// Peer input and application calls, interleaved.
#[derive(Arbitrary, Debug)]
enum Op {
    Recv {
        stream: u8,
        bytes: Vec<u8>,
        fin: bool,
    },
    Reset {
        stream: u8,
        code: u16,
    },
    StopSending {
        stream: u8,
        code: u16,
    },
    /// Empty `fields` sends a valid request (client) or a 200 response (server).
    SendHeaders {
        stream: u8,
        fields: Vec<(Vec<u8>, Vec<u8>, bool)>,
        end: bool,
    },
    SendData {
        stream: u8,
        len: u16,
        end: bool,
    },
    Sent {
        stream: u8,
        n: u16,
    },
    DataWritten {
        stream: u8,
        n: u16,
    },
    /// Bind uni stream kind `x % 3` to id `IDS[x / 3]`.
    OpenUni(u8),
    /// Release the `n`-th header block delivered so far.
    Release(u8),
    Abort {
        stream: u8,
        code: u16,
    },
    StartShutdown,
    FinishShutdown,
    TransportClosed,
}

const MAX_OPS: usize = 4096;

fn canned(role: Role) -> Vec<FieldRef<'static>> {
    let f = |n: &'static str, v: &'static str| FieldRef::new(n.as_bytes(), v.as_bytes());
    match role {
        Role::Client => vec![
            f(":method", "GET"),
            f(":scheme", "https"),
            f(":authority", "a"),
            f(":path", "/"),
        ],
        Role::Server => vec![f(":status", "200")],
    }
}

fn apply(p: &mut Peer, role: Role, op: &Op) {
    let c = &mut p.conn;
    match op {
        Op::Recv { stream, bytes, fin } => return p.recv(id(*stream), bytes, *fin),
        Op::Reset { stream, code } => return p.reset(id(*stream), *code),
        Op::StopSending { stream, code } => return p.stop_sending(id(*stream), *code),
        Op::SendHeaders {
            stream,
            fields,
            end,
        } => {
            let fields: Vec<FieldRef> = if fields.is_empty() {
                canned(role)
            } else {
                fields
                    .iter()
                    .map(|(n, v, never_index)| FieldRef {
                        name: n,
                        value: v,
                        never_index: *never_index,
                    })
                    .collect()
            };
            let _ = c.send_headers(id(*stream), &fields, *end);
        }
        Op::SendData { stream, len, end } => {
            let _ = c.send_data(id(*stream), (*len).into(), *end);
        }
        Op::Sent { stream, n } => {
            let s = id(*stream);
            let pending = c.poll_send(s).map(<[u8]>::len);
            if c.sent(s, (*n).into()).is_ok() {
                assert!(usize::from(*n) <= pending.unwrap_or(0));
            }
        }
        Op::DataWritten { stream, n } => {
            let _ = c.data_written(id(*stream), (*n).into());
        }
        Op::OpenUni(x) => {
            let kind = [
                UniKind::Control,
                UniKind::QpackEncoder,
                UniKind::QpackDecoder,
            ][usize::from(*x % 3)];
            let _ = c.bind_uni(kind, id(*x / 3 % IDS.len() as u8));
        }
        Op::Release(n) => {
            if !p.blocks.is_empty() {
                let b = p.blocks[usize::from(*n) % p.blocks.len()];
                c.release(b);
            }
        }
        Op::Abort { stream, code } => {
            let _ = c.abort(id(*stream), H3Code((*code).into()));
        }
        Op::StartShutdown => {
            let _ = c.start_shutdown();
        }
        Op::FinishShutdown => {
            let _ = c.finish_shutdown();
        }
        Op::TransportClosed => c.transport_closed(),
    }
    let _ = c.sendable().count();
    p.drain();
}

fuzz_target!(|ops: Vec<Op>| {
    let ops = &ops[..ops.len().min(MAX_OPS)];
    for role in [Role::Client, Role::Server] {
        let mut p = Peer::new(role, false);
        p.drain();
        for op in ops {
            apply(&mut p, role, op);
            p.check();
        }
    }
});
