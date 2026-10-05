#![no_main]

use arbitrary::Arbitrary;
use h3wire::{Action, Role, StreamId};
use h3wire_fuzz::{Peer, id};
use libfuzzer_sys::fuzz_target;

/// Peer input as the transport delivers it.
#[derive(Arbitrary, Debug)]
enum WireOp {
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
    Datagram(Vec<u8>),
}

/// A connection whose local uni streams are bound, as a transport would do at startup.
fn peer(role: Role) -> Peer {
    let mut p = Peer::new(role, true);
    let mut next = match role {
        Role::Client => 2,
        Role::Server => 3,
    };
    while let Some(a) = p.conn.poll_action() {
        if let Action::OpenUni(kind) = a {
            p.conn.bind_uni(kind, StreamId(next)).unwrap();
            next += 4;
        }
    }
    p
}

fuzz_target!(|ops: Vec<WireOp>| {
    for mut p in [peer(Role::Server), peer(Role::Client)] {
        for op in &ops {
            match op {
                WireOp::Recv { stream, bytes, fin } => p.recv(id(*stream), bytes, *fin),
                WireOp::Reset { stream, code } => p.reset(id(*stream), *code),
                WireOp::StopSending { stream, code } => p.stop_sending(id(*stream), *code),
                WireOp::Datagram(payload) => p.datagram(payload),
            }
        }
        p.check();
    }
});
