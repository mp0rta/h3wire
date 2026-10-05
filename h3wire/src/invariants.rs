//! Observation types shared by the test harness and fuzz targets, and the trace invariant
//! checker.

use crate::error::H3Code;
use crate::event::{Action, Event};
use crate::headers::HeadersKind;
use crate::stream::StreamId;
use std::collections::{HashMap, HashSet};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Side {
    Client,
    Server,
}

/// One observed step of a connection, in order.
#[derive(Clone, Copy, Debug)]
pub enum Obs {
    Event(Side, Event),
    Action(Side, Action),
    Body {
        side: Side,
        stream: StreamId,
        len: usize,
    },
    Frame {
        side: Side,
        stream: StreamId,
    },
}

/// Where a request stream's receive side is in `HEADERS -> DATA -> trailers`.
#[derive(Clone, Copy, Default, PartialEq, Eq)]
enum Phase {
    #[default]
    AwaitHead,
    Body,
    AfterTrailers,
}

#[derive(Default)]
struct StreamCheck {
    phase: Phase,
    /// `Finished` or `StreamAborted` seen.
    terminal: bool,
    /// Server: the request reached the application (Request `Headers` or a `Frame`).
    processed: bool,
}

/// The next phase after a `Headers` of `kind` on `side`, or `None` if out of order:
/// client `Informational* Response Trailers?`, server `Request Trailers?`.
fn next_phase(side: Side, phase: Phase, kind: HeadersKind) -> Option<Phase> {
    use HeadersKind::*;
    match (side, phase, kind) {
        (Side::Client, Phase::AwaitHead, Informational) => Some(Phase::AwaitHead),
        (Side::Client, Phase::AwaitHead, Response) | (Side::Server, Phase::AwaitHead, Request) => {
            Some(Phase::Body)
        }
        (_, Phase::Body, Trailers) => Some(Phase::AfterTrailers),
        _ => None,
    }
}

/// Check the spec section 5.2 invariants observable from an ordered trace (per request
/// stream and side; "open" means before that side's `Event::Closed`).
pub fn check(trace: &[Obs]) -> Result<(), String> {
    let mut streams: HashMap<(Side, StreamId), StreamCheck> = HashMap::new();
    let mut closed = HashSet::new();
    let mut close_sent = HashSet::new();
    let mut goaway: HashMap<Side, u64> = HashMap::new();
    for (i, o) in trace.iter().enumerate() {
        let fail = |what: &str| Err(format!("trace[{i}] {o:?}: {what}"));
        // The request stream an observation is about, if any.
        let (side, stream) = match *o {
            Obs::Event(side, e) => match e {
                Event::Headers { stream, .. }
                | Event::Finished(stream)
                | Event::StreamAborted { stream, .. } => (side, Some(stream)),
                _ => (side, None),
            },
            Obs::Body { side, stream, .. } | Obs::Frame { side, stream } => (side, Some(stream)),
            Obs::Action(side, _) => (side, None),
        };
        if !matches!(o, Obs::Action(..)) && closed.contains(&side) {
            return fail("observed after Event::Closed");
        }
        let st = stream
            .filter(|s| s.is_request())
            .map(|s| streams.entry((side, s)).or_default());
        if let Some(st) = &st {
            if st.terminal {
                return fail("after the stream's terminal event");
            }
        }
        match (*o, st) {
            (Obs::Event(_, Event::Headers { kind, .. }), Some(st)) => {
                let Some(phase) = next_phase(side, st.phase, kind) else {
                    return fail("Headers kind out of order");
                };
                st.phase = phase;
                st.processed |= kind == HeadersKind::Request;
            }
            (Obs::Event(_, Event::Finished(_) | Event::StreamAborted { .. }), Some(st)) => {
                st.terminal = true;
            }
            (Obs::Body { .. }, Some(st)) if st.phase != Phase::Body => {
                return fail("Body outside HEADERS -> DATA -> trailers");
            }
            (Obs::Frame { .. }, Some(st)) => st.processed = true,
            (Obs::Event(_, Event::Closed { .. }), _) => {
                closed.insert(side);
            }
            (Obs::Event(_, Event::GoAway { id }), _) => {
                if goaway.get(&side).is_some_and(|&prev| id > prev) {
                    return fail("received GOAWAY id increased");
                }
                goaway.insert(side, id);
            }
            (Obs::Action(_, a), _) => {
                if close_sent.contains(&side) {
                    return fail("action after CloseConnection");
                }
                match (side, a) {
                    (_, Action::CloseConnection { .. }) => {
                        close_sent.insert(side);
                    }
                    (
                        Side::Client,
                        Action::ResetStream {
                            code: H3Code::REQUEST_REJECTED,
                            ..
                        }
                        | Action::StopSending {
                            code: H3Code::REQUEST_REJECTED,
                            ..
                        },
                    ) => return fail("REQUEST_REJECTED from the client"),
                    (
                        Side::Server,
                        Action::ResetStream {
                            stream,
                            code: H3Code::REQUEST_REJECTED,
                        },
                    ) if streams.get(&(side, stream)).is_some_and(|s| s.processed) => {
                        return fail("REQUEST_REJECTED for a processed request");
                    }
                    _ => {}
                }
            }
            _ => {}
        }
    }
    Ok(())
}
