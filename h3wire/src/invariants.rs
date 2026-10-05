//! Observation types shared by the test harness and fuzz targets.

use crate::event::{Action, Event};
use crate::stream::StreamId;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Side {
    Client,
    Server,
}

/// One observed step of a connection, in order.
#[derive(Clone, Debug)]
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
