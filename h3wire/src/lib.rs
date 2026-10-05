#![forbid(unsafe_code)]

mod error;
#[doc(hidden)]
pub mod frame;
mod headers;
#[doc(hidden)]
pub mod qpack;
#[doc(hidden)]
pub mod varint;
pub use error::*;
pub use headers::{FieldRef, HeaderBlockId, HeaderBlockRef, HeadersKind, Pseudo};
mod config;
mod settings;
pub use config::*;
pub use settings::PeerSettings;
#[doc(hidden)]
#[path = "invariants.rs"]
pub mod __invariants;
mod conn;
mod event;
mod stream;
pub use conn::{Connection, Role};
pub use event::{AbortSource, Action, DataFrame, Datagram, Event, Recv};
pub use stream::{StreamId, UniKind};
