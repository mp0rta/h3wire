#![forbid(unsafe_code)]

mod error;
#[doc(hidden)]
pub mod frame;
#[doc(hidden)]
pub mod varint;
pub use error::*;
