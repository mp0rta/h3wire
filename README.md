# h3wire

h3wire is a sans-I/O HTTP/3 (RFC 9114) and QPACK (RFC 9204) engine in pure Rust:
the core consumes stream bytes and resets from your QUIC transport and returns
events for the application and actions for the transport, with no I/O, no async
runtime and no dependencies beyond `std` (`#![forbid(unsafe_code)]`, MSRV 1.85).
Status: v0.1 in development. It covers RFC 9114 request/response streams, control
and QPACK streams, GOAWAY and stream termination, QPACK with the static table only
(no dynamic table), Extended CONNECT (RFC 9220), the HTTP/3 part of HTTP Datagrams
(RFC 9297) and extension points for frame, stream and setting types. There is no
async layer or QUIC adapter yet.

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or
[MIT license](LICENSE-MIT) at your option.
