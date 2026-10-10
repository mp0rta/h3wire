# h3wire-async

Runtime-neutral async HTTP/3 over the sans-I/O [h3wire](https://crates.io/crates/h3wire)
core: a hyper-shaped client and server, streaming bodies with trailers, Extended
CONNECT tunnels (RFC 9220) and HTTP datagrams (RFC 9297).

The QUIC transport plugs in through the poll-based traits in `h3wire_async::quic`;
[h3wire-quinn](https://crates.io/crates/h3wire-quinn) implements them for quinn. The
application supplies the executor (`rt::Executor`); the `tokio` feature adds
`rt::TokioExecutor`.

> **Note:** h3wire-async's API is unstable until the v0.3 MASQUE milestone: expect 0.x minor bumps; patches never break.

## Usage

```rust,ignore
use h3wire_async::{Builder, rt::TokioExecutor};

// Server: a future that drives `quic_conn` and dispatches requests to a tower `Service`.
let conn = Builder::new().serve_connection(quic_conn, service, TokioExecutor);
conn.await?;

// Client: spawn the driver, then send requests. Dropping the last `SendRequest`
// shuts the connection down gracefully.
let (mut send, driver) = Builder::new().handshake(quic_conn, TokioExecutor).await?;
tokio::spawn(driver);
let resp = send.send_request(request).await?;
```

See the [API documentation](https://docs.rs/h3wire-async).

## License

Licensed under either of Apache License, Version 2.0 or MIT license at your option.
