# h3wire-quinn

[quinn](https://crates.io/crates/quinn) 0.11 transport for
[h3wire-async](https://crates.io/crates/h3wire-async): async HTTP/3 over quinn on the
sans-I/O [h3wire](https://crates.io/crates/h3wire) core.

This crate selects no runtime, TLS provider or certificate verifier: configure your own
quinn endpoint (ALPN `h3`) and hand its connections over.

> **Note:** h3wire-async's API is unstable until the v0.3 MASQUE milestone: expect 0.x minor bumps; patches never break.

## Usage

```rust,ignore
use h3wire_async::{Builder, rt::TokioExecutor};

// Server: serve one quinn connection until it closes.
h3wire_quinn::server(quinn_conn, &Builder::new(), service, TokioExecutor).await?;

// Client: spawn the driver, then send requests.
let (mut send, driver) = h3wire_quinn::client(quinn_conn, &Builder::new(), TokioExecutor).await?;
tokio::spawn(driver);
let resp = send.send_request(request).await?;
```

The repository's `examples/server.rs` and `examples/client.rs` are complete programs
(rustls with ring). See the [API documentation](https://docs.rs/h3wire-quinn).

## License

Licensed under either of Apache License, Version 2.0 or MIT license at your option.
