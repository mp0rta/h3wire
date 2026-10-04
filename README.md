# h3wire
h3wire is a pure-Rust, sans-I/O HTTP/3 protocol engine designed for embeddability and protocol extensibility.
Unlike async HTTP/3 libraries such as hyperium/h3, h3wire does not own transport streams or expose HTTP request/response as its fundamental abstraction.
