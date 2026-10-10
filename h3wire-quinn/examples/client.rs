// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 mp0rta
//! The interop client (`docs/interop.md`): HTTP/3 over quinn with h3wire-async.
//!
//! ```text
//! cargo run -p h3wire-quinn --example client -- <url> --ca <pem>
//!     [--method POST --data-len N] [--expect-sha256 HEX]
//!     [--concurrency K] [--goaway]
//! ```
//!
//! Sends `K` (default 1) identical requests on one connection and prints, per response,
//! `status=<code> sha256=<hex of the body>`, followed by ` trailers=<name:value,...>`
//! when it had trailers. The request body is `N` bytes of `b'a'`. The server's
//! certificate must chain to `--ca`.
//!
//! The connection always ends with a graceful shutdown (no new requests, then
//! `H3_NO_ERROR`), started by dropping the `SendRequest`. With `--goaway` it starts as
//! soon as every response's HEADERS arrived, with the bodies still in flight; otherwise
//! once the bodies are read.
//!
//! Exits non-zero on an error, a non-2xx status, a hash other than `--expect-sha256`,
//! or a connection that does not close cleanly.
//!
//! Library crates select no TLS provider; this example uses rustls with ring.

use bytes::Bytes;
use h3wire_async::rt::TokioExecutor;
use h3wire_async::{BoxError, Builder, Error};
use http::{HeaderMap, Method, Request, Uri};
use http_body::Frame;
use http_body_util::combinators::UnsyncBoxBody;
use http_body_util::{BodyExt, Empty, StreamBody};
use quinn::crypto::rustls::QuicClientConfig;
use quinn::rustls::pki_types::CertificateDer;
use quinn::rustls::pki_types::pem::PemObject;
use quinn::rustls::{self, RootCertStore, crypto::ring};
use sha2::{Digest, Sha256};
use std::net::{SocketAddr, ToSocketAddrs};
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

type Body = UnsyncBoxBody<Bytes, BoxError>;

const USAGE: &str = "usage: client <url> --ca PEM [--method M] [--data-len N] \
                     [--expect-sha256 HEX] [--concurrency K] [--goaway]";

#[derive(Default)]
struct Args {
    url: String,
    ca: String,
    method: Option<String>,
    data_len: usize,
    expect: Option<String>,
    concurrency: usize,
    goaway: bool,
}

#[tokio::main]
async fn main() -> ExitCode {
    match run().await {
        Ok(true) => ExitCode::SUCCESS,
        Ok(false) => ExitCode::FAILURE,
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}

fn args() -> Result<Args, BoxError> {
    let mut a = Args {
        concurrency: 1,
        ..Args::default()
    };
    let mut it = std::env::args().skip(1);
    let val = |it: &mut dyn Iterator<Item = String>| it.next().ok_or(USAGE);
    while let Some(s) = it.next() {
        match s.as_str() {
            "--ca" => a.ca = val(&mut it)?,
            "--method" => a.method = Some(val(&mut it)?),
            "--data-len" => a.data_len = val(&mut it)?.parse()?,
            "--expect-sha256" => a.expect = Some(val(&mut it)?.to_lowercase()),
            "--concurrency" => a.concurrency = val(&mut it)?.parse()?,
            "--goaway" => a.goaway = true,
            _ if !s.starts_with("--") && a.url.is_empty() => a.url = s,
            _ => return Err(format!("unknown argument {s}\n{USAGE}").into()),
        }
    }
    if a.url.is_empty() || a.ca.is_empty() || a.concurrency == 0 {
        return Err(USAGE.into());
    }
    Ok(a)
}

/// `Ok(false)`: a check failed (already reported).
async fn run() -> Result<bool, BoxError> {
    let a = args()?;
    let uri: Uri = a.url.parse()?;
    let host = uri.host().ok_or("the url has no host")?;
    let host = host
        .trim_start_matches('[')
        .trim_end_matches(']')
        .to_owned();
    let addr = (host.as_str(), uri.port_u16().unwrap_or(443))
        .to_socket_addrs()?
        .next()
        .ok_or("the host did not resolve")?;

    let mut roots = RootCertStore::empty();
    for c in CertificateDer::pem_file_iter(&a.ca)? {
        roots.add(c?)?;
    }
    let mut tls = rustls::ClientConfig::builder_with_provider(Arc::new(ring::default_provider()))
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_root_certificates(roots)
        .with_no_client_auth();
    tls.alpn_protocols = vec![b"h3".to_vec()];
    let cc = quinn::ClientConfig::new(Arc::new(QuicClientConfig::try_from(tls)?));
    let bind: SocketAddr = if addr.is_ipv6() {
        "[::]:0"
    } else {
        "0.0.0.0:0"
    }
    .parse()?;
    let mut endpoint = quinn::Endpoint::client(bind)?;
    endpoint.set_default_client_config(cc);
    let conn = endpoint.connect(addr, &host)?.await?;

    let (mut send, driver) =
        h3wire_quinn::client::<Body, _>(conn, &Builder::new(), TokioExecutor).await?;
    // Dropping the last `SendRequest` starts the graceful shutdown.
    let driver = tokio::spawn(driver);

    let method: Method = match &a.method {
        Some(m) => m.parse()?,
        None if a.data_len > 0 => Method::POST,
        None => Method::GET,
    };
    let heads: Vec<_> = (0..a.concurrency)
        .map(|_| {
            let req = Request::builder()
                .method(method.clone())
                .uri(uri.clone())
                .body(body(a.data_len))
                .unwrap();
            send.send_request(req)
        })
        .collect();
    let mut resps = Vec::new();
    for h in heads {
        resps.push(h.await?);
    }
    let mut send = Some(send);
    if a.goaway {
        send = None;
    }

    let mut ok = true;
    for r in resps {
        let status = r.status();
        let mut sha = Sha256::new();
        let mut trailers = None;
        let mut body = r.into_body();
        while let Some(f) = body.frame().await {
            match f?.into_data() {
                Ok(d) => sha.update(&d),
                Err(f) => trailers = f.into_trailers().ok(),
            }
        }
        let sha = hex(&sha.finalize());
        match &trailers {
            Some(t) => println!(
                "status={} sha256={sha} trailers={}",
                status.as_u16(),
                list(t)
            ),
            None => println!("status={} sha256={sha}", status.as_u16()),
        }
        if !status.is_success() {
            eprintln!("error: status {status}");
            ok = false;
        }
        if a.expect.as_ref().is_some_and(|e| *e != sha) {
            eprintln!("error: sha256 mismatch");
            ok = false;
        }
    }

    drop(send);
    match tokio::time::timeout(Duration::from_secs(10), driver).await {
        Ok(r) => r?.map_err(|e: Error| format!("connection: {e}"))?,
        Err(_) => return Err("graceful shutdown timed out".into()),
    }
    endpoint.wait_idle().await;
    Ok(ok)
}

/// `n` bytes of `b'a'` in 64 KiB DATA frames.
fn body(n: usize) -> Body {
    static A: [u8; 65536] = [b'a'; 65536];
    let frames: Vec<Frame<Bytes>> = (0..n)
        .step_by(A.len())
        .map(|i| Frame::data(Bytes::from_static(&A[..A.len().min(n - i)])))
        .collect();
    if frames.is_empty() {
        return Empty::new().map_err(|e| match e {}).boxed_unsync();
    }
    StreamBody::new(futures::stream::iter(frames.into_iter().map(Ok))).boxed_unsync()
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn list(t: &HeaderMap) -> String {
    t.iter()
        .map(|(k, v)| format!("{k}:{}", String::from_utf8_lossy(v.as_bytes())))
        .collect::<Vec<_>>()
        .join(",")
}
