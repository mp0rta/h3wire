// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 mp0rta
//! The interop server (`docs/interop.md`): HTTP/3 over quinn with h3wire-async.
//!
//! ```text
//! cargo run -p h3wire-quinn --example server -- \
//!     --listen 0.0.0.0:4433 --cert cert.pem --key key.pem [--masque-echo]
//! ```
//!
//! Routes:
//! - `GET /bytes/{n}`: `n` bytes of `b'a'`.
//! - `POST /sha256`: the lowercase hex SHA-256 of the request body (64 characters).
//! - `GET /trailers`: a short body, then the trailer `x-check: ok`.
//! - `GET /goaway`: replies, then starts this connection's graceful shutdown.
//! - With `--masque-echo`, Extended CONNECT `connect-udp` (RFC 9298): a 200 with
//!   `capsule-protocol: ?1`; context-ID-0 datagrams and the tunnel's bytes (so its
//!   capsules) are echoed.
//!
//! Graceful shutdown sends GOAWAY, serves the requests below the cutoff and closes with
//! `H3_NO_ERROR`. The final GOAWAY is best-effort: quinn's close discards stream data
//! still queued, so a client may see the `H3_NO_ERROR` CONNECTION_CLOSE without it. A
//! shutdown still draining after 10 s drops the connection, which also closes it with
//! `H3_NO_ERROR`. Each connection is logged to stderr: `<addr>: accepted`, then
//! `<addr>: closed cleanly` (graceful shutdown, or the peer closed with `H3_NO_ERROR`)
//! or `<addr>: closed with error: ...`.
//!
//! Library crates select no TLS provider; this example uses rustls with ring.

use bytes::Bytes;
use h3wire_async::body::RecvBody;
use h3wire_async::core::varint;
use h3wire_async::datagram::{DatagramSlot, Datagrams};
use h3wire_async::ext::Protocol;
use h3wire_async::rt::TokioExecutor;
use h3wire_async::upgrade::{self, OnUpgrade};
use h3wire_async::{BoxError, Builder, Error};
use http::{HeaderMap, Method, Request, Response, StatusCode};
use http_body::Frame;
use http_body_util::combinators::UnsyncBoxBody;
use http_body_util::{BodyExt, Empty, StreamBody};
use quinn::crypto::rustls::QuicServerConfig;
use quinn::rustls::pki_types::pem::PemObject;
use quinn::rustls::pki_types::{CertificateDer, PrivateKeyDer};
use quinn::rustls::{self, crypto::ring};
use sha2::{Digest, Sha256};
use std::future::{Future, pending};
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;
use tokio::sync::Notify;
use tower_service::Service;

type Body = UnsyncBoxBody<Bytes, BoxError>;
type Fut = Pin<Box<dyn Future<Output = Result<Response<Body>, BoxError>> + Send>>;

const USAGE: &str = "usage: server --listen ADDR --cert PEM --key PEM [--masque-echo]";

#[tokio::main]
async fn main() -> Result<(), BoxError> {
    let (mut listen, mut cert, mut key, mut masque) = (None, None, None, false);
    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        match a.as_str() {
            "--listen" => listen = args.next(),
            "--cert" => cert = args.next(),
            "--key" => key = args.next(),
            "--masque-echo" => masque = true,
            _ => return Err(format!("unknown argument {a}\n{USAGE}").into()),
        }
    }
    let (Some(listen), Some(cert), Some(key)) = (listen, cert, key) else {
        return Err(USAGE.into());
    };
    let listen: SocketAddr = listen.parse()?;
    let certs = CertificateDer::pem_file_iter(&cert)?.collect::<Result<Vec<_>, _>>()?;
    let key = PrivateKeyDer::from_pem_file(&key)?;
    let mut tls = rustls::ServerConfig::builder_with_provider(Arc::new(ring::default_provider()))
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_no_client_auth()
        .with_single_cert(certs, key)?;
    tls.alpn_protocols = vec![b"h3".to_vec()];
    let sc = quinn::ServerConfig::with_crypto(Arc::new(QuicServerConfig::try_from(tls)?));
    let endpoint = quinn::Endpoint::server(sc, listen)?;
    let mut builder = Builder::new();
    builder.enable_connect_protocol(masque);
    eprintln!("listening on {listen} (masque-echo: {masque})");
    while let Some(incoming) = endpoint.accept().await {
        let builder = builder.clone();
        tokio::spawn(async move {
            let peer = incoming.remote_address();
            eprintln!("{peer}: accepted");
            match serve(incoming, &builder, masque).await {
                Ok(()) => eprintln!("{peer}: closed cleanly"),
                Err(e) => eprintln!("{peer}: closed with error: {}", chain(&*e)),
            }
        });
    }
    Ok(())
}

/// Serve one connection until it closes; `GET /goaway` starts its graceful shutdown.
async fn serve(incoming: quinn::Incoming, builder: &Builder, masque: bool) -> Result<(), BoxError> {
    let conn = incoming.await?;
    let goaway = Arc::new(Notify::new());
    let app = App {
        goaway: goaway.clone(),
        masque,
    };
    let mut conn = h3wire_quinn::server(conn, builder, app, TokioExecutor);
    tokio::select! {
        r = &mut conn => return Ok(r?),
        () = goaway.notified() => {}
    }
    Pin::new(&mut conn).graceful_shutdown();
    match tokio::time::timeout(Duration::from_secs(10), &mut conn).await {
        Ok(r) => Ok(r?),
        Err(_) => Err("graceful shutdown timed out; dropped (H3_NO_ERROR)".into()),
    }
}

#[derive(Clone)]
struct App {
    goaway: Arc<Notify>,
    masque: bool,
}

impl Service<Request<RecvBody>> for App {
    type Response = Response<Body>;
    type Error = BoxError;
    type Future = Fut;

    fn poll_ready(&mut self, _: &mut Context<'_>) -> Poll<Result<(), BoxError>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, req: Request<RecvBody>) -> Fut {
        let app = self.clone();
        Box::pin(async move { Ok(app.route(req).await) })
    }
}

impl App {
    async fn route(self, mut req: Request<RecvBody>) -> Response<Body> {
        let path = req.uri().path().to_owned();
        let udp = req.extensions().get::<Protocol>() == Some(&Protocol::from_static("connect-udp"));
        match (req.method().clone(), path.as_str()) {
            (Method::GET, "/trailers") => {
                let mut t = HeaderMap::new();
                t.insert("x-check", "ok".parse().unwrap());
                let frames = [
                    Frame::data(Bytes::from_static(b"trailers\n")),
                    Frame::trailers(t),
                ];
                reply(200, frames)
            }
            (Method::GET, "/goaway") => {
                self.goaway.notify_one();
                reply(200, vec![Frame::data(Bytes::from_static(b"goaway\n"))])
            }
            (Method::GET, p) if p.starts_with("/bytes/") => match p[7..].parse::<usize>() {
                Ok(n) => reply(200, a_bytes(n)),
                Err(_) => reply(400, vec![]),
            },
            (Method::POST, "/sha256") => {
                let mut h = Sha256::new();
                let body = req.body_mut();
                while let Some(f) = body.frame().await {
                    match f {
                        Ok(f) => f.into_data().into_iter().for_each(|d| h.update(d)),
                        Err(_) => return reply(400, vec![]),
                    }
                }
                reply(200, vec![Frame::data(hex(&h.finalize()).into())])
            }
            (Method::CONNECT, _) if self.masque && udp => {
                let dgrams = req
                    .extensions()
                    .get::<DatagramSlot>()
                    .and_then(DatagramSlot::register);
                tokio::spawn(echo(upgrade::on(&mut req), dgrams));
                let mut r = reply(200, vec![]);
                r.headers_mut()
                    .insert("capsule-protocol", "?1".parse().unwrap());
                r
            }
            _ => reply(404, vec![]),
        }
    }
}

/// A response of `frames`; with none, an empty body that is at its end, as a CONNECT 2xx
/// must be.
fn reply<I>(status: u16, frames: I) -> Response<Body>
where
    I: IntoIterator<Item = Frame<Bytes>>,
    I::IntoIter: Send + 'static,
{
    let mut frames = frames.into_iter().peekable();
    let body = if frames.peek().is_none() {
        Empty::new().map_err(|e| match e {}).boxed_unsync()
    } else {
        StreamBody::new(futures::stream::iter(frames.map(Ok))).boxed_unsync()
    };
    let mut r = Response::new(body);
    *r.status_mut() = StatusCode::from_u16(status).unwrap();
    r
}

/// `n` bytes of `b'a'` in 64 KiB DATA frames, made as they are sent: nothing is
/// allocated, whatever `n` is.
fn a_bytes(n: usize) -> impl Iterator<Item = Frame<Bytes>> + Send + 'static {
    static A: [u8; 65536] = [b'a'; 65536];
    (0..n)
        .step_by(A.len())
        .map(move |i| Frame::data(Bytes::from_static(&A[..A.len().min(n - i)])))
}

/// `e` and its sources, `: `-separated.
fn chain(mut e: &(dyn std::error::Error + 'static)) -> String {
    let mut s = e.to_string();
    while let Some(x) = e.source() {
        s += &format!(": {x}");
        e = x;
    }
    s
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// Echo the tunnel's bytes and its context-ID-0 datagrams (RFC 9298 §4: other context
/// IDs are dropped) until the client finishes the tunnel.
async fn echo(on: OnUpgrade, mut dgrams: Option<Datagrams>) -> Result<(), Error> {
    let (mut tx, mut rx) = on.await?.split();
    loop {
        tokio::select! {
            d = next(&mut dgrams) => match d? {
                Some(d) if varint::decode(&d).map(|(id, _)| id) == Some(0) => {
                    let _ = dgrams.as_ref().unwrap().send(d); // unreliable: a refusal is a loss
                }
                Some(_) => {}
                None => dgrams = None,
            },
            b = rx.recv() => match b? {
                Some(b) => tx.send(b).await?,
                None => return tx.finish(),
            },
        }
    }
}

async fn next(d: &mut Option<Datagrams>) -> Result<Option<Bytes>, Error> {
    match d {
        Some(d) => d.recv().await,
        None => pending().await,
    }
}
