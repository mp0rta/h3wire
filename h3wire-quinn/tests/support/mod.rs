// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 mp0rta
//! Loopback test support: quinn endpoints, an h3wire-async client and server, a
//! `CorePeer` over quinn, and bodies.
#![allow(dead_code)] // each test binary uses a subset

use bytes::Bytes;
use h3wire_async::__testing::{CorePeer, PeerObs};
use h3wire_async::body::RecvBody;
use h3wire_async::core::{Event, StreamId};
use h3wire_async::rt::TokioExecutor;
use h3wire_async::{BoxError, Builder, Error, SendRequest, ServerConnection};
use h3wire_quinn::QuinnConnection;
use http::{HeaderMap, Method, Request, Response};
use http_body::{Body, Frame};
use http_body_util::combinators::UnsyncBoxBody;
use http_body_util::{BodyExt, Empty, Full, StreamBody};
use quinn::Endpoint;
use quinn::rustls::RootCertStore;
use quinn::rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer};
use sha2::{Digest, Sha256};
use std::future::{Future, poll_fn};
use std::net::{Ipv4Addr, SocketAddr};
use std::pin::{Pin, pin};
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinHandle;
use tower_service::Service;

/// Request and response bodies.
pub type BoxBody = UnsyncBoxBody<Bytes, BoxError>;
pub type Fut = Pin<Box<dyn Future<Output = Result<Response<BoxBody>, BoxError>> + Send>>;
pub type Peer = CorePeer<QuinnConnection>;

/// A server and a client endpoint on loopback (ephemeral ports), with an rcgen
/// self-signed certificate for `localhost` and datagrams enabled; the server's address.
pub fn endpoint_pair() -> (Endpoint, Endpoint, SocketAddr) {
    endpoint_pair_with(|_| {})
}

/// [`endpoint_pair`], with `f` applied to both endpoints' transport config.
pub fn endpoint_pair_with(
    f: impl FnOnce(&mut quinn::TransportConfig),
) -> (Endpoint, Endpoint, SocketAddr) {
    let ck = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let cert: CertificateDer<'static> = ck.cert.der().clone();
    let key = PrivatePkcs8KeyDer::from(ck.signing_key.serialize_der());
    let mut transport = quinn::TransportConfig::default();
    transport.datagram_receive_buffer_size(Some(1 << 16));
    f(&mut transport);
    let transport = Arc::new(transport);
    let mut sc = quinn::ServerConfig::with_single_cert(vec![cert.clone()], key.into()).unwrap();
    sc.transport_config(transport.clone());
    let server = Endpoint::server(sc, (Ipv4Addr::LOCALHOST, 0).into()).unwrap();
    let addr = server.local_addr().unwrap();
    let mut roots = RootCertStore::empty();
    roots.add(cert).unwrap();
    let mut cc = quinn::ClientConfig::with_root_certificates(Arc::new(roots)).unwrap();
    cc.transport_config(transport);
    let mut client = Endpoint::client((Ipv4Addr::LOCALHOST, 0).into()).unwrap();
    client.set_default_client_config(cc);
    (server, client, addr)
}

/// A connected quinn pair; the endpoints are kept alive with it.
pub struct Conns {
    pub server: quinn::Connection,
    pub client: quinn::Connection,
    pub endpoints: (Endpoint, Endpoint),
}

pub async fn connect() -> Conns {
    connect_with(|_| {}).await
}

/// [`connect`], with `f` applied to the transport config.
pub async fn connect_with(f: impl FnOnce(&mut quinn::TransportConfig)) -> Conns {
    let (se, ce, addr) = endpoint_pair_with(f);
    let (server, client) =
        tokio::join!(async { se.accept().await.unwrap().await.unwrap() }, async {
            ce.connect(addr, "localhost").unwrap().await.unwrap()
        },);
    Conns {
        server,
        client,
        endpoints: (se, ce),
    }
}

/// Fail the test if `f` takes longer than 10 seconds.
pub async fn with_timeout<F: Future>(f: F) -> F::Output {
    tokio::time::timeout(Duration::from_secs(10), f)
        .await
        .expect("test timed out")
}

/// Lowercase hex SHA-256.
pub fn sha256(b: &[u8]) -> String {
    Sha256::digest(b)
        .iter()
        .map(|x| format!("{x:02x}"))
        .collect()
}

/// `n` deterministic bytes.
pub fn pattern(n: usize) -> Bytes {
    (0..n).map(|i| (i % 251) as u8).collect::<Vec<_>>().into()
}

pub fn full(b: impl Into<Bytes>) -> BoxBody {
    Full::new(b.into()).map_err(|e| match e {}).boxed_unsync()
}

/// An empty body (`is_end_stream`).
pub fn empty() -> BoxBody {
    Empty::new().map_err(|e| match e {}).boxed_unsync()
}

/// A body of the given frames.
pub fn frames(f: Vec<Frame<Bytes>>) -> BoxBody {
    StreamBody::new(futures::stream::iter(f.into_iter().map(Ok))).boxed_unsync()
}

/// `b` in 64 KiB DATA frames.
pub fn chunked(b: Bytes) -> BoxBody {
    let n = 64 * 1024;
    frames(
        (0..b.len())
            .step_by(n)
            .map(|i| Frame::data(b.slice(i..(i + n).min(b.len()))))
            .collect(),
    )
}

pub type Tx = futures::channel::mpsc::UnboundedSender<Result<Frame<Bytes>, BoxError>>;

/// A body fed through a channel; it ends when the sender is dropped.
pub fn chan() -> (Tx, BoxBody) {
    let (tx, rx) = futures::channel::mpsc::unbounded();
    (tx, StreamBody::new(rx).boxed_unsync())
}

pub fn data(tx: &Tx, b: &'static [u8]) {
    tx.unbounded_send(Ok(Frame::data(Bytes::from_static(b))))
        .unwrap();
}

/// A body that reports its first poll, then never yields.
pub struct Probe(pub Option<oneshot::Sender<()>>);

impl Body for Probe {
    type Data = Bytes;
    type Error = BoxError;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        _: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, BoxError>>> {
        if let Some(t) = self.0.take() {
            let _ = t.send(());
        }
        Poll::Pending
    }
}

/// The whole body and its trailers.
pub async fn collect<B>(body: B) -> Result<(Bytes, Option<HeaderMap>), B::Error>
where
    B: Body<Data = Bytes>,
{
    let c = body.collect().await?;
    let t = c.trailers().cloned();
    Ok((c.to_bytes(), t))
}

/// All of a tunnel's bytes until the peer's FIN.
pub async fn read_to_end(t: &mut h3wire_async::upgrade::Tunnel) -> Result<Vec<u8>, Error> {
    let mut out = Vec::new();
    while let Some(b) = t.recv().await? {
        out.extend_from_slice(&b);
    }
    Ok(out)
}

pub fn request(method: Method, path: &str, body: BoxBody) -> Request<BoxBody> {
    Request::builder()
        .method(method)
        .uri(format!("https://localhost{path}"))
        .body(body)
        .unwrap()
}

pub fn get(path: &str) -> Request<BoxBody> {
    request(Method::GET, path, empty())
}

/// A plain CONNECT to `host:443`.
pub fn connect_req(host: &str) -> Request<BoxBody> {
    Request::builder()
        .method(Method::CONNECT)
        .uri(format!("{host}:443"))
        .body(empty())
        .unwrap()
}

pub fn reply(status: u16, body: BoxBody) -> Response<BoxBody> {
    Response::builder().status(status).body(body).unwrap()
}

/// A Service from a closure.
#[derive(Clone)]
pub struct Svc<F>(pub F);

impl<F: FnMut(Request<RecvBody>) -> Fut> Service<Request<RecvBody>> for Svc<F> {
    type Response = Response<BoxBody>;
    type Error = BoxError;
    type Future = Fut;

    fn poll_ready(&mut self, _: &mut Context<'_>) -> Poll<Result<(), BoxError>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, req: Request<RecvBody>) -> Fut {
        (self.0)(req)
    }
}

pub type Reply = oneshot::Sender<Response<BoxBody>>;
pub type Handed = (Request<RecvBody>, Reply);

/// A Service that hands each request to the test with the sender for its response; its
/// future lives (the request task is not cancelled) while the `Reply` is open.
#[derive(Clone)]
pub struct Handoff(pub mpsc::UnboundedSender<Handed>);

impl Service<Request<RecvBody>> for Handoff {
    type Response = Response<BoxBody>;
    type Error = BoxError;
    type Future = Fut;

    fn poll_ready(&mut self, _: &mut Context<'_>) -> Poll<Result<(), BoxError>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, req: Request<RecvBody>) -> Fut {
        let (tx, rx) = oneshot::channel();
        let _ = self.0.send((req, tx));
        Box::pin(async move { rx.await.map_err(|_| "no response".into()) })
    }
}

pub fn handoff() -> (Handoff, mpsc::UnboundedReceiver<Handed>) {
    let (tx, rx) = mpsc::unbounded_channel();
    (Handoff(tx), rx)
}

/// A spawned server connection.
pub struct Server {
    shutdown: Option<oneshot::Sender<oneshot::Sender<()>>>,
    pub done: JoinHandle<Result<(), Error>>,
}

impl Server {
    /// Start its graceful shutdown; resolves once `graceful_shutdown` was called.
    pub async fn shutdown(&mut self) {
        let (tx, rx) = oneshot::channel();
        self.shutdown.take().unwrap().send(tx).unwrap();
        rx.await.unwrap();
    }
}

/// Serve `service` on `conn` in a task.
pub fn spawn_server<S>(conn: quinn::Connection, b: &Builder, service: S) -> Server
where
    S: Service<Request<RecvBody>, Response = Response<BoxBody>, Error = BoxError>
        + Clone
        + Send
        + 'static,
    S::Future: Send + 'static,
{
    let mut conn: ServerConnection<_, _, _> = h3wire_quinn::server(conn, b, service, TokioExecutor);
    let (tx, mut rx) = oneshot::channel::<oneshot::Sender<()>>();
    let mut waiting = true;
    let done = tokio::spawn(poll_fn(move |cx| {
        if waiting {
            if let Poll::Ready(r) = Pin::new(&mut rx).poll(cx) {
                waiting = false;
                if let Ok(ack) = r {
                    Pin::new(&mut conn).graceful_shutdown();
                    let _ = ack.send(());
                }
            }
        }
        Pin::new(&mut conn).poll(cx)
    }));
    Server {
        shutdown: Some(tx),
        done,
    }
}

/// An h3wire-async client and server over quinn.
pub struct Pair {
    pub send: SendRequest<BoxBody>,
    pub client: JoinHandle<Result<(), Error>>,
    pub server: Server,
    pub conns: Conns,
}

pub async fn pair<S>(service: S) -> Pair
where
    S: Service<Request<RecvBody>, Response = Response<BoxBody>, Error = BoxError>
        + Clone
        + Send
        + 'static,
    S::Future: Send + 'static,
{
    pair_with(connect().await, &Builder::new(), service).await
}

/// [`pair`] over `conns`, the server built by `sb`.
pub async fn pair_with<S>(conns: Conns, sb: &Builder, service: S) -> Pair
where
    S: Service<Request<RecvBody>, Response = Response<BoxBody>, Error = BoxError>
        + Clone
        + Send
        + 'static,
    S::Future: Send + 'static,
{
    let server = spawn_server(conns.server.clone(), sb, service);
    let (send, conn) = h3wire_quinn::client(conns.client.clone(), &Builder::new(), TokioExecutor)
        .await
        .unwrap();
    Pair {
        send,
        client: tokio::spawn(conn),
        server,
        conns,
    }
}

/// Poll `f` while stepping `peer`, until `f` completes.
pub async fn drive<F: Future>(peer: &mut Peer, f: F) -> F::Output {
    let mut f = pin!(f);
    poll_fn(|cx| {
        loop {
            if let Poll::Ready(v) = f.as_mut().poll(cx) {
                return Poll::Ready(v);
            }
            if peer.poll_step(cx).is_pending() {
                return Poll::Pending;
            }
        }
    })
    .await
}

pub fn finished(p: &Peer, s: StreamId) -> bool {
    p.trace().contains(&PeerObs::Event(Event::Finished(s)))
}

/// The `:status` of every header block received on `s`.
pub fn statuses(p: &Peer, s: StreamId) -> Vec<String> {
    p.headers(s)
        .iter()
        .filter_map(|h| {
            h.iter()
                .find(|(n, _)| n == ":status")
                .map(|(_, v)| v.clone())
        })
        .collect()
}

pub fn req_fields(method: &'static str, path: &'static str) -> Vec<(&'static str, &'static str)> {
    vec![
        (":method", method),
        (":scheme", "https"),
        (":authority", "localhost"),
        (":path", path),
    ]
}

/// A raw HEADERS frame (static QPACK only).
pub fn headers_frame(fields: &[(&str, &str)]) -> Vec<u8> {
    use h3wire_async::core::{FieldRef, frame, qpack};
    let f: Vec<FieldRef> = fields
        .iter()
        .map(|(n, v)| FieldRef::new(n.as_bytes(), v.as_bytes()))
        .collect();
    let mut block = Vec::new();
    qpack::encoder::encode_field_section(&f, &mut block);
    let mut out = Vec::new();
    frame::encode_header(0x01, block.len() as u64, &mut out);
    out.extend_from_slice(&block);
    out
}
