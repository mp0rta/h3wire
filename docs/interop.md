# Interop

h3wire-async over quinn (`h3wire-quinn`), tested against other HTTP/3 implementations
in Docker, plus h3spec and a manual Chrome check. The job runs weekly and on manual
dispatch (`.github/workflows/interop.yml`), not on pull requests. For a release, it is
dispatched on the release-candidate tag; an earlier green run does not count.

## Running it

```sh
interop/run.sh               # builds both images, then runs the matrix and h3spec
SKIP_BUILD=1 interop/run.sh  # reuses the images
```

It writes `target/interop-report.md` and exits non-zero on any mandatory failure, or on
any h3spec failure not in `interop/h3spec-allowlist`. Per-cell logs go to
`target/interop/out/<cell>.log`, the h3spec output to `target/interop/h3spec.txt`.
The run takes about 15 s once the images exist. A cold build of the images takes a few
minutes, mostly BoringSSL and quiche.

Files in `interop/`:

- `versions.env` pins every peer to a release tag and the tag's commit (the build fails
  if the tag moved), the h3spec release binary (URL and SHA-256), and the base images.
  These change only by a deliberate PR.
- `Dockerfile.peers` builds curl, the ngtcp2 example client and server, quiche-client
  and quiche-server, and adds h3spec. `Dockerfile.h3wire` builds our examples.
- `cells.tsv` is the matrix: `capability  peer  version  direction  command  status`.
  A `mandatory` cell runs its exact command; an `unsupported-by-peer-tooling` cell
  records in its command column why no command exists.
- `h3spec-allowlist` lists the expected h3spec failures.

Our side is `h3wire-quinn/examples/{server,client}.rs`:

- The server serves `GET /bytes/{n}`, `POST /sha256`, `GET /trailers` (trailer
  `x-check: ok`) and `GET /goaway` (replies, then starts that connection's graceful
  shutdown). With `--masque-echo` it accepts Extended CONNECT `connect-udp` and echoes
  datagrams and tunnel bytes.
- The client prints `status=<code> sha256=<hex of the body>` per response, and exits
  non-zero on an error, a non-2xx status, or a hash mismatch.

## Pass criteria

Against our server, every cell also needs each connection it opened to close cleanly at
our server: its graceful shutdown completed, or the peer closed with `H3_NO_ERROR` or
with the QUIC transport's `NO_ERROR`. The server logs `closed cleanly`.

- **GET, POST large body, concurrent (16):** the peer gets complete, correct bodies,
  checked by SHA-256. Bodies are 1 MiB and 8 MiB of `a`, and the upload is 10 MiB.
  The 16 concurrent requests share one connection.
- **Trailers:**
  - against our server, the peer reports the trailer `x-check: ok`;
  - against the ngtcp2 server (`--send-trailers`), our client reports its
    `x-ngtcp2-stream-id` trailer.
- **GOAWAY, against our server:** the peer requests an 8 MiB body and `/goaway` on one
  connection. Two things must hold:
  - the in-flight 8 MiB response completes intact;
  - our server's graceful shutdown completes, so it closes the connection with
    `H3_NO_ERROR` (0x100), logged as `closed cleanly`.

  Seeing the final GOAWAY is not a criterion. Its delivery is best-effort: the close may
  arrive without it, because quinn's close discards stream data still queued.
- **GOAWAY, from our client:** our client (`--goaway`) starts its graceful shutdown
  (GOAWAY) once the response HEADERS arrive, with the 8 MiB body still in flight. The
  body must complete and the connection must close cleanly.

## Matrix

Run on 2026-10-11 with h3wire `21c0ebc` plus this change. Every mandatory cell passed,
every connection to our server closed cleanly.

| capability | peer | version | direction | result |
|---|---|---|---|---|
| GET | curl | curl-8_22_0 / ngtcp2 v1.25.0 / nghttp3 v1.18.0 | peer → h3wire | pass |
| POST large body | curl | curl-8_22_0 / ngtcp2 v1.25.0 / nghttp3 v1.18.0 | peer → h3wire | pass |
| trailers | curl | curl-8_22_0 / ngtcp2 v1.25.0 / nghttp3 v1.18.0 | peer → h3wire | pass |
| concurrent (16) | curl | curl-8_22_0 / ngtcp2 v1.25.0 / nghttp3 v1.18.0 | peer → h3wire | pass |
| GOAWAY | curl | curl-8_22_0 / ngtcp2 v1.25.0 / nghttp3 v1.18.0 | peer → h3wire | pass |
| GET | ngtcp2 example client | ngtcp2 v1.25.0 / nghttp3 v1.18.0 | peer → h3wire | pass |
| POST large body | ngtcp2 example client | ngtcp2 v1.25.0 / nghttp3 v1.18.0 | peer → h3wire | pass |
| trailers | ngtcp2 example client | ngtcp2 v1.25.0 / nghttp3 v1.18.0 | peer → h3wire | pass |
| concurrent (16) | ngtcp2 example client | ngtcp2 v1.25.0 / nghttp3 v1.18.0 | peer → h3wire | pass |
| GOAWAY | ngtcp2 example client | ngtcp2 v1.25.0 / nghttp3 v1.18.0 | peer → h3wire | pass |
| GET | quiche-client | quiche 0.30.0 | peer → h3wire | pass |
| POST large body | quiche-client | quiche 0.30.0 | peer → h3wire | pass |
| trailers | quiche-client | quiche 0.30.0 | peer → h3wire | pass |
| concurrent (16) | quiche-client | quiche 0.30.0 | peer → h3wire | pass |
| GOAWAY | quiche-client | quiche 0.30.0 | peer → h3wire | pass |
| GET | ngtcp2 example server | ngtcp2 v1.25.0 / nghttp3 v1.18.0 | h3wire → peer | pass |
| POST large body | ngtcp2 example server | ngtcp2 v1.25.0 / nghttp3 v1.18.0 | h3wire → peer | pass |
| trailers | ngtcp2 example server | ngtcp2 v1.25.0 / nghttp3 v1.18.0 | h3wire → peer | pass |
| concurrent (16) | ngtcp2 example server | ngtcp2 v1.25.0 / nghttp3 v1.18.0 | h3wire → peer | pass |
| GOAWAY | ngtcp2 example server | ngtcp2 v1.25.0 / nghttp3 v1.18.0 | h3wire → peer | pass |
| GET | quiche-server | quiche 0.30.0 | h3wire → peer | pass |
| POST large body | quiche-server | quiche 0.30.0 | h3wire → peer | unsupported (1) |
| trailers | quiche-server | quiche 0.30.0 | h3wire → peer | unsupported (2) |
| concurrent (16) | quiche-server | quiche 0.30.0 | h3wire → peer | pass |
| GOAWAY | quiche-server | quiche 0.30.0 | h3wire → peer | pass |
| Extended CONNECT (connect-udp) | all peers | as above | both | unsupported (3) |
| HTTP datagrams (RFC 9297) | all peers | as above | both | unsupported (3) |

Unsupported by peer tooling:

1. quiche-server answers only GET (405 to any other method). It also stops reading every
   request stream after its HEADERS (STOP_SENDING), so it never reads an upload.
2. quiche-server sends no response trailers, and does not read request trailers (see 1).
3. No peer tool in the matrix speaks RFC 9298 to an echo server:
   - the ngtcp2 examples and quiche's apps have no Extended CONNECT at all (quiche-server
     rejects `:protocol`; `--dgram-proto` sends datagrams without Extended CONNECT);
   - curl 8.21+ speaks CONNECT-UDP only as the client of an HTTP/3 proxy
     (`--proxy-http3`, experimental, needs a `USE_PROXY_HTTP3` build). That needs a proxy
     that forwards to a target, and our server only echoes.

   MASQUE interop moves to v0.3. The echo route itself was checked locally
   with the h3wire client: a 200 with `capsule-protocol: ?1`, context-ID-0 datagrams
   echoed, other context IDs dropped, and capsule bytes echoed until FIN.

### Observations

Recorded from the cell logs:

- **curl closes with QUIC's transport-level `NO_ERROR`.** It sends CONNECTION_CLOSE type
  0x1c, code 0, instead of the application close `H3_NO_ERROR` (0x100). The default
  close error is set at `lib/vquic/cf-ngtcp2-cmn.c:1093` (`ngtcp2_ccerr_default`) and
  sent at `:1259`. h3wire-async treats it as a clean close (the connection future
  resolves `Ok`; handles still see `Transport`). The ngtcp2 client and quiche-client
  close with `H3_NO_ERROR`.
- **quiche-server stops reading our 10 MiB upload with `STOP_SENDING(0)`** and sends a
  complete response. Our client keeps that response, as RFC 9114 §4.1 requires: the
  status (405 for POST, 200 for a GET with a body) and the body arrive, and the
  connection closes cleanly. This was checked by hand, outside the matrix.

## h3spec

h3spec v0.1.14 (release binary, SHA-256 pinned in `versions.env`) runs against our
server: `h3spec -n h3wire 4433`. It is not a complete HTTP/3 certification.

There are 77 cases and 3 failures, all allowlisted. Failures are classified by layer:
`quic` failures belong to quinn and its TLS (rustls), `h3` failures to h3wire.

| case | description | layer | ruling |
|---|---|---|---|
| `TransportError.hs:245:32` | MUST send missing_extension TLS alert if the quic_transport_parameters extension does not included [TLS 8.2] (second variant: parameters under the draft codepoint 0xffa5) | quic | rustls, through quinn, accepts the draft codepoint. Allowlisted, attributed to quinn. The first variant (no parameters at all) passes. |
| `HTTP3Error.hs:216:21` | MUST NOT buffer a frame longer than SETTINGS_MAX_FIELD_SECTION_SIZE [HTTP/3 7.1] | h3 | The frame is a GOAWAY whose declared length is 2^30. We close with `H3_FRAME_ERROR` at the frame header, without buffering. h3spec expects `H3_EXCESSIVE_LOAD`. RFC 9114 §7.1: a GOAWAY payload is exactly one varint, so a longer payload MUST be `H3_FRAME_ERROR`. Allowlisted. |
| `HTTP3Error.hs:277:21` | MUST send H3_CLOSED_CRITICAL_STREAM if an encoder stream ends inside an instruction [QPACK 4.2] | h3 | The partial instruction is the octet 0x3f, a Set Dynamic Table Capacity of at least 31. Our limit is 0, since we send no `SETTINGS_QPACK_MAX_TABLE_CAPACITY`, so that octet MUST be `QPACK_ENCODER_STREAM_ERROR` (RFC 9204 §4.3.1). We detect it before the FIN. Allowlisted. |

Case ids are the source locations h3spec prints. They hold for the pinned binary only;
re-check them when h3spec is bumped. `run.sh` lists an allowlisted case that passes,
but does not fail on it.

## Chrome (manual)

Chrome is tested by hand once; the steps and the result are recorded here.

**Steps**

1. Make a short-lived self-signed certificate for `localhost`:

   ```sh
   openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 14 \
     -subj /CN=localhost -addext subjectAltName=DNS:localhost \
     -addext basicConstraints=critical,CA:FALSE -keyout key.pem -out cert.pem
   ```

2. Compute its SPKI hash:

   ```sh
   openssl x509 -in cert.pem -pubkey -noout | openssl pkey -pubin -outform der \
     | openssl dgst -sha256 -binary | base64
   ```

3. Start the server. `[::]` also accepts IPv4 on Linux, which matters because Chrome may
   resolve `localhost` to `::1`:

   ```sh
   cargo run --release -p h3wire-quinn --example server -- \
     --listen '[::]:4433' --cert cert.pem --key key.pem
   ```

4. Start Chrome with a fresh profile:

   ```sh
   google-chrome --user-data-dir="$(mktemp -d)" \
     --origin-to-force-quic-on=localhost:4433 \
     --ignore-certificate-errors-spki-list=<spki from step 2> \
     https://localhost:4433/bytes/1000
   ```

5. Check the two pages:
   - `/bytes/1000` shows 1000 `a` characters, and the DevTools Network panel shows the
     protocol `h3`;
   - `/trailers` loads the body `trailers` over `h3` without an error. Chrome does not
     display trailers.
6. Close Chrome. The server log shows the connection as `accepted`, then `closed`.

**Record**

- Date: _to be filled in_
- Chrome version: _to be filled in_
- Result: not yet run (manual step pending)
