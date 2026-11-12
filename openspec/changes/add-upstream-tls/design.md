## Context

See proposal.md - Why. The current state that shapes the approach:

- `reverse_proxy::build_state` builds one `Client<HttpConnector, Body>` per distinct
  upstream with `build_http()`. It is infallible.
- `server::run` binds the reverse proxy listener and then spawns a task that calls
  `serve_on`, which calls `build_state`. A failure inside that task is only logged; it
  does not stop the start.
- `Host` is stripped before forwarding and hyper rebuilds it from the upstream URI.
  `build_upstream_uri` appends the request path to the upstream, so an upstream with a
  path, such as `https://openrouter.ai/api`, already works.
- A connection failure maps through `From<hyper_util::client::legacy::Error>` to
  `Error::Proxy`, which answers 502 and counts `reason="upstream_error"`.
- The image is `debian:trixie-slim` with `ca-certificates`.
- No TLS crate is in `Cargo.lock`.

## Goals / Non-Goals

**Goals:**

- One client type that serves `http` and `https` upstreams, so the routing code does not
  branch on the scheme.
- The trust set of every upstream is built, and every CA bundle read, before any
  data-plane listener binds.

**Non-Goals:**

- Client certificates (mutual TLS) toward the upstream.
- An outbound HTTP proxy (`HTTPS_PROXY`) for the upstream connection.
- Reloading a CA bundle without a restart.
- TLS on the HTTP API or the admin server.

## Decisions

### D1. rustls on the ring provider, with the native root store

`hyper-rustls` 0.27 with default features off and `native-tokio`, `http1`, `http2`,
`tls12`, `ring`. This pulls `rustls` 0.23, `rustls-native-certs`, and `tokio-rustls`.

- Rejected `aws-lc-rs`, the rustls default: it needs cmake and a longer C build, and its
  FIPS mode is not a goal.
- Rejected `native-tls` with OpenSSL: it links the system `libssl` dynamically and
  negotiates HTTP/2 less well. It is the only way to avoid ISC, and ISC was accepted.
- Rejected `webpki-roots`: the roots would be fixed at build time, and its license is
  CDLA-Permissive-2.0. The image already ships `ca-certificates`.
- Rejected `rustls-platform-verifier`: on Linux it reads the same store, with more
  dependencies.

`rustls-native-certs` honors `SSL_CERT_FILE` and `SSL_CERT_DIR` and otherwise reads the
system store (`/etc/ssl/certs` in the image). The protocol versions are the rustls
defaults, TLS 1.2 and 1.3. TLS 1.2 stays for corporate gateways that do not offer 1.3.

### D2. One connector type, one `ClientConfig` per CA bundle

`clients: HashMap<String, Client<HttpsConnector<HttpConnector>, Body>>`. The connector
is built with `https_or_http()`, so the URI scheme picks plain HTTP or TLS. Its ALPN
offers `h2` and `http/1.1` (`enable_all_versions()`), and the hyper-util client
uses HTTP/2 when the upstream selects it. A plain `http` connection never negotiates, so
it stays HTTP/1.1 (no h2c).

The system roots load once into a `RootCertStore`. An upstream without
`upstream_ca_path` uses a `ClientConfig` over that store. An upstream with a bundle uses
a clone of the store with the bundle's certificates added. Validation guarantees that
all routes of one upstream agree on the bundle, so the client stays keyed by the upstream
string, as the `One pooled client per upstream` requirement states.

- Rejected an enum of a plain client and a TLS client: every forwarding call would match
  on it, for no gain, since `https_or_http` already dispatches by scheme.

The roots load only when at least one route names an `https` upstream, so a config of
plain upstreams reads no certificate store.

### D3. Build the upstream clients before the listener binds

A new fallible constructor, for example `UpstreamClients::build(&AppConfig) ->
Result<_, Error>`, runs in `server::run` after the engine is built and before the reverse
proxy listener binds. `serve_on` and `build_state` take the built clients instead of
building them. A missing, unreadable, or empty bundle returns `Error::Config` naming the
route's `path_prefix` and the path; `run` returns it and the process exits non-zero.
This matches how a model guard that fails to load stops the start.

A PEM file parses through `rustls-pki-types` (`CertificateDer::pem_file_iter`). A file
with no certificate is an error: a bundle that adds nothing is a config mistake.

### D4. Root store errors warn, they do not stop the start

`rustls-native-certs` returns the certificates it loaded and the errors it met. The
proxy logs one `warn!` with the error count and one `info!` with the loaded count. If the
store loads no certificate, the proxy still starts and logs a `warn!`; an `https`
upstream that relies on the system roots then answers 502. Stopping the start here would
add a requirement that was not agreed.

### D5. Errors and timeouts reuse the existing paths

A TLS failure surfaces as a `hyper_util::client::legacy::Error` from the connect step,
so it reaches the existing 502 path and `reason="upstream_error"`. The log line carries
the error chain, so the operator sees the certificate cause. It holds no message
content. `upstream_timeout_secs` wraps the whole exchange future, so it covers the TCP
connect and the TLS handshake too.

`HOP_BY_HOP_HEADERS` already strips `connection`, `keep-alive`, `te`,
`transfer-encoding`, and `upgrade`, which HTTP/2 forbids, so a forwarded request is
valid on HTTP/2 unchanged.

### D6. Validation in `config.rs`

`Route` gets `upstream_ca_path: Option<PathBuf>` with `#[serde(default)]`. The three
`semantic` checks of the configuration delta run in `AppConfig::validate`, next to the
upstream scheme check. They compare `upstream` strings as written, the same identity the
client map uses. They do not touch the file system, so validate mode keeps its
"opens no TLS material" rule.

### D7. Tests

- Unit tests in `config.rs` with `#[test_case]` for every validation scenario, and in the
  key reference test for the new key.
- A test CA from `rcgen` (dev dependency, MIT OR Apache-2.0) issues a server certificate
  for `localhost`, and a second certificate for another name.
- An in-process HTTPS echo server (`tokio-rustls` acceptor and the hyper server) records
  the HTTP version of each request and can be limited to `http/1.1` in its ALPN list.
- `upstream_tls_integration.rs` (new; the `reverse_proxy_integration.rs` harness builds `http://` routes only), with the helper in `tests/support/tls.rs`: CA bundle trusted, no bundle → 502, wrong host → 502,
  `h2` selected, `http/1.1` only, plain `http` upstream unchanged.
- `startup_integration.rs`, which spawns the binary: the system root scenario runs it
  with `SSL_CERT_FILE` naming CA A and a route bundle of CA B; a missing bundle and an
  empty bundle each exit non-zero with no data-plane port bound.
- `validate_cli_integration.rs`: a missing bundle path passes `--validate`.

## Risks / Trade-offs

- [cargo-about may not match ring's license files, which hold several texts] → add a
  `clarify` entry for `ring` in `about.toml` if `docker/ctl compile` fails on it.
- [An upstream gateway misbehaves on HTTP/2] → ALPN lets the server choose; there is no
  knob to force HTTP/1.1. Add one only when a real upstream needs it.
- [`SSL_CERT_FILE` in the container replaces the system store, not adds to it] → the docs
  say to use `upstream_ca_path` for an extra CA, and name the variable's effect.
- [The app-to-Voidwall leg stays plain HTTP, with the provider API key in
  `Authorization`] → unchanged by this change; the recipes keep that leg on one host or
  one Docker network. Inbound TLS stays backlog 1.1.
- [The binary grows by the rustls and ring code] → accepted.

## Migration Plan

No config changes. A config with an `https` upstream that answered 502 now forwards.
Rollback is the previous image; a config that sets `upstream_ca_path` then fails as an
unknown key.

## Open Questions

- Which hosted provider the AnythingLLM recipe shows (OpenAI or OpenRouter), and the
  model, is a docs choice made in the docs-sync step.
