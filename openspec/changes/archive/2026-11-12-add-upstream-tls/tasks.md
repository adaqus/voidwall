## 1. Dependencies and license gate

- [x] 1.1 Add `hyper-rustls` 0.27 to `crates/voidwall/Cargo.toml` with
  `default-features = false` and `native-tokio`, `http1`, `http2`, `tls12`, `ring`; add
  `rustls-pki-types` with its PEM support if `hyper-rustls` does not re-export it. Check:
  `cargo tree -p voidwall -i aws-lc-rs` and `cargo tree -p voidwall -i webpki-roots`
  find nothing.
- [x] 1.2 Add `ISC` to `deny.toml` `allow` and `about.toml` `accepted`. Check:
  `cargo deny check licenses` passes.
- [x] 1.3 Add dev dependencies `rcgen` (ring provider) and `tokio-rustls` for the test
  server. Check: `cargo check -p voidwall --tests` passes.

## 2. Configuration

- [x] 2.1 Add `upstream_ca_path: Option<PathBuf>` to `Route` (D6). Check: a config with
  the key parses; the key reference test fails until 5.1 documents it.
- [x] 2.2 Add the three `semantic` checks: empty path, key on an `http` upstream, and
  routes of one upstream that disagree on the key. Check: `#[test_case]` unit tests for
  every scenario of `A route's upstream CA bundle is validated` pass.

## 3. Upstream clients

- [x] 3.1 Build the root store once, only when a route names an `https` upstream, with
  the `warn!`/`info!` lines of D4. Check: unit test that a config of `http` upstreams
  builds clients without reading a store.
- [x] 3.2 Add the fallible client builder of D3: one
  `Client<HttpsConnector<HttpConnector>, Body>` per upstream, `https_or_http()`, ALPN
  `h2` and `http/1.1`, the route bundle added to a clone of the root store. A missing,
  unreadable, unparsable, or empty bundle returns `Error::Config` naming the
  `path_prefix` and the path. Check: unit tests for a valid bundle, a missing file, a
  file with no certificate, and a file with a broken PEM block.
- [x] 3.3 Call the builder in `server::run` before the reverse proxy listener binds, and
  pass the clients to `serve_on` and `build_state`. Update their callers in tests.
  Check: `cargo test -p voidwall` passes.
- [x] 3.4 Confirm a TLS failure reaches the existing 502 path with
  `reason="upstream_error"` and that `upstream_timeout_secs` covers the handshake (D5).
  Check: covered by the integration tests in 4.2 and 4.3.

## 4. Integration tests

- [x] 4.1 Add a test helper: an `rcgen` CA, a server certificate for `localhost`, one for
  another name, and an HTTPS echo server that records the HTTP version and can limit its
  ALPN list to `http/1.1`. Check: used by 4.2 to 4.4.
- [x] 4.2 `upstream_tls_integration.rs`: the route bundle is trusted; no bundle → 502
  `{"error":"upstream error"}` and `voidwall_errors_total{outcome="blocked",reason="upstream_error"}`
  increments; a certificate for another host → 502. Check: new tests pass.
- [x] 4.3 `upstream_tls_integration.rs`: the upstream selects `h2` → HTTP/2; the upstream
  offers only `http/1.1` → HTTP/1.1; a plain `http` upstream → HTTP/1.1 without TLS; an
  `openai-chat` route with a streamed answer over HTTP/2 is scanned as before. Check: new
  tests pass.
- [x] 4.4 `startup_integration.rs`: with `SSL_CERT_FILE` naming CA A, an upstream signed
  by CA A is reached both from a route with no bundle and from a route with a bundle of
  CA B; a missing bundle and a bundle with no
  certificate each exit non-zero, log the route and the path, and bind no data-plane
  port. Check: new tests pass.
- [x] 4.5 `validate_cli_integration.rs`: a config whose `upstream_ca_path` does not exist
  passes `--validate`. Check: new test passes.

## 5. Documentation

- [x] 5.1 `docs/configuration.md`: add `reverse_proxy.routes[].upstream_ca_path`, its
  validation rules, that it adds to the system roots, that verification cannot be turned
  off, and that `SSL_CERT_FILE` replaces the system store. Check: the config.rs key
  reference test passes.
- [x] 5.2 `ARCHITECTURE.md` § 7: remove the "Upstream TLS" row and describe the built
  behavior where the reverse proxy forwarding is described; remove item 1.4 from
  `docs/dev/backlog.md`. Check: `grep -n "build_http" ARCHITECTURE.md docs/dev/backlog.md`
  finds nothing.
- [x] 5.3 Run the `docs-sync` skill: drop the plain-HTTP-only notice from
  `docs/recipes/README.md` and `docs/recipes/anythingllm.md`, and add a hosted-model
  section to the AnythingLLM recipe (Generic OpenAI → Voidwall → `https` upstream).
  Check: docs-sync reports no stale page.
- [x] 5.4 Confirm no Grafana change is needed: no metric family, label, or reason value
  is added. Check: `grep -n errors_total docker/grafana/dashboards/voidwall.json` shows
  only the `sum by (outcome, reason)` query, which takes every reason unchanged.

## 6. Verification

- [x] 6.1 Run `cargo test --workspace`, `cargo clippy --workspace --all-targets` (no
  warnings), and `cargo deny check licenses`. Check: all three pass.
- [x] 6.2 Run `docker/ctl compile`. Check: it passes the license gate and the generated
  notices file holds the ISC text of `ring`, `rustls-webpki`, and `untrusted`.
- [x] 6.3 End to end, with the user's API key: AnythingLLM (Generic OpenAI) → Voidwall
  image → the hosted provider chosen in 5.3. A clean message gets an answer; a message
  with a prompt injection gets `400 content blocked`. Check: both results recorded in the
  recipe's "Tested with" line.
- [x] 6.4 Review the diff against the spec deltas with the `code-review` skill. Check: no
  finding left open.
