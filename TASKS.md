# PII Proxy — Implementation Tasks

Decisions applied:
- **Scan + redact in one pass**: single `spawn`-to-scanner-thread call that scans and
  optionally redacts, avoiding double CPU work.
- **Connection pooling**: `hyper-util` pooling client — one pool per upstream in reverse
  proxy mode, one global pool in forward proxy mode.
- **Graceful shutdown**: `tokio::signal` + `CancellationToken` propagated to all
  listeners; drain in-flight requests with configurable timeout.

---

## Phase 1 — Foundation

### 1.1 Project skeleton & dependencies
- [x] Set up `Cargo.toml` with all expected dependencies: `tokio`, `axum`, `hyper`,
  `hyper-util`, `http-body-util`, `tokio-rustls`, `rustls`, `rcgen`, `serde`,
  `toml`, `prometheus`, `bytes`, `tracing`, `tracing-subscriber`, `clap`
- [x] Add `pii` crate dependency (determine exact crate name / git source)
- [x] Create empty module files: `config.rs`, `scanner.rs`, `action.rs`,
  `reverse_proxy.rs`, `forward_proxy.rs`, `api.rs`, `admin.rs`, `metrics.rs`,
  `tls.rs`, `error.rs`
- [x] Wire up `mod` declarations in `main.rs`

### 1.2 Error types
- [x] Define `error.rs` with a unified `Error` enum (config errors, scanner errors,
  proxy errors, I/O errors)
- [x] Implement `From` conversions and `IntoResponse` for HTTP error responses
- [x] Unit tests for error conversions

### 1.3 Configuration
- [ ] Define config structs in `config.rs` matching the TOML structure from DESIGN.md:
  `AppConfig`, `PiiConfig`, `ScanConfig`, `ReverseProxyConfig`, `Route`,
  `ForwardProxyConfig`, `RestApiConfig`, `AdminConfig`, `TlsConfig`
- [ ] Derive `serde::Deserialize` for all config structs
- [ ] Implement `scanner_threads` default logic: auto-detect via
  `std::thread::available_parallelism()`, cap at 4 when cores <= 8, half otherwise
- [ ] Implement all validation rules from DESIGN.md:
  - At least one mode enabled
  - No port conflicts across enabled listeners
  - `header` requires `warn` or `redact`
  - `redact` requires `redact_strategy`
  - `char` strategy requires `mask_char`
  - `scanner_threads` >= 1
  - Reverse proxy: no overlapping `path_prefix`, valid upstream URLs
  - REST API: no `block`/`header` actions
- [ ] CLI parsing with `clap`: `--config` arg and `PII_PROXY_CONFIG` env fallback
- [ ] Unit tests for validation (valid config, each invalid case)

### 1.4 Metrics
- [ ] Define all Prometheus metrics in `metrics.rs` using `prometheus` crate macros /
  `lazy_static`:
  - `pii_proxy_detections_total` (counter, labels: `pii_kind`, `mode`, `route`)
  - `pii_proxy_blocked_total` (counter, labels: `mode`, `route`)
  - `pii_proxy_redacted_total` (counter, labels: `pii_kind`, `mode`, `route`)
  - `pii_proxy_requests_total` (counter, labels: `mode`, `route`, `method`, `status`)
  - `pii_proxy_request_duration_seconds` (histogram, labels: `mode`, `route`)
  - `pii_proxy_errors_total` (counter, labels: `outcome`, `reason`)
- [ ] Helper functions to increment metrics from action/proxy code
- [ ] Unit tests for metric helper functions

---

## Phase 2 — Scanner Thread Pool

### 2.1 Scanner service
- [ ] Define `ScanRequest` and `ScanResult` types in `scanner.rs`:
  - `ScanRequest`: contains text fragments to scan (body, URL, query, headers),
    action config (whether to redact), redact strategy
  - `ScanResult`: `detected: bool`, `kinds: Vec<PiiKind>`, `matches_count: usize`,
    optionally `redacted_body: Option<Bytes>`, `redacted_url: Option<String>`,
    `redacted_headers: Option<Vec<(String, String)>>`
- [ ] Implement `ScannerPool` struct:
  - On `new()`: spawn `scanner_threads` OS threads via `std::thread::spawn`
  - Each thread creates its own `pii::Scanner` instance from config
  - Bounded `crossbeam-channel` or `std::sync::mpsc` for receiving work
  - Each message: `(ScanRequest, tokio::sync::oneshot::Sender<ScanResult>)`
  - Thread loop: `recv()` → scan (and optionally redact) → send result via oneshot
- [ ] Implement async `ScannerPool::process(&self, req: ScanRequest) -> Result<ScanResult>`
  that sends request to channel and awaits the oneshot
- [ ] Handle channel-full / thread-dead scenarios according to `on_error` policy
- [ ] Implement `ScannerPool::shutdown()` — drop sender, join threads
- [ ] Unit tests: basic scan, redact, pool exhaustion behavior

---

## Phase 3 — Action Engine

### 3.1 Action pipeline
- [ ] Define action types in `action.rs`: `Action` enum (`Block`, `Warn`, `Header`,
  `Redact`), `ActionSet` (parsed and validated set of actions for a route)
- [ ] Implement `ActionEngine::execute()`:
  - Input: `ScanResult`, action config, request parts
  - Applies precedence: block → redact → header → warn
  - Returns `ActionOutcome`:
    - `Block { response: Response }` — 403 with JSON body listing PII kinds
    - `Forward { body: Bytes, extra_headers: HeaderMap, scan_result: ScanResult }`
    - `Pass` — no PII detected, forward unchanged
- [ ] Wire metrics increments into each action path (detections, blocked, redacted)
- [ ] Unit tests for each action combination and precedence

---

## Phase 4 — Admin Server

### 4.1 Admin endpoints
- [ ] Implement `admin.rs` axum router:
  - `GET /metrics` — render Prometheus metrics
  - `GET /healthz` — return 200
  - `GET /readyz` — return 200 once all listeners are bound (accept an
    `Arc<AtomicBool>` or similar readiness signal)
- [ ] Bind to configured `admin.listen` address
- [ ] Integration test: health and readiness endpoints, metrics rendering

---

## Phase 5 — Reverse Proxy Mode

### 5.1 Request handling pipeline
- [ ] Implement `reverse_proxy.rs` axum router:
  - Route matching by `path_prefix` (longest-prefix wins)
  - For each incoming request:
    1. Check content-type against allowed list; check body size
    2. Buffer body up to `max_body_size`
    3. Collect scan targets (URL, query, headers, body) per route scan config
    4. Submit to `ScannerPool`
    5. Run `ActionEngine::execute()` on result
    6. On `Block` → return 403
    7. On `Forward` → proxy to upstream with possibly mutated body/headers
    8. On `Pass` → proxy unchanged
- [ ] Upstream connection pooling: one `hyper-util` pooling client per upstream URL,
  stored in a `HashMap<String, Client>` built at startup
- [ ] Forward request preserving method, path suffix (strip prefix, append remainder),
  headers (minus hop-by-hop)
- [ ] Stream upstream response back to client
- [ ] Increment all relevant metrics

### 5.2 TLS termination (reverse proxy)
- [ ] In `tls.rs`: build `tokio_rustls::TlsAcceptor` from cert/key paths
- [ ] If `reverse_proxy.tls.enabled`, wrap the TCP listener with TLS acceptor

### 5.3 Integration tests
- [ ] Plain HTTP proxying end-to-end (proxy → echo upstream)
- [ ] Route matching: longest-prefix wins, unknown prefix returns 404
- [ ] Block action: request with PII returns 403, not forwarded
- [ ] Redact action: PII replaced in forwarded request body/headers
- [ ] Header action: `X-PII-Detected` header added to forwarded request
- [ ] Warn action: metrics incremented, request forwarded unchanged
- [ ] `on_error` fail-open and fail-close paths
- [ ] Oversized body handling

---

## Phase 6 — Load Testing

Setup and infrastructure per `docs/load-testing.md`.

### 6.1 Test infrastructure
- [ ] Echo server binary (`benches/echo_server.rs`)
- [ ] Payload generation script — clean and PII-containing payloads at 100 B,
  1 KB, 10 KB, 100 KB, 1 MB
- [ ] Test TOML configs in `benches/configs/` (one per scenario variant)

### 6.2 k6 test scenarios
- [ ] Baseline — proxy overhead vs direct-to-upstream, clean payloads
- [ ] Action comparison — warn vs block vs redact cost
- [ ] Body size scaling — throughput degradation from 100 B to 1 MB
- [ ] Concurrency scaling — saturation point and tail latency (1 to 500 connections)
- [ ] Scanner thread scaling — effect of `scanner_threads` 1/2/4/8

### 6.3 Automation
- [ ] `benches/run_all.sh` — builds, starts servers, runs all scenarios,
  collects JSON results, prints summary table

---

## Phase 7 — REST API Mode

### 7.1 REST API endpoints
- [ ] Implement `api.rs` axum router:
  - `POST /v1/scan` — accept JSON `{ "text": "..." }`, scan via `ScannerPool`,
    return `{ "detected": bool, "matches_count": N, "kinds": [...] }`
  - `POST /v1/redact` — accept JSON `{ "text": "..." }`, scan+redact via
    `ScannerPool`, return `{ "text": "...", "redacted_count": N, "kinds": [...] }`
  - `GET /v1/health` — 200
  - `GET /v1/config` — return current PII scanner config as JSON
- [ ] Respect `max_body_size` / `on_error` for incoming requests
- [ ] Increment `pii_proxy_requests_total` with `mode=rest_api`
- [ ] Integration tests: scan detection, redaction, oversized body, health

---

## Phase 8 — Forward Proxy Mode

### 8.1 Forward proxy handler
- [ ] Implement `forward_proxy.rs`:
  - Parse absolute-form URI from request line (standard forward proxy behavior)
  - Same pipeline as reverse proxy: buffer → scan → action → forward
  - Single global `hyper-util` pooling client for all destinations
- [ ] No CONNECT support — return 405 for CONNECT method

### 8.2 Forward proxy TLS (MITM)
- [ ] Client-facing: TLS termination using configured CA cert/key
- [ ] Dynamic per-host certificate generation via `rcgen`, signed by the CA
- [ ] Cache generated certs (bounded LRU cache keyed by hostname)
- [ ] Upstream-facing: TLS origination via `hyper-rustls` / `rustls` client config
- [ ] Integration tests: HTTP forwarding, action pipeline

---

## Phase 9 — Load Testing (Full Suite)

Extend load testing from Phase 6 to cover all modes.

### 9.1 Additional scenarios
- [ ] Mode comparison — reverse proxy vs forward proxy vs REST API
- [ ] Soak test — 30 min at 80% max rate, monitor memory, file descriptors, p99 drift

---

## Phase 10 — Main Entrypoint & Lifecycle

### 10.1 Startup orchestration
- [ ] `main.rs`:
  1. Parse CLI args, load and validate config
  2. Initialize `tracing` subscriber
  3. Initialize Prometheus metrics registry
  4. Create `ScannerPool`
  5. Create `ActionEngine` (stateless, config-driven)
  6. Spawn enabled listeners as tokio tasks:
     - Admin server (always on)
     - Reverse proxy (if enabled)
     - Forward proxy (if enabled)
     - REST API (if enabled)
  7. Set readiness flag once all listeners are bound
  8. Await shutdown signal

### 10.2 Graceful shutdown
- [ ] `tokio::signal::ctrl_c()` + SIGTERM handler → trigger `CancellationToken`
- [ ] Each listener: stop accepting new connections, drain in-flight with timeout
- [ ] `ScannerPool::shutdown()` — drain channel, join threads
- [ ] Exit with 0

---

## Phase 11 — End-to-End Testing

### 11.1 Cross-mode integration tests
- [ ] Full integration test: start binary with test config, send requests through
  each mode, verify scan/block/redact/header behavior end-to-end
- [ ] Test config validation rejects all invalid cases at startup
