# PII Proxy — Implementation Tasks

Decisions applied:
- **Scan + redact in one pass**: single `spawn`-to-scanner-thread call that scans and
  optionally redacts, avoiding double CPU work.
- **Connection pooling**: `hyper-util` pooling client — one pool per upstream in reverse
  proxy mode, one global pool in forward proxy mode.
- **Graceful shutdown**: `tokio::signal` + `CancellationToken` propagated to all
  listeners; drain in-flight requests with configurable timeout.
- **Structured body scanning**: JSON and CSV/TSV bodies are parsed into context-value
  fragments before scanning (hybrid approach). The `pii` crate gains a
  `mark_piis_structured` API that accepts fragments with context (key path / column
  name), value, and document byte offset. Structured scanning fully replaces flat
  text scanning for these content types. CSV/TSV without headers falls back to flat
  text scanning.

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
- [x] Define config structs in `config.rs` matching the TOML structure from DESIGN.md:
  `AppConfig`, `PiiConfig`, `ScanConfig`, `ReverseProxyConfig`, `Route`,
  `ForwardProxyConfig`, `RestApiConfig`, `AdminConfig`, `TlsConfig`
- [x] Derive `serde::Deserialize` for all config structs
- [x] Config changes for request/response action split:
  - Remove `Action::Warn` variant
  - Add `DirectionConfig` struct with `actions`, `redact_strategy`, `mask_char`,
    `block_status`, `block_body`, `block_headers`
  - `ReverseProxyConfig`: add `request: DirectionConfig` and `response: DirectionConfig`
    (mode-level only, not overridable per route)
  - `Route`: only `path_prefix`, `upstream`, and optional `scan` override — no
    `request`/`response` action overrides (for different action policies, deploy
    separate proxy instances)
  - `ForwardProxyConfig`: add `request: DirectionConfig` and `response: DirectionConfig`
  - Remove flat `redact_strategy`, `mask_char` from `Route` and `ForwardProxyConfig`
  - Default action sets: reverse proxy request `["redact", "header"]`,
    reverse proxy response `["redact"]`, forward proxy request `["redact"]`,
    forward proxy response `["redact", "header"]`
  - Move `on_error` into `ScanConfig`
  - Rename `pii_kinds` → `detect`, `exclude_pii_kinds` → `ignore` in `PiiConfig`
- [x] Implement `scanner_threads` default logic: auto-detect via
  `std::thread::available_parallelism()`, cap at 4 when cores <= 8, half otherwise
- [x] Implement all validation rules from DESIGN.md:
  - At least one mode enabled
  - No port conflicts across enabled listeners
  - `block` and `header` mutually exclusive in same direction's `actions` list
  - `header` only valid in `reverse_proxy.*.request` and `forward_proxy.response`
  - `redact` requires `redact_strategy`
  - `char` strategy requires `mask_char`
  - `scanner_threads` >= 1
  - Reverse proxy: no overlapping `path_prefix`, valid upstream URLs
  - Reverse proxy: routes must not define `request`/`response` action overrides
  - HTTP API: no `block`/`header` actions
- [x] CLI parsing with `clap`: `--config` arg and `PII_PROXY_CONFIG` env fallback
- [x] Unit tests for validation (valid config, each invalid case)

### 1.4 Metrics
- [x] Define all Prometheus metrics in `metrics.rs` using `prometheus` crate macros /
  `lazy_static`:
  - `pii_proxy_detections_total` (counter, labels: `pii_kind`, `mode`, `route`, `direction`)
  - `pii_proxy_blocked_total` (counter, labels: `mode`, `route`, `direction`)
  - `pii_proxy_redacted_total` (counter, labels: `pii_kind`, `mode`, `route`, `direction`)
  - `pii_proxy_requests_total` (counter, labels: `mode`, `route`, `method`, `status`)
  - `pii_proxy_request_duration_seconds` (histogram, labels: `mode`, `route`)
  - `pii_proxy_errors_total` (counter, labels: `outcome`, `reason`)
- [x] Helper functions to increment metrics from action/proxy code
  - All detection/blocked/redacted helpers take a `direction` parameter (`"request"` or `"response"`)
- [x] Unit tests for metric helper functions

---

## Phase 2 — Scanner Thread Pool

### 2.1 Scanner service
- [x] Define `ScanRequest` and `ScanResult` types in `scanner.rs`:
  - `ScanRequest`: contains text fragments to scan (body, URL, query, headers),
    action config (whether to redact), redact strategy
  - `ScanResult`: `detected: bool`, `kinds: Vec<String>`, `matches_count: usize`,
    optionally `redacted_body: Option<Bytes>`, `redacted_url: Option<String>`,
    `redacted_query: Option<String>`, `redacted_headers: Option<Vec<(String, String)>>`
- [x] Implement `ScannerPool` struct:
  - On `new()`: spawn `scanner_threads` OS threads via `std::thread::spawn`
  - Each thread creates its own `pii::Scanner` instance from config
  - Bounded `crossbeam-channel` or `std::sync::mpsc` for receiving work
  - Each message: `(ScanRequest, tokio::sync::oneshot::Sender<ScanResult>)`
  - Thread loop: `recv()` → scan (and optionally redact) → send result via oneshot
- [x] Implement async `ScannerPool::process(&self, req: ScanRequest) -> Result<ScanResult>`
  that sends request to channel and awaits the oneshot
- [x] Handle channel-full / thread-dead scenarios according to `on_error` policy
- [x] Implement `ScannerPool::shutdown()` — drop sender, join threads
- [x] Unit tests: basic scan, redact, pool exhaustion behavior

---

## Phase 3 — Action Engine

### 3.1 Action pipeline
- [x] Define action types in `action.rs`: `ActionSet` (parsed and validated set
  of actions for a direction). Uses `Action` enum (`Block`, `Header`, `Redact`)
  from `config.rs` (no `Warn` — metrics are always updated unconditionally).
- [x] Implement `execute()`:
  - Input: `ScanResult`, `ActionSet`, `ActionContext` (mode, route, direction)
  - Applies precedence: block → redact → header
  - Returns `ActionOutcome`:
    - `Block { status: u16, body: Bytes, headers: HeaderMap }` — configurable
      error response with PII kinds
    - `Forward { body: Option<Bytes>, extra_headers: HeaderMap, scan_result: ScanResult }`
    - `Pass` — no PII detected, forward unchanged
- [x] Metrics are always incremented when PII is detected (detections), regardless
  of action config. Block and redact metrics are incremented when those actions fire.
  All metrics include the `direction` label.
- [x] Unit tests for each action combination, precedence, and direction constraints

---

## Phase 4 — Admin Server

### 4.1 Admin endpoints
- [x] Implement `admin.rs` axum router:
  - `GET /metrics` — render Prometheus metrics
  - `GET /healthz` — return 200
  - `GET /readyz` — return 200 once all listeners are bound (accept an
    `Arc<AtomicBool>` or similar readiness signal)
- [x] Bind to configured `admin.listen` address
- [x] Integration test: health and readiness endpoints, metrics rendering

---

## Phase 5 — Reverse Proxy Mode

### 5.1 Request handling pipeline
- [x] Implement `reverse_proxy.rs` axum router:
  - Route matching by `path_prefix` (longest-prefix wins)
  - For each incoming request:
    1. **Request scanning** (if `request_actions` is non-empty):
       a. Check content-type against allowed list; check body size
       b. Buffer body up to `max_body_size`
       c. Collect scan targets (URL, query, headers, body) per route scan config
       d. Submit to `ScannerPool`
       e. Run `execute()` with request action set
       f. On `Block` → return configurable error response
       g. On `Forward` → continue with possibly mutated body/headers
    2. Proxy to upstream (preserving method, path suffix, headers minus hop-by-hop)
    3. **Response scanning** (if `response_actions` is non-empty):
       a. Buffer upstream response body
       b. Submit response body/headers to `ScannerPool`
       c. Run `execute()` with response action set
       d. On `Block` → return configurable error response (discard upstream response)
       e. On `Forward` → return possibly mutated response to client
    4. On `Pass` (either direction) → forward unchanged
- [x] Upstream connection pooling: one `hyper-util` pooling client per upstream URL,
  stored in a `HashMap<String, Client>` built at startup
- [x] Increment all relevant metrics with `direction` label

### 5.2 TLS termination (reverse proxy)
- [ ] In `tls.rs`: build `tokio_rustls::TlsAcceptor` from cert/key paths
- [ ] If `reverse_proxy.tls.enabled`, wrap the TCP listener with TLS acceptor

### 5.3 Integration tests
- [x] Plain HTTP proxying end-to-end (proxy → echo upstream)
- [x] Route matching: longest-prefix wins, unknown prefix returns 404
- [x] Request block action: request with PII returns configurable error response, not forwarded
- [x] Response block action: response with PII returns error response, upstream response discarded
- [x] Request redact action: PII replaced in forwarded request body/headers
- [x] Response redact action: PII replaced in response body before sending to client
- [x] Header action: `X-PII-Detected` header added to forwarded request (reverse proxy)
- [x] Empty action list disables scanning for that direction
- [x] Metrics always incremented when PII detected (no warn action needed)
- [x] `on_error` fail-open and fail-close paths
- [x] Oversized body handling
- [x] GA4 (Google Analytics 4) traffic shapes — full PiiKind sweep against
  `/mp/collect` JSON event params; field-shape coverage of integrator-error-prone
  fields (`dl`, `dt`, `dr`, `uid`, `ep.*`, `up.*`, `user_data`, `items`,
  `exception.description`, `link_url`, `form_destination`, batch endpoint,
  URL-path PII, GET-form leaks, password-reset URLs, referrer chains)

---

## Phase 6 — Load Testing

Setup and infrastructure per `docs/load-testing.md`.

### 6.1 Test infrastructure
- [x] Echo server binary (`benches/echo_server.rs`)
- [x] Payload generation script — clean and PII-containing payloads at 100 B,
  1 KB, 10 KB, 100 KB, 1 MB
- [x] Test TOML configs in `benches/configs/` (one per scenario variant)

### 6.2 k6 test scenarios
- [x] Baseline — proxy overhead vs direct-to-upstream, clean payloads
- [x] Action comparison — block vs redact vs header cost
- [x] Body size scaling — throughput degradation from 100 B to 1 MB
- [x] Concurrency scaling — saturation point and tail latency (1 to 500 connections)
- [x] Scanner thread scaling — effect of `scanner_threads` 1/2/4/8

### 6.3 Automation
- [x] `benches/run.sh` — builds, starts servers, runs all scenarios,
  collects JSON results, prints summary table

---

## Phase 7 — Structured Body Scanning

### 7.1 pii crate: structured scanning API
- [x] Define `ContextFragment` struct in `pii/src/lib.rs`:
  - `context: &str` — key path (e.g., `user.phone_number`, `phones[0]`)
  - `value: &str` — the text content to scan
  - `offset: usize` — byte offset of `value` in the original document
- [x] Add `mark_piis_structured(&self, fragments: &[ContextFragment]) -> Vec<PiiMatch>`
  to `Detector` trait with default no-op returning empty `Vec`
- [x] Add `mark_piis_structured(&self, fragments: &[ContextFragment]) -> Vec<PiiMatch>`
  to `Scanner` that delegates to all detectors via `flat_map`
- [x] Unit tests: `Scanner::mark_piis_structured` with empty fragments returns empty

### 7.2 pii crate: HyperscanDetector structured support
- [x] Override `mark_piis_structured` in `HyperscanDetector`:
  - For each fragment, call `mark_piis` on `fragment.value`
  - Offset-adjust each `PiiMatch` by adding `fragment.offset`
  - Collect and return all matches
- [x] Unit tests: email/SSN/IBAN detected in fragment values with correct
  document-absolute offsets

### 7.3 pii crate: KeywordContextDetector structured support
- [x] Override `mark_piis_structured` in `KeywordContextDetector`:
  - For each fragment, iterate over path prefixes from the full path down
    to a single segment, synthesizing `"{prefix}: {value}"` each time:
    - iter 1: `a.b.c: value` (exposes `c` next to `:`)
    - iter 2: `a.b: value` (exposes `b`)
    - iter 3: `a: value` (exposes `a`)
  - Run each synthesis through existing `mark_piis_on`
  - Offset-adjust results: subtract synthetic prefix length, add `fragment.offset`
  - Short-circuit: stop iterating once any match for the value's byte range
    is recorded (all iterations map to the same document-absolute span, so
    dedup is implicit)
  - If the synthesized prefix would exceed `MATCH_LOOKBACK` (512 bytes),
    fall back to per-segment synthesis (`"{segment}: {value}"` for each
    segment in isolation)
  - Strip array-index segments (`[0]`) from path before iterating
- [x] Unit tests:
  - `phone_number` context + phone value → detected with correct offset
    (resolves on iter 1)
  - `user.phone_number` nested context + phone value → detected on iter 1
    (`phone_number` adjacent to `:`)
  - `phone_number.primary` context (keyword at head) + phone value →
    detected on iter 2 after dropping `primary`
  - `email.work` context (keyword at head) + email value → verify path
    (pattern-only detector handles this; keyword-context iteration still
    runs but is a no-op for pattern-only kinds)
  - `user.phone_number.value` (keyword in middle) + phone value →
    detected on iter 2 (`user.phone_number: V`)
  - `unknown_field` context + phone value → not detected (no keyword match
    at any iteration)
  - Multiple fragments with different PII kinds → all detected
  - Offset correctness: returned `PiiMatch.start`/`end` are document-absolute
  - Lookback overflow: path with segments totalling > 512 bytes →
    per-segment fallback still detects leaf-segment keyword

### 7.4 Proxy: JSON body flattener
- [x] Add `serde_json` dependency to proxy `Cargo.toml`
- [x] Implement JSON flattener in proxy's `scanner.rs` (or a new `body_parser.rs`):
  - `fn flatten_json(raw: &[u8]) -> Result<Vec<OwnedContextFragment>, Error>`
  - Recursively walk JSON tree using `serde_json::Value` or streaming parser
  - Produce fragments for string values only (skip numbers, booleans, nulls)
  - Context: dot-separated key path with `[index]` for array elements
  - Offset: byte position of the value content (inside quotes) in the raw JSON
  - `OwnedContextFragment` struct: `context: String`, `value: String`, `offset: usize`
- [x] Unit tests:
  - Flat object: `{"phone": "555-1234"}` → one fragment, correct offset
  - Nested object: `{"a": {"b": "val"}}` → context `a.b`, correct offset
  - Array: `{"x": ["a", "b"]}` → `x[0]`, `x[1]` with correct offsets
  - Mixed types: numbers/bools/nulls skipped, strings extracted
  - Nested arrays: `{"a": [["x"]]}` → `a[0][0]`
  - Empty object/array → no fragments
  - Invalid JSON → error

### 7.5 Proxy: CSV/TSV body parser
- [x] Add `csv` crate dependency to proxy `Cargo.toml`
- [x] Implement CSV/TSV parser in proxy's `scanner.rs` (or `body_parser.rs`):
  - `fn flatten_csv(raw: &[u8], delimiter: u8) -> Result<Option<Vec<OwnedContextFragment>>, Error>`
  - Returns `None` when no header row is detected (fallback to flat text)
  - Header detection heuristic: first row is treated as headers if it contains
    at least one non-numeric field
  - Context: `column_name[row_index]` (0-based row index, excluding header)
  - Offset: byte position of cell content in the raw body
- [x] Unit tests:
  - Basic CSV: headers + data rows → fragments with correct contexts and offsets
  - TSV: tab delimiter works identically
  - No headers detected → returns `None`
  - Empty cells → fragments with empty value strings
  - Quoted CSV fields → correct value (unquoted) and offset (to content within quotes)
  - Single row (headers only, no data) → no fragments

### 7.6 Proxy: integrate structured scanning into pipeline
- [x] Define `BodyFormat` enum in proxy's `scanner.rs`:
  - `PlainText(Bytes)` — existing flat text path
  - `Structured { fragments: Vec<OwnedContextFragment>, raw: Bytes }`
- [x] Add content-type routing logic:
  - `application/json` → JSON flattener → `Structured` (also covers
    `text/json` and any RFC 6839 `application/*+json`)
  - `text/csv` → CSV parser (delimiter `,`) → `Structured` if headers detected,
    else `PlainText`
  - `text/tab-separated-values` → CSV parser (delimiter `\t`) → `Structured` if
    headers detected, else `PlainText`
  - All other content types → `PlainText` (unchanged)
  - On parse failure: follow `on_error` policy (fail_open → `PlainText` fallback,
    fail_close → block)
- [x] Update `ScanRequest` to accept `BodyFormat` instead of `Option<Bytes>`
- [x] Update `execute_scan` to handle `Structured` variant:
  - Convert `OwnedContextFragment` to `pii::ContextFragment` (borrow)
  - Call `scanner.mark_piis_structured(&fragments)`
  - Redaction: apply matches to `raw` bytes using document-absolute offsets
- [x] Update `scan_and_act` / `scan_and_act_response` to construct `BodyFormat`
  based on content-type before building `ScanRequest`
- [x] Integration tests:
  - Nested JSON body with PII in deep key → detected and redacted correctly
  - CSV body with PII in data cells → detected via column-name context
  - TSV body → same as CSV with tab delimiter
  - JSON parse failure with `fail_open` → falls back to plain text scanning
  - JSON parse failure with `fail_close` → blocks request
  - CSV without headers → falls back to flat text scanning
  - Redacted JSON output is valid JSON
  - Redacted CSV output preserves delimiter structure
  - JSON keyword at the **head** of a path (`phone_number.primary`) →
    detected on iteration 2 after dropping trailing segment
  - JSON keyword in the **middle** of a path (`user.phone_number.value`) →
    detected on iteration 2
  - JSON keyword at head inside an array (`phone_number[0].primary`) →
    array indices stripped, still resolves
- [x] **Side fixes discovered during integration**:
  - `KeywordContextDetector::mark_piis_structured` (pii crate): apply
    `decode_for_detection` to each fragment value with offset remapping —
    structured path now matches flat-path detection of URL-encoded /
    HTML-encoded / zero-width-obfuscated separators
  - `default_content_types()` (proxy `config.rs`): add `text/csv` and
    `text/tab-separated-values` so the default config matches DESIGN.md
    and exercises the new structured paths out of the box

---

## Phase 8 — HTTP API Mode

### 8.1 HTTP API endpoints
- [x] Rename `RestApiConfig` → `HttpApiConfig`, TOML section
  `[rest_api]` → `[http_api]`, and metrics `mode` label
  `rest_api` → `http_api`. Update validation messages and existing tests
  accordingly.
- [x] Implement `http_api.rs` axum router:
  - `POST /v1/scan` — read the raw request body, route by `Content-Type`
    using the same `BodyFormat` content-type routing introduced in Phase 7
    (text/plain → flat; application/json → JSON flatten; text/csv,
    text/tab-separated-values → CSV/TSV parse with header detection).
    Submit to `ScannerPool` and return JSON
    `{ "detected": bool, "matches_count": N, "kinds": [...] }`.
  - `POST /v1/redact` — same input handling as scan; return the body with
    PII redacted in place. The response `Content-Type` mirrors the request.
    Match metadata travels in headers: `X-PII-Detected: KIND1,KIND2`
    (omitted when none) and `X-PII-Redacted-Count: N`.
  - `GET /openapi.json` — *(stub returning 501; full impl in 8.2)*
- [x] Reject `Content-Type` outside `scan.content_types` with `415`.
- [x] Reject bodies above `max_body_size` with `413`.
- [x] Reject malformed structured bodies (invalid JSON, malformed CSV) with
  `400` regardless of `on_error` — the caller declared the content type, so
  silently falling back to flat-text would mask their bug.
- [x] On scanner failure, follow `on_error`: `fail_open` returns the body
  unredacted with `X-PII-Redacted-Count: 0`; `fail_close` returns `500`.
  Either way increment `pii_proxy_errors_total` with the outcome.
- [x] Increment `pii_proxy_requests_total` with `mode=http_api`.
- [x] Integration tests:
  - text/plain scan and redact
  - application/json scan and redact (nested keys + arrays); redacted output
    is valid JSON
  - text/csv scan and redact; redacted output preserves delimiter structure
  - text/tab-separated-values scan and redact
  - oversized body → 413
  - unsupported content type → 415
  - malformed JSON → 400
  - CSV without headers → flat-text fallback (matches proxy behaviour)
  - response `Content-Type` mirrors request
  - `X-PII-Detected` and `X-PII-Redacted-Count` headers populated correctly
  - no PII present → `X-PII-Detected` omitted, `X-PII-Redacted-Count: 0`

### 8.2 OpenAPI generation
- [x] Add `utoipa` (or equivalent) dependency to `Cargo.toml`.
- [x] Annotate the `api.rs` request/response types and route handlers so
  they appear in the generated spec. Document content-type routing,
  response headers (`X-PII-Detected`, `X-PII-Redacted-Count`), and error
  status codes.
- [x] Wire `GET /openapi.json` to return the generated spec served as
  `application/json`.
- [x] Integration test: `GET /openapi.json` returns a 200 with valid JSON
  containing both `/v1/scan` and `/v1/redact` paths and the documented
  response headers. Use a snapshot of a stable subset rather than the full
  spec to keep the test resistant to incidental ordering changes.

### 8.3 Docker Compose docs service
- [x] Extend `docker/docker-compose.yml` with an `api-docs` service running
  `swaggerapi/swagger-ui:latest`. Configure `SWAGGER_JSON_URL` to point at
  the proxy's `/openapi.json` over the compose network. Map the UI to a
  local port (`8088:8080` suggested). `depends_on: [proxy]`.
- [x] Update `docker/proxy.toml` (or add a sample alongside it) so
  `[http_api]` is enabled and the listener is reachable on the compose
  network.
- [x] Document the workflow in `docs/`: how to start the stack, where to
  reach the docs, and that this service is for development/operator use,
  not production.

### 8.4 Performance benchmark
- [x] Benchmarks are added to benches.

---

## Phase 9 — Forward Proxy Mode

### 9.1 Forward proxy handler
- [ ] Implement `forward_proxy.rs`:
  - Parse absolute-form URI from request line (standard forward proxy behavior)
  - Same pipeline as reverse proxy with request/response scanning:
    1. Request scanning (if `request_actions` non-empty): buffer → scan → action
    2. Forward to destination
    3. Response scanning (if `response_actions` non-empty): buffer → scan → action
  - Single global `hyper-util` pooling client for all destinations
- [ ] No CONNECT support — return 405 for CONNECT method

### 9.2 Forward proxy TLS (MITM)
- [ ] Client-facing: TLS termination using configured CA cert/key
- [ ] Dynamic per-host certificate generation via `rcgen`, signed by the CA
- [ ] Cache generated certs (bounded LRU cache keyed by hostname)
- [ ] Upstream-facing: TLS origination via `hyper-rustls` / `rustls` client config
- [ ] Integration tests: HTTP forwarding, action pipeline

---

## Phase 10 — Load Testing (Full Suite)

Extend load testing from Phase 6 to cover all modes.

### 10.1 Additional scenarios
- [ ] Mode comparison — reverse proxy vs forward proxy vs HTTP API
- [ ] Soak test — 30 min at 80% max rate, monitor memory, file descriptors, p99 drift

---

## Phase 11 — Main Entrypoint & Lifecycle

### 11.1 Startup orchestration
- [x] `main.rs`:
  1. Parse CLI args, load and validate config
  2. Initialize `tracing` subscriber
  3. Initialize Prometheus metrics registry
  4. Create `ScannerPool`
  5. Build `ActionSet` instances from config (per mode/direction)
  6. Spawn enabled listeners as tokio tasks:
     - Admin server (always on)
     - Reverse proxy (if enabled)
     - Forward proxy (if enabled)
     - HTTP API (if enabled)
  7. Set readiness flag once all listeners are bound
  8. Await shutdown signal

### 11.2 Graceful shutdown
- [x] `tokio::signal::ctrl_c()` + SIGTERM handler → trigger `CancellationToken`
- [x] Each listener: stop accepting new connections, drain in-flight with timeout
- [x] `ScannerPool::shutdown()` — drain channel, join threads
- [x] Exit with 0

---

## Phase 12 — End-to-End Testing

### 12.1 Cross-mode integration tests
- [ ] Full integration test: start binary with test config, send requests through
  each mode, verify scan/block/redact/header behavior end-to-end
- [ ] Test config validation rejects all invalid cases at startup

---

## Phase 13 — User-Defined PII Definitions

See DESIGN.md § "User-Defined PII Definitions".

### 13.1 Configuration
- [x] Add `pub custom: Vec<pii::UserPiiDefinition>` to `PiiConfig` with
  `#[serde(default)]` (reuses the `pii` crate's own `Deserialize` impl)
- [x] Implement `validate_custom_pii()` called from `AppConfig::validate()`:
  - Each `label` non-empty
  - `label` unique across `[[pii.custom]]` entries (case-sensitive)
  - `label` does not collide with any built-in `PiiKind::label()` — check the
    full namespace, independent of `detect`/`ignore`
  - Each `pattern` non-empty
  - Cap total entries at 64
  - Reject the literal `"CUSTOM"` in `detect`/`ignore` (extend
    `validate_pii_kinds_exclusivity` or add a sibling validator)
- [x] Unit tests for each validation case: empty label, duplicate labels,
  built-in collision (e.g., custom label `EMAIL`), empty pattern, cap exceeded,
  `"CUSTOM"` in `detect`, `"CUSTOM"` in `ignore`
- [x] TOML round-trip test: parse a config with `[[pii.custom]]` entries and
  verify the deserialized values

### 13.2 Scanner integration
- [x] In `build_scanner` (`scanner.rs`), chain
  `.user_piis(config.custom.iter().cloned())` onto the builder when the list
  is non-empty
- [x] Map `pii::PiiError::{RegexCompilation, HyperscanCompilation}` surfaced
  by `builder.build()` to the proxy's startup error path with sufficient
  context to identify the offending entry
- [x] Unit test: scanner builds with a valid user definition and detects a
  matching sample
- [x] Unit test: scanner build fails with a clear error for an invalid regex

### 13.3 Label propagation
- [x] Replace `m.kind.label()` with `m.label()` in `execute_scan` aggregation
  (`all_kinds` population) so user labels surface in `ScanResult.kinds`
- [x] Replace `m.kind.label()` with `m.label()` in `redact_in_place` so
  `type_label` redaction produces `[USER_LABEL]` rather than `[CUSTOM]`
  (replacement length still derived from label length)
- [x] Verify metrics helpers (`detections`, `redacted`) are driven by the
  per-match label string — confirm `pii_kind` counter label uses `m.label()`
- [x] Update affected unit tests in `scanner.rs` where the redaction output
  now reflects user labels

### 13.4 Integration tests
- [x] Reverse proxy: request with custom-defined value → `block` response
  `kinds` list contains the user label
- [x] Reverse proxy: `redact` with `type_label` → forwarded body contains
  `[USER_LABEL]`
- [x] Reverse proxy: `header` action → `X-PII-Detected` includes user label
- [ ] HTTP API `/v1/scan`: returns user label in `kinds` *(deferred — Phase 8
  HTTP API mode not yet implemented)*
- [ ] HTTP API `/v1/redact`: replaces matched value with `[USER_LABEL]`
  *(deferred — Phase 8 HTTP API mode not yet implemented)*
- [x] Country filter: user entry with a country outside the scanner's
  enabled set is silently dropped (entry present in config, no match fires)
- [x] Keyword-mode entry: value without the keyword is not matched; value
  with the keyword is matched and span covers only the value
- [x] Built-in + user detection coexist: a body containing both triggers
  both sets of labels in `kinds`

### 13.5 Documentation
- [x] Add a worked example config to `docs/` (or extend an existing example)
  demonstrating `[[pii.custom]]` alongside `detect`/`ignore`
- [x] Note the `CUSTOM` label reservation in the config reference

---

## Phase 14 — Config Validation CLI

See DESIGN.md § "Pre-flight Validation". Lets operators gate config changes in
CI/CD before they hit production; especially important now that user-supplied
regex patterns in `[[pii.custom]]` can fail compilation.

### 14.1 --validate option
- [x] Extend `Cli` in `config.rs`: add `validate: Option<PathBuf>`
- [x] Enforce mutual exclusion with `--config` via clap `ArgGroup`
  (`required = true`, `multiple = false`) so exactly one is provided;
  `--help` shows the constraint
- [x] In `main.rs`, branch before any async/server setup: if `validate` is
  set, run the validate-only code path and `std::process::exit(0 or 1)`
- [x] Validate-only code path:
  1. Load and parse TOML
  2. Run `AppConfig::validate()`
  3. Call `build_scanner(&config.pii)` (construct and discard the scanner —
     this exercises regex + vectorscan compilation)
  4. No listener bind, no `ScannerPool` spawn, no TLS, no upstream clients,
     no tracing subscriber noise beyond a single success/failure line
- [x] On success: exit 0 with a one-line "config OK" message
- [x] On failure: print a structured diagnostic to stderr and exit 1

### 14.2 Diagnostics
- [x] Error categories surfaced clearly: TOML parse, schema, semantic
  validation, scanner build. Initial approach: single non-zero exit code
  with a category tag in the message (simplest for CI integration)
- [x] For `[[pii.custom]]` regex failures, include the offending entry's
  `label` in the diagnostic so operators can locate it in the config
- [x] Unit tests covering each failure category end-to-end via the CLI
  (invoke the binary in an integration test or a library-style validation
  function)

### 14.3 Integration tests
- [x] Valid full config → exit 0
- [x] Missing config file → exit non-zero, filesystem error surfaced
- [x] Invalid TOML → exit non-zero with parse error
- [x] Invalid schema (e.g. unknown action) → exit non-zero
- [x] `detect` and `ignore` both set → exit non-zero
- [x] `[[pii.custom]]` entry with bad regex → exit non-zero, diagnostic cites
  the entry label
- [x] Custom label colliding with built-in (e.g. `EMAIL`) → exit non-zero
- [x] Exceeds custom entry cap → exit non-zero
- [x] `"CUSTOM"` in `detect`/`ignore` → exit non-zero
- [x] Verify no TCP port is bound during validation (assert via a process-level
  probe or by pre-binding the configured port and confirming validation still
  succeeds)
- [x] Verify `--validate` and `--config` cannot be combined; missing both
  prints a clap usage error

### 14.4 Documentation
- [x] Ensure DESIGN.md § "Pre-flight Validation" names the flag exactly
- [x] Add a `docs/` entry with sample CI usage (pre-commit-hook snippet)
  *(GitHub Actions example skipped per operator request)*
- [ ] Note the flag in README / quick-start once one exists
  *(deferred — no README yet)*

---

## Phase 15 — Plural Keyword Forms (pii crate)

Discovered while implementing Phase 7: `KeywordContextDetector` patterns list
singular keywords only (e.g. `phone_number`, `tax_file_number`). Plural forms
like `phone_numbers`, `tax_file_numbers`, `passports` are not detected because
the trailing `s` sits between the keyword and the separator class
(`[\s:.#/\-"=,\]\\]`), and `s` is not in that class. This affects both flat
scanning and structured scanning — the structured wrapper inherits the
limitation. Common in real JSON schemas (e.g. GA4 `phone_numbers`,
`passport_numbers` arrays). Applies to all language sets in the detector
(`Language::En`, `Fr`, `De`), not just English.

### 15.1 Pattern updates
- [x] Audit each value-bearing keyword in
  `pii/src/keyword_context_detector.rs` across **every** `Language::*` block
  and add optional plural suffix where natural. Suffix shape is
  language-specific:
  - **English**: typically `s?`, occasionally `(?:s|es)?`
    (e.g. `phone_number s?`, `passport (?:s|es)?`)
  - **French**: typically `s?` (e.g. `numéro_de_téléphone s?`,
    `passeport s?`); use `(?:s|x)?` only for the rare `-x` plurals
  - **German**: varies by word — `Nummer` → `Nummern` (`(?:n)?`),
    `Telefon` → `Telefone` (`e?`), compounds usually pluralize on the
    final element. Add suffixes per-keyword rather than blanket `s?`
- [x] Verify additions do not introduce false positives — suffix groups
  must admit only the legitimate plural ending, not arbitrary letters
  (so `phoned`, `phoning`, `Telefonate` still must not match)
- [x] Unit tests per language: plural form of each affected keyword
  detected with correct value span. Cover at least one keyword per
  language: e.g. `phone_numbers: 555-123-4567` (En),
  `numéros_de_téléphone: …` (Fr), `Telefonnummern: …` (De)
- [x] Regression: existing singular-form `#[test_case]` rows still pass
  in every language block
- [x] Structured-scan smoke test in `keyword_context_detector.rs`: a
  `phone_numbers[0]` context fragment + phone value resolves on iter 1
  (English path); analogous tests for at least one Fr and one De keyword

### 15.2 Author guidance
- [x] Extend `pii/CLAUDE.md` with a "Adding keyword-context patterns"
  section codifying the rules so future patterns don't repeat the bug:
  - Plural forms are **mandatory** for every value-bearing keyword,
    per language (En `s?` / `(?:s|es)?`, Fr `s?` / `(?:s|x)?`,
    German per-keyword as in 15.1)
  - Reminder that the keyword/value separator class is
    `[\s:.#/\-"=,\]\\]` and `*?` (lazy zero-or-more) — anything outside
    that class between keyword and value blocks the match (incl. letters
    like `s`, `_`)
  - Each new pattern must ship with `#[test_case]` rows for: singular,
    plural, camelCase, snake_case, kebab-case, and the JSON
    `"key":"value"` shape
  - Country/language tagging must match the kind's `applicable_countries()`
    so country filters work correctly

---

## Phase 16 — Specializations

See DESIGN.md § "Specializations". Specializations are per-endpoint adapters
that parse a known wire format (GA4, Matomo), scan a declared subset of
fields, and re-encode the result correctly. They fix two problems flat
scanning cannot: encoding round-trip correctness (e.g. `[EMAIL]` becoming
`%5BEMAIL%5D` inside form-encoded bodies, or being re-encoded twice in
Matomo's `url=` parameter) and false positives on opaque IDs.

### 16.1 Framework
- [x] New module `crates/proxy/src/specialization/mod.rs`:
  - `Specialization` trait with `name()` and async `process()` per
    DESIGN.md. `process()` takes both the **query string** and the
    **body** (each `Option`), plus body content-type and a `ScanHandle`
  - `ScanHandle` exposing a single async method that scans a field value
    and returns matched kinds + redacted replacement (when redaction is
    enabled for the direction). Internally backed by `ScannerPool`
  - `ProcessedRequest { query, body, scan_result }` where `query` and
    `body` are each `Option<ProcessedPart>` (re-encoded bytes +
    content-type); `None` means the specialization left that slot
    untouched (including the input-was-`None` case)
  - `SpecializationError` enum: `Decode { reason }`,
    `UnsupportedContentType`, `RecursionLimit` (for nested URL decoding)
- [x] Built-in registry: `fn lookup(name: &str) -> Option<&'static dyn Specialization>`
  returning singletons for `"ga4"` and `"matomo"`. Unknown names return
  `None` for callers to convert into a config or API-level error.
- [x] Rate-limited warn helper keyed by `specialization` name (one log
  line per name per minute, at most). Must never log payload contents.
- [x] Unit tests: registry lookup (hit + miss), `ProcessedRequest`
  shape, rate-limiter emits once then suppresses within window.

### 16.2 Pipeline integration
- [x] Plumb a per-route / per-API-request `Option<&dyn Specialization>`
  into the request-side scan path (`scan_and_act` in reverse proxy, the
  equivalent in http_api). The response-side path receives the same
  specialization but only the body slot is populated.
- [x] When a specialization is active:
  - The proxy's default scanning of the **query string** and the
    **request body** is bypassed for that request — the specialization
    is the sole entry point for those parts.
  - **URL path** and **request headers** continue on the default scan
    path with their existing `scan_config` controls. They are scanned
    *in addition to* the specialization's output (one combined
    `ScanResult` is assembled for downstream actions).
- [x] On `SpecializationError`:
  - fall back to default scanning of query+body (existing content-type
    routing) for that request,
  - emit rate-limited warning,
  - increment `pii_proxy_specialization_errors_total{specialization, reason}`.
- [x] `UnsupportedContentType` on the response direction is the
  expected common case (1x1 gif / 204) — silent fallback, **no** log
  line, **no** counter increment.
- [x] Do **not** consult `on_error` for specialization decode failures —
  fallback is always taken on the request side.
- [x] Unit tests:
  - success path: spec returns re-encoded query+body and aggregated
    kinds; default URL-path and header scanning still runs and its
    detections merge into the final `ScanResult`
  - decode failure falls back to default scan and increments the error
    counter
  - rate-limited log fires once across N successive failures within a
    window
  - response-side `UnsupportedContentType` produces no log, no counter
    increment

### 16.3 GA4 specialization

**Source of truth for the allowlist:** every field that
`crates/proxy/tests/ga4_integration.rs` demonstrates as a PII vector
must be allowlisted, so enabling the specialization does not regress
detection coverage. Use the table in DESIGN.md § "Specializations →
ga4" as the canonical list. Cross-reference each test case below to
confirm coverage before checking the box.

- [x] Implement `Ga4Specialization`
  (`crates/proxy/src/specialization/ga4.rs`).
- [x] **Query string and form-body transport** (`/g/collect`):
  - Parse as `application/x-www-form-urlencoded`.
  - Recursively decode `dl`, `dr` as URLs and scan each inner query
    parameter (per DESIGN.md). Path component of the inner URL also
    scanned for embedded PII.
  - Scan as flat string: `dt`, `uid`, `en`, every parameter with a
    prefix of `ep.` or `up.`, `cu`, `cm`, `cs`, `_uip`, `ip_override`.
  - Skip: `v`, `tid`, `cid`, `_s`, `_et`, `_p`, `_z`, `gtm`, `sid`,
    `seg`, `sct`.
  - Re-encode with redacted values percent-encoded for form-body
    context; doubly-encoded for the inner URL layer of `dl`/`dr`.
- [x] **JSON body transport** (`/mp/collect`, `/debug/mp/collect`,
  `/batch`):
  - Walk the JSON tree. For each string leaf under
    `client_id`, `user_id`, `user_data.**`, `user_properties.*.value`,
    `ip_override`, `user_location.**`, `events[].name`,
    `events[].params.**` (including arbitrary custom keys),
    `events[].params.items[].**`, call `ScanHandle`.
  - `events[].params.page_location` and `events[].params.link_url`
    receive recursive URL treatment in addition to flat scanning.
  - Skip non-string leaves, numeric and boolean fields, and
    `timestamp_micros`, `message_id`, `non_personalized_ads`,
    `consent.*`.
  - Re-emit JSON with substituted values; preserve key order where the
    JSON library allows. Redacted leaves stay inside the original
    quotes so output remains valid JSON.
- [x] Error categories: `invalid_json`,
  `invalid_form_encoding`, `unexpected_shape` (top-level not an
  object), `recursion_limit` (URL-in-URL nesting beyond a small bound
  — e.g. 3).
- [x] **Unit tests** — one per allowlisted field family, plus negatives:
  - `dl` with email in inner query → detected, output doubly-encoded
    redaction
  - `dr` with email + credit-card-shaped value in inner query
  - `dt`, `uid`, `en`, `ep.<custom>`, `up.<custom>` each with PII →
    detected
  - JSON `user_id`, `user_data.email_address`,
    `user_data.phone_number`, `user_data.address.*`,
    `user_properties.<name>.value`, `ip_override`,
    `user_location.city`, `events[].name`,
    `events[].params.page_title`, `events[].params.search_term`,
    `events[].params.transaction_id`, `events[].params.coupon`,
    `events[].params.affiliation`, `events[].params.link_url`,
    `events[].params.form_destination`, `events[].params.description`
    (multi-line stack trace), `events[].params.items[].item_name`,
    `events[].params.items[].item_id` → each detected
  - Multi-event payload: PII in one event, clean in another →
    selective detection
  - Numeric/bool/null leaves skipped without error
  - Opaque IDs (`cid`, `tid`, auto-generated dotted-decimal `cid`) do
    not trigger false positives
  - Malformed JSON → `Decode { reason: "invalid_json" }`
  - Top-level array → `Decode { reason: "unexpected_shape" }`
  - Recursion limit hit by an `dl` whose inner URL also contains a
    `dl=` → `RecursionLimit`
- [x] **Integration test parity** — port every numbered test in
  `crates/proxy/tests/ga4_integration.rs` (#1–#29 plus clean
  pass-through) to a new module that runs the same scenarios against a
  route configured with `specialization = "ga4"`. Each must:
  - still detect the same PII kinds,
  - produce a re-encoded body/query that is byte-identical to the
    original except inside redacted spans,
  - in form-encoded outputs, redaction labels must be properly
    percent-encoded (`%5BEMAIL%5D`, not `[EMAIL]`).
  - The block, header, and redact actions all retain their existing
    semantics (parity with the non-specialized tests).
  Ported to `crates/proxy/tests/ga4_spec_integration.rs`.
- [x] **False-positive regression** — add a test confirming the
  specialization does *not* scan `cid`, `tid`, `_s`, `_et`, even when
  their values happen to match a PII shape (e.g. construct a `cid`
  that looks like a credit card number). Without the spec, the proxy
  would flag this; with the spec, it must not.

### 16.4 Matomo specialization

**Source of truth for the allowlist:** every field that
`crates/proxy/tests/matomo_integration.rs` demonstrates as a PII vector
must be allowlisted. Use the table in DESIGN.md § "Specializations →
matomo" as the canonical list.

- [x] Implement `MatomoSpecialization`
  (`crates/proxy/src/specialization/matomo.rs`).
- [x] **Form/query transport** (the common case — GET query string or
  POST `application/x-www-form-urlencoded` body):
  - Parse fields. For each declared field, call `ScanHandle`.
  - Flat-string scan: `action_name`, `uid`, `cip`, every parameter
    matching `^dimension\d+$`, `e_c`, `e_a`, `e_n`, `e_v`, `search`,
    `search_cat`, `cra`, `cra_st`, `c_n`, `c_p`, `c_i`.
  - Recursive URL scan: `url`, `urlref`, `link`, `download`, `cra_ru`.
    Parse the value as a URL; scan each inner query parameter and the
    path component; re-encode at both layers.
  - JSON-value scan: `cvar`, `_cvar`, `ec_items`. Parse the value as
    JSON; scan each string leaf; re-emit JSON inside the form field.
  - Skip: `idsite`, `rec`, `apiv`, `_id`, `rand`, `revenue`, `idgoal`,
    `res`, `h`, `m`, `s`, `fla`, `qt`, `realp`, `wma`, `dir`, `java`,
    `cookie`, `pv_id`, `gt_ms`, plus any other parameter not in the
    allowlist.
  - Re-encode form/query bytes with each scanned field replaced; opaque
    fields pass through verbatim. Redaction labels properly
    percent-encoded.
- [x] **Bulk JSON transport** (`{"requests": ["?...", "?..."],
  "token_auth": "..."}`):
  - Parse top-level JSON.
  - For each entry in `requests`, strip the leading `?`, process the
    remainder as a flat-form Matomo payload (same allowlist as above),
    then reassemble.
  - `token_auth` passes through unchanged and is not scanned (operator
    credential, not subject PII).
  - Re-emit the bulk JSON envelope with each entry's redacted query
    string in place.
- [ ] **Legacy `/piwik.php`**: identical handling to `/matomo.php`. The
  specialization is selected by route config, so the alias is an
  operator config concern, not a spec concern. Document it in
  `docs/specializations.md` so operators remember to route both paths.
- [x] Error categories: `invalid_form_encoding`, `invalid_bulk_json`,
  `invalid_inner_url` (per offending field — not fatal; falls back to
  flat scan of that field's raw value), `invalid_inner_json` (same
  per-field fallback for `cvar` / `_cvar` / `ec_items`),
  `recursion_limit`.
- [x] **Unit tests** — one per allowlisted field family:
  - `url` with `email=` and `card=` in inner query → both detected,
    output doubly-encoded
  - `urlref` recursive scan
  - `link` and `download` recursive scan
  - `cra_ru` recursive scan
  - `cvar` and `_cvar` JSON values → string leaves scanned
  - `ec_items` JSON array → string elements scanned
  - `e_c`/`e_a`/`e_n`/`e_v` flat scan
  - `search` and `search_cat` flat scan
  - `cra` and `cra_st` (multi-line stack trace) flat scan
  - `c_n`, `c_p`, `c_i` flat scan (heatmap form input)
  - `dimension1` through `dimension999` (sample a few) flat scan
  - `action_name`, `uid`, `cip` flat scan
  - Bulk endpoint: two entries, one with PII in `url`, one clean →
    selective detection, bulk envelope preserved
  - Opaque fields (`idsite`, `_id`, `rand`, `revenue`, `res`, `h`, `m`,
    `s`) pass through unchanged
  - `cvar` with malformed inner JSON → that field falls back to flat
    scanning; other fields unaffected; counter increments under reason
    `invalid_inner_json`
  - `url` whose value is not parseable as a URL → falls back to flat
    scan of the raw value
  - Malformed top-level form encoding →
    `Decode { reason: "invalid_form_encoding" }`
  - Malformed bulk JSON → `Decode { reason: "invalid_bulk_json" }`
- [x] **Integration test parity** — port every numbered test in
  `crates/proxy/tests/matomo_integration.rs` (#1–#29 plus clean
  pass-through and `/piwik.php` alias) to a new module that runs the
  same scenarios against a route configured with
  `specialization = "matomo"`. Same parity rules as for GA4: same PII
  kinds detected, byte-equivalent output outside redacted spans,
  redaction labels percent-encoded.
  Ported to `crates/proxy/tests/matomo_spec_integration.rs`.
- [x] **False-positive regression** — confirm the specialization does
  not scan `_id`, `rand`, `idsite`, `revenue`, `res`, even when their
  values match a PII shape (e.g. construct an `_id` whose hex digits
  happen to form an IBAN-shaped string).
- [x] **Encoding bug regression** — the canonical test for the user's
  reported issue: the demo's Matomo payload (with `url=` containing a
  URL-encoded email and `dimension2` containing a URL-encoded phone
  number) must redact such that the output is valid form-encoded data,
  i.e. brackets in `[EMAIL]`, `[IP_ADDRESS]`, `[PHONE_NUMBER]` are
  percent-encoded as `%5B` / `%5D`. Round-tripping the response
  through a form-decoder must yield the redaction labels intact.

### 16.5 Config: reverse proxy
- [x] Add `specialization: Option<String>` to `Route` in `config.rs`.
- [x] Validation: if set, value must resolve via the registry; otherwise
  startup error names the route and the unknown name.
- [x] Unit tests: route with known specialization parses + validates,
  unknown name rejected, omitted field accepted.
- [x] Extend the sample `proxy.toml` in `crates/proxy/configs/` (and the
  docker config) with a commented-out specialization example.
  *(no `crates/proxy/configs/` directory exists; updated `docker/proxy.toml`
  which is the canonical sample.)*

### 16.6 HTTP API
- [x] Accept `?specialization=<name>` on `POST /v1/scan` and
  `POST /v1/redact`. Unknown name → `400` with a structured error body
  naming the unknown value.
- [x] When set, specialization owns parsing and content-type routing is
  bypassed (DESIGN.md § HTTP API). In API mode the specialization
  receives `query=None` (the API's own `?specialization=` is consumed
  by the handler, not handed to the spec); the payload comes entirely
  in the request body. Callers that want to test a `/g/collect`-style
  query-string payload pass it as an `application/x-www-form-urlencoded`
  body — the spec handles form-encoded bodies the same way.
- [x] `Content-Type` allowlist still enforced for the *outer* content
  type — calling `/v1/scan?specialization=ga4` with a non-JSON body
  yields a `415` (or the specialization's own `400` for decode failure,
  whichever fires first; pick the cheapest check).
- [x] `X-PII-Specialization: <name>` response header on both endpoints
  when a specialization processed the body (omitted otherwise) — lets
  callers verify which path ran.
- [x] Update the OpenAPI annotations: document the query parameter on
  both routes, list the accepted values, document the response header.
- [x] Integration tests:
  - GA4 JSON payload → kinds returned, body redacted on `/v1/redact`
  - Matomo form-encoded payload → kinds returned, redacted body is
    valid form-encoded data with correctly-encoded redaction labels
  - unknown specialization name → 400
  - specialization decode failure → falls back to raw scan, request
    succeeds, error counter incremented
  - response header `X-PII-Specialization` populated correctly (present
    when set, absent otherwise)

### 16.7 Reverse proxy
- [x] Wire specialization into the reverse proxy request path: when the
  matched route carries `specialization`, run the request body through it
  before action evaluation. Redacted body replaces the forwarded body.
- [x] Apply the same specialization (if any) to the response body when
  response actions are non-empty.
- [x] If the response `Content-Type` is not what the specialization
  expects, the specialization returns
  `SpecializationError::UnsupportedContentType` and the response falls
  through to raw scanning (which the content-type allowlist then skips).
  Both GA4 and Matomo respond to tracking calls with a 1x1 tracking
  pixel (`image/gif`) or `204 No Content`, so this is the **common case
  on the response path** — not an exception. It must be silent: no log
  noise, no `specialization_errors_total` increment. Only decode/shape
  failures on bodies the specialization claimed it could handle count
  toward the error counter.
- [x] Integration tests:
  - route with `specialization = "ga4"` against a payload containing
    PII in `user_id` → kinds detected, `[EMAIL]` redacted in forwarded
    body, metrics labelled `specialization="ga4"`
  - same with Matomo and a doubly-encoded `url=` → redacted forwarded
    body has correct encoding at both layers
  - response from upstream that does not match the specialization →
    falls back without error counter increment

### 16.8 Forward proxy — deferred
- [ ] Same wiring as 16.7 for forward proxy. Blocked until Phase 9 lands.
  Track as a follow-up; no work required in this phase beyond noting the
  dependency in `forward_proxy.rs` once that module exists.

### 16.9 Metrics
- [x] Add `specialization` label to `pii_proxy_detections_total` and
  `pii_proxy_redacted_total`. Default value `"none"` when no
  specialization is active.
- [x] New counter `pii_proxy_specialization_errors_total` with labels
  `specialization`, `reason`.
- [x] Update metric helper functions and call sites.
- [x] Unit tests for helper functions covering the new label.

### 16.10 Demo page
- [x] Add a "Specialization" `<select>` to `docker/demo/index.html`,
  placed alongside the existing endpoint and content-type selectors.
  Options: `(none)`, `ga4`, `matomo`.
- [x] When the user submits the form, append `?specialization=<value>`
  to the request URL when the value is not `(none)`. The `(none)` option
  sends no query parameter.
- [x] Update the `examples` object so that selecting "GA4 tracking" or
  "Matomo tracking" buttons sets the specialization dropdown to `ga4` or
  `matomo` respectively, in addition to setting endpoint/content-type/body.
  The JSON/CSV/TSV/text examples set specialization to `(none)`.
- [x] Display the `X-PII-Specialization` response header in the result
  panel so users can confirm which path ran.
- [ ] Smoke test: load the page in a browser, click each example, verify
  the dropdown updates and the request goes to the right URL. (Manual —
  no Playwright in this project today.)

### 16.11 Documentation
- [ ] New `docs/specializations.md`: what specializations are, when to
  use them, table of built-in specs with their declared field
  allowlists, how to select them per mode, and the failure-fallback
  semantics.
- [ ] Cross-link from DESIGN.md and from the HTTP API reference.
- [ ] Update `docs/demo1.md` (or the equivalent demo walkthrough) to
  mention the specialization selector and the auto-select behaviour.

---

## Phase 17 — Italian Support Review Follow-ups

Code-review findings on the (uncommitted) Italian language + Italy PII change.
The performance regression that blocked the commit is already resolved
(codice-fiscale uppercase-only hyperscan pattern + keyword fallback; the
residual ~5-6% phone-pattern DFA-cliff cost was accepted). The items below are
correctness and cleanup findings from reviewing the rest of the diff. Line
numbers are approximate and will drift.

### 17.1 Correctness
- [ ] **English keywords for `ItPartitaIva` and `ItPostalCode` are tagged
  `Language::It`** (`keyword_context_detector.rs` ~986, ~992), unlike
  `ItPhoneNumber`/`ItPassportNumber`/`ItDriversLicense` which use a separate
  `Language::En` tuple. The pattern filter gates on
  `enabled_languages.contains(lang)`, so under a config with Country::It enabled
  but languages = [En] only, `VAT number: IT12345678903` and
  `italian postal code: 00184` are not detected at all (the whole tuple is
  gated behind Italian). Split the English keywords into their own
  `Language::En` tuples, consistent with the sibling Italian kinds. Add a
  `Country::It` + `Language::En`-only test so the gap can't regress.
- [ ] **`ItPartitaIva` keyword alternation includes the bare, non-country-scoped
  `vat[\s_-]?numbers?`** (`keyword_context_detector.rs` ~986), binding any
  generic "VAT number" label to the Italian kind + Italian Luhn. A non-Italian
  11-digit EU VAT that happens to pass the Italian Luhn (e.g. a French-style
  11-digit VAT with no `IT` prefix) is mislabelled `IT_PARTITA_IVA`. Country-
  prefix the English alternations (`italian vat`, `it vat`) and drop the bare
  `vat number(s)` token, per the skill convention.

### 17.2 Cleanup (reuse / simplification / efficiency)
- [ ] **`it_postal_check` duplicates `fr/de/at/ch_postal_check`**
  (`validators.rs` ~1639) as a 5th near-verbatim copy of the
  trim → length → all-digit → parse → inclusive-range shape, and diverges: it
  only `trim()`s instead of filtering internal whitespace like the others, and
  uses `parse().unwrap_or(0)`. Factor a shared `postal_range_check(s, len, lo,
  hi)` helper and route the five callers through it.
- [ ] **Italian phone keyword alternation duplicated verbatim** between the
  `ItPhoneNumber`/`Language::It` tuple (~998) and the
  `UsPhoneNumber`/`Language::It` tuple (~1043), differing only in the trailing
  value regex. Editing one and not the other silently diverges which Italian
  keywords trigger Italian vs US numbers. Share the keyword fragment.
- [ ] **11th verbatim copy of the ~50-branch English phone keyword alternation**
  (`keyword_context_detector.rs` ~1008, also at ~120/259/265/271/277/283/600/
  647/689/894). Any change to the shared English phone vocabulary must be
  hand-applied to 11 ~600-char string literals with no compiler help. (Also the
  known DFA-cliff source; the perf cost was accepted, but the maintenance cost
  stands.) Factor the shared alternation into a `const` fragment concatenated
  into each country pattern. See `keyword-detector-vectorscan-cliff` memory.
- [ ] **`it_codice_fiscale_check` allocates a `String` via
  `s.trim().to_ascii_uppercase()` on every call** (`validators.rs` ~1546), while
  the sibling Italian validators operate on `&[u8]` with no allocation. Fold
  case per-byte inline (the odd/even tables already key on uppercase) so the
  validator runs on the stack on the hot scanner thread.
- [ ] **`it_partita_iva_check` `b.len() == 13` IT-prefix guard is redundant and
  fragile** (`validators.rs` ~1612): it's subsumed by the later `core.len() !=
  11` check and couples prefix-stripping to an exact total length, so e.g.
  `IT 00488410010` (space after `IT`) skips the strip and returns false. Use a
  length-independent case-insensitive two-byte `strip_prefix`.

---

## Phase 18 — AI4Privacy Effectiveness Eval

See DESIGN.md § "AI4Privacy Effectiveness Evaluation". A benchmarking harness
that scores Voidwall's detection against the `ai4privacy/pii-masking-300k`
dataset and reports span-level precision/recall/F1 per entity type + overall,
comparable to other PII solutions' published numbers. It drives `POST /v1/redact`
and recovers predicted spans by diffing the `type_label`-redacted body against
the original. Reporting tool, not a `cargo test` target.

### 18.1 Cargo wiring
- [x] Add `reqwest` as an optional dependency and an `eval = ["dep:reqwest"]`
  feature (off by default) so neither default builds nor the deployed proxy
  image gain a client stack.
- [x] Declare the explicit `[[bin]]` `ai4privacy-eval`
  (`path = "benches/ai4privacy_eval.rs"`, `required-features = ["eval"]`),
  mirroring the `echo-server` convention to avoid `src/bin` auto-discovery.

### 18.2 Eval binary (`benches/ai4privacy_eval.rs`)
- [x] Args/env: `DATASET` (JSONL file or directory; optional — defaults to the
  ctl auto-fetch cache, see 18.3), `API_URL` (default `http://localhost:8083`),
  `MAX_ROWS`, `LANG`, `CONCURRENCY` (default 32), `ENFORCE`. When `DATASET`
  points at a directory, stream every `*.jsonl` in it. Clear error when the
  resolved path is missing/empty.
- [x] Lenient serde row model: `source_text` (alias `unmasked_text`),
  `privacy_mask: Vec<{label, start, end, value}>`, `language`. Extra fields
  ignored. Handle the older stringified-`privacy_mask` form via a deserialize
  shim.
- [x] Stream JSONL line-by-line (`BufReader::lines`), never fully buffered;
  apply `LANG` / `MAX_ROWS` filters.
- [x] Bounded-concurrency driver over `tokio` semaphore + `JoinSet` (no `futures`
  dep): POST each `source_text` to `{API_URL}/v1/redact` as `text/plain`.
- [x] `recover_spans(original, redacted) -> Vec<(start, end, kind)>`: split the
  redacted body on the `\[[A-Z][A-Z0-9_]*\]` token regex, anchor literal
  segments left-to-right in the original (char offsets), emit a predicted span
  per token. Document the adjacent-token / literal-`[LABEL]` heuristic limits.
- [x] Ground-truth span resolution: use `start`/`end`, validating against
  `value`; fall back to substring search when offsets don't line up
  (byte/char coordinate mismatch guard).
- [x] Category mapping table (exact / keyword-gated / known-gaps) + per-category
  expected-kind families; bucket unknown dataset labels as `unclassified` and
  surface them.
- [x] Scoring: span-overlap TP/FP/FN for **detection** and **typed** variants;
  aggregate per entity type + micro/macro overall; per-predicted-kind FP
  breakdown. Treat per-row HTTP errors as all-FN and count them.
- [x] Precision band: compute both `raw_precision` (every FP counted) and
  `adjusted_precision` (FPs that pass a strict structural validator
  re-classified as *unscored*, neither TP nor FP). Carve-out applies **only**
  to strong-validator formats (`EMAIL`, `IBAN` mod-97, `CREDIT_CARD` Luhn,
  `IP_ADDRESS`, `MAC_ADDRESS`, `BITCOIN_ADDRESS`, `ETHEREUM_ADDRESS`, `VIN`,
  `IMEI`); for all other kinds `adjusted_precision` collapses to
  `raw_precision`. Surface re-classified spans in a separate
  `confirmed_unannotated` bucket so the carve-out is transparent.
- [x] Report: stdout table (category · GT n · detection R · typed R) + overall
  detection & typed P/R/F1 (all-categories and supported-only) reporting both
  `raw_precision` and `adjusted_precision` + `confirmed_unannotated` bucket +
  uncovered-gap list. `ENFORCE=1` asserts committed per-category floors and
  exits non-zero on breach.
- [x] Unit tests: `recover_spans` (single/multiple/leading/trailing/unicode
  spans, adjacent tokens), span overlap, category lookup, GT-offset fallback,
  precision-band carve-out (validator-confirmed FP becomes unscored for a
  strong-validator kind; stays counted for a keyword-gated/fuzzy kind).

### 18.3 `docker/ctl eval` subcommand
- [x] Add `cmd_eval` mirroring `cmd_soak`: runs
  `cargo run --release --features eval --bin ai4privacy-eval`, wiring the env
  knobs and defaulting `API_URL` to the compose HTTP API (`:8083`). Add to the
  dispatch `case` and `usage`.
- [x] Auto-fetch the dataset when `DATASET` is unset and the cache is empty:
  `curl` the public, ungated JSONL train file(s) from the HF resolve URL
  (`https://huggingface.co/datasets/ai4privacy/pii-masking-300k/resolve/main/data/train/<lang>_openpii_*.jsonl`)
  into `.cache/ai4privacy/`. LANG-aware: fetch only the `LANG` file when `LANG`
  is set, otherwise all six train languages. No parquet conversion, no Python /
  `huggingface_hub` dependency. Skip the download when the cache already holds
  the needed file(s); honor an explicit `DATASET` override verbatim. Point the
  binary at the cache dir (or file) once present.
- [x] Gitignore the `.cache/` directory (and its contents) so auto-fetched
  dataset files are never committed.

### 18.4 Documentation
- [ ] `docs/ai4privacy-eval.md`: dataset acquisition (auto-fetched on first run;
  note the files are already JSONL on HF and `DATASET` can override with a local
  copy — no parquet/Python step), expected row schema, how to run via
  `docker/ctl eval`, metric definitions (including the `raw_precision` /
  `adjusted_precision` band and the `confirmed_unannotated` bucket), the category
  mapping table, and the precision/span-recovery caveats.

---

## Phase 19 — Disable Checksum Validation (eval-only)

See DESIGN.md § "AI4Privacy Effectiveness Evaluation → Disabling checksum
validation (eval-only)". A single global `pii.validate` boolean (default `true`)
that bypasses every per-detector checksum/format validator scanner-wide. Its
only purpose is measuring **structural recall** against AI4Privacy's fabricated
ground truth (checksum-invalid cards, synthetic IDs), where real validators
correctly reject values and depress recall for reasons unrelated to pattern
coverage. It is a measurement mode, not a precision mode: with validation off,
false positives rise and overlap resolution can let a wrong-kind match steal a
span — so recall is an optimistic ceiling and precision is not meaningful. The
flag defaults on and is never set in any shipped/default config.

### 19.1 pii crate: builder + detector gating
- [ ] Add `validate: bool` field to `ScannerBuilder` (default `true` in
  `Scanner::builder()`) and a `pub fn validate(mut self, on: bool) -> Self`
  setter with a doc comment marking it eval-only.
- [ ] Thread the flag into both detector constructors in `ScannerBuilder::build()`:
  `HyperscanDetector::new(&enabled_kinds, self.validate)` and
  `KeywordContextDetector::new(&enabled_kinds, &languages, self.validate)`.
  `UserDetector` has no built-in validators — leave its signature unchanged.
- [ ] `HyperscanDetector`: store `validate: bool`; gate all four validator call
  sites (`hyperscan_detector.rs` ~414, ~429, ~477, ~492) as
  `if !self.validate || (entry.validator)(candidate)`. Leave the `validator`
  function pointers intact — only short-circuit their invocation.
- [ ] `KeywordContextDetector`: store `validate: bool`; gate both validator call
  sites (`keyword_context_detector.rs` ~1618, ~1660) as
  `if !self.validate || (pattern.validate)(value_match.as_str())`.
- [ ] Update existing in-crate `::new` callers (tests, benches) to pass
  `true` → verify: `cargo check -p pii --all-targets` is clean.
- [ ] Unit test: a checksum-invalid value (e.g. Luhn-failing credit card) is
  **missed** with `validate(true)` and **detected** with `validate(false)`,
  via the public `ScannerBuilder`. Cover one hyperscan-detector kind
  (CreditCard/Luhn) and one keyword-context kind. → verify: `cargo test -p pii`.

### 19.2 proxy: config field + scanner wiring
- [ ] Add `pub validate: bool` to `PiiConfig` (`config.rs`) with an explicit
  `#[serde(default = "default_validate")]` and `fn default_validate() -> bool
  { true }`. A bare `#[serde(default)]` would default to `false` — must not be
  used here.
- [ ] In `build_scanner` (`scanner.rs`), chain `builder = builder.validate(config.validate)`.
- [ ] At startup, when `!config.validate`, emit one `warn!` line ("PII checksum
  validation disabled — eval mode, expect false positives"). Place it where
  the scanner is built so `--validate` config-check runs surface it too.
- [ ] Unit tests: `validate` defaults to `true` when the `[pii]` key is omitted;
  round-trips `false` when set. → verify: `cargo test -p pii-proxy config`.

### 19.3 Eval usage
- [ ] No change to the eval harness or `docker/ctl eval` — confirm the workflow
  is: set `pii.validate = false` in `docker/proxy.toml`, restart the proxy, run
  `docker/ctl eval` as usual. Add a one-line note in `docs/ai4privacy-eval.md`
  (folded into task 18.4) pointing to the flag for structural-recall runs.

---

## Phase 20 — Dictionary-Based Name Detection (`DictionaryDetector`)

See DESIGN.md § "Dictionary-Based Detection (`DictionaryDetector`)" and
`docs/ner-vs-regex-latency-research.md`. A new `pii`-crate detector that catches
dictionary-shaped PII via FST membership lookup over a gazetteer. **Scope: English
only, `PersonName` (given + surname), standalone candidate detector** (no NER
second tier). It is built and the FST loaded **only when `PersonName` is enabled**.
Recall and false-positive rate are to be observed before any further tier is added.
Follows the "Adding a New Detector" checklist in `crates/pii/CLAUDE.md`.

### 20.1 Data sourcing & offline FST build tool
- [x] Add a standalone build tool in the `pii` crate (e.g.
  `tools/build_names_fst.rs` as a non-default `[[bin]]`, or an `xtask`) that
  reads the source name lists and emits a single `fst::Map` artifact
  (`names_en.fst`). It is a **build-time** tool, not shipped in the proxy image.
- [x] Source English data from license-clean sources: US SSA given names
  (public domain), US Census 2010 surnames (public domain), optionally Wikidata
  given/family names (CC0) for breadth. Do **not** use scraped/leaked dumps.
  Record provenance + license in a `NOTICE`/README next to the tool.
  (Provenance/licenses recorded in `data/names/README.md`; using SSA + Census 2010
  + `google-10000-english` (MIT) for the common-word flag. Wikidata not used in v1.)
- [x] Normalize on build: lowercase (Unicode-correct) + a fixed Unicode form
  (NFC); dedup; **sort** keys lexicographically (required by `fst`). Apply the
  **identical** normalization that the detector will use at query time.
- [x] Compute the `u64` value bitmask per form: `IS_GIVEN`, `IS_SURNAME`
  (a form can be both → OR the bits), and `ALSO_COMMON_WORD` — the latter
  auto-derived by intersecting the name set with an English word-frequency list
  (e.g. `wordfreq` / SCOWL / `google-10000-english`) above a chosen threshold.
- [x] Frequency-cut the surname long tail to a documented coverage band (keep the
  artifact to a few MB). Print final entry count + artifact size.
  (`SURNAME_MIN_COUNT` env, default 100 = full Census file; `GIVEN_MIN_COUNT` default 0.)
- [ ] Commit the generated `names_en.fst` artifact (a few MB) to the repo (or
  document a fetch step); record the build inputs/threshold so it is reproducible.
  (BLOCKED on manual data download — run the tool, then commit the artifact.)
- [x] Verify: rebuild is deterministic (same inputs → byte-identical artifact).
  (Verified with synthetic inputs: two runs produce byte-identical SHA-256.)

### 20.2 pii crate: kind, flags, dependencies
- [x] Confirm or add `PiiKind::PersonName` in `lib.rs` (the proxy config already
  references `"PersonName"`); ensure `label()` returns `PERSON_NAME` and it is
  reachable for `Country::International` so it is not country-gated.
  (Already present: variant, `label()` → `PERSON_NAME`, `Country::International`, `ALL_KINDS`.)
- [x] Add dependencies to `crates/pii/Cargo.toml`: `fst` and
  `unicode-segmentation`. (Exact-membership + prefix walk only — the `levenshtein`
  feature is **not** needed for v1.)
- [x] Define the flag bitmask constants in one place (e.g.
  `dictionary_detector.rs`): `IS_GIVEN`, `IS_SURNAME`, `ALSO_COMMON_WORD`. These
  must match the build tool (20.1) exactly — add a comment cross-linking the two.
  (Canonical in `dictionary_detector::flags`; the build tool imports them — single
  source, no duplicated constants to keep in sync.)

### 20.3 pii crate: FST loading
- [ ] Load the artifact into a `fst::Map` and wrap it for read-only sharing. Use
  `include_bytes!` to embed the committed artifact (gives a `&'static [u8]`, so a
  single copy is shared across all threads with no per-thread cost and no runtime
  file path), or mmap a path if embedding proves too large — pick one, document why.
- [ ] Map load/parse failure to a clear `PiiError` surfaced at scanner build time
  (so `--validate` catches a corrupt artifact), not a runtime panic.
- [ ] Unit test: the artifact loads, `len() > 0`, and a known name (`"smith"`)
  resolves with the expected flags. → verify: `cargo test -p pii dictionary`.

### 20.4 pii crate: tokenization & windowing
- [ ] Implement tokenization via `unicode_word_indices`, producing tokens with
  `(start, end)` **byte offsets** into the input (skips whitespace/punctuation,
  valid UTF-8 boundaries).
- [ ] Implement 1–3 adjacent-token windowing producing, per window: a **canonical
  lookup key** (tokens lowercased + NFC, single-space joined) and the **original
  byte span** `(first.start, last.end)`.
- [ ] Unit tests: token offsets correct for ASCII + accented input; multi-space /
  newline between tokens still yields a single-space canonical key;
  hyphenated token (`Jean-Pierre`) splits (documented behaviour).

### 20.5 pii crate: `DictionaryDetector` core (lookup + gating)
- [ ] Implement `DictionaryDetector` (`crates/pii/src/dictionary_detector.rs`)
  implementing the `Detector` trait (`Send + Sync`).
- [ ] `mark_piis`: tokenize → window → FST lookup → emit a `PersonName`
  `PiiMatch` over the original byte span on a (gated) hit.
- [ ] Precision gating: a hit with `ALSO_COMMON_WORD` set is **suppressed unless
  promoted** by cheap evidence — capitalisation mid-sentence, an adjacent
  given+surname pair, or a nearby title/honorific keyword (`Mr.`, `Dr.`). Forms
  **without** `ALSO_COMMON_WORD` fire on a bare hit.
- [ ] Prefer the **longest** overlapping window at the same start (or emit all and
  rely on `resolve_overlaps`); ensure spans are document-absolute byte offsets.
- [ ] `has_piis`: return `true` on the first gated hit (short-circuit).
- [ ] Optimisations (keep simple; add only if benches justify): start windows only
  at a capitalised, non-numeric token; FST prefix-pruning via the `raw::Fst`
  node/transition walk to stop extending a window on a dead prefix.
- [ ] Unit tests via `#[test_case]`:
  - bare-hit name with no `ALSO_COMMON_WORD` (`"Kowalski"`/`"Smith"`) → detected,
    span correct
  - multi-token name (`"John Smith"`) → single longest-window match
  - `ALSO_COMMON_WORD` form lowercase mid-prose (`"i will go"`) → **not** detected
  - same form promoted by evidence (`"Mr. Will"` / `"Will Smith"`) → detected
  - no-hit token (`"asdfghjkl"`) → not detected
  - offsets are document-absolute within surrounding text

### 20.6 pii crate: structured scanning support
- [ ] Override `mark_piis_structured` in `DictionaryDetector` to scan each
  fragment's **value** text directly (names need no key-path context) and
  offset-adjust matches by `fragment.offset`.
- [ ] Unit test: `{"name": "John Smith"}`-style fragment value → detected with
  document-absolute offsets.

### 20.7 pii crate: registration & activation
- [ ] Register `DictionaryDetector` in `Scanner::new()` / `ScannerBuilder::build()`
  **after `KeywordContextDetector` (last in the chain)** — rationale: `mark_piis`
  order is output-neutral (`resolve_overlaps` arbitrates), and last placement lets
  the cheap vectorscan detectors short-circuit `has_piis` first.
- [ ] **Activation gate:** construct the detector and load the FST **only when
  `PersonName` is in the enabled kind set** (present in `detect`, or not in
  `ignore`). When `PersonName` is disabled, the detector is not built and the FST
  is never loaded.
- [ ] Unit tests: with `PersonName` enabled, the scanner has the detector and
  detects a sample name; with `PersonName` excluded (via `ignore` / absent from
  `detect`), no `PersonName` match fires and the artifact is not loaded. → verify:
  `cargo test -p pii`.

### 20.8 Overlap resolution
- [ ] Confirm no `overlap.rs` priority-group entry is needed initially —
  `PersonName` rarely produces an equal-span match with a structured kind; the
  generic containment/longest rules cover the rare overlap (a name token inside an
  address). Add a test asserting a name contained in a wider address span is
  dropped by the generic rule; only add a priority entry if an equal-span clash is
  observed.

### 20.9 Benchmarks
- [ ] Add a `PERSON_NAME_TEXT` corpus constant (realistic prose with embedded
  names) in `benches/pii_benchmark.rs`.
- [ ] Add a `per_detector` benchmark entry for `DictionaryDetector`.
- [ ] Add names into `MIXED_PII_TEXT` so throughput / comparison benches cover the
  new kind. → verify: `cargo bench -p pii throughput_mark_piis` shows the names
  path stays microsecond-class (O(text length), per the research doc).

### 20.10 Proxy integration (verification only — no new config)
- [ ] Verify `PersonName` flows end-to-end through the existing pipeline with **no
  new config keys**: enabling via `[pii].detect` / `ignore`,
  `pii_proxy_detections_total{pii_kind="PERSON_NAME"}`, `X-PII-Detected`, and
  `[PERSON_NAME]` `type_label` redaction.
- [ ] Integration test (`crates/proxy/tests/`): a request/body containing a name
  → `PersonName` detected, redacted as `[PERSON_NAME]`, metric labelled
  `pii_kind="PERSON_NAME"`; with `PersonName` disabled in config, no detection.

### 20.11 AI4Privacy eval
- [ ] Run `docker/ctl eval` for the name categories
  (`GIVENNAME*`/`LASTNAME*` → `PERSON_NAME`) before/after the detector to record
  the recall lift and the false-positive impact (the metric the standalone phase
  exists to measure). Capture the numbers in the eval notes.

### 20.12 Documentation
- [ ] Document the offline FST build (inputs, licenses, normalization, frequency
  threshold, rebuild command) next to the build tool.
- [ ] Update `crates/pii/CLAUDE.md`: note `DictionaryDetector` as a third detector
  type (dictionary/FST membership), its English-only/`PersonName` scope, the
  activation gate, and the build-tool location.
