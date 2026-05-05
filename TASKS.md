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
  - REST API: no `block`/`header` actions
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

## Phase 8 — REST API Mode

### 8.1 REST API endpoints
- [ ] Implement `api.rs` axum router:
  - `POST /v1/scan` — accept JSON `{ "text": "..." }`, scan via `ScannerPool`,
    return `{ "detected": bool, "matches_count": N, "kinds": [...] }`
  - `POST /v1/redact` — accept JSON `{ "text": "..." }`, scan+redact via
    `ScannerPool`, return `{ "text": "...", "redacted_count": N, "kinds": [...] }`
  - `GET /v1/health` — 200
- [ ] Respect `max_body_size` / `on_error` for incoming requests
- [ ] Increment `pii_proxy_requests_total` with `mode=rest_api`
- [ ] Integration tests: scan detection, redaction, oversized body, health

### 8.2 Performance benchmark
- [ ] Benchmarks are added to benches

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
- [ ] Mode comparison — reverse proxy vs forward proxy vs REST API
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
     - REST API (if enabled)
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
- [ ] REST API `/v1/scan`: returns user label in `kinds` *(deferred — Phase 8
  REST API mode not yet implemented)*
- [ ] REST API `/v1/redact`: replaces matched value with `[USER_LABEL]`
  *(deferred — Phase 8 REST API mode not yet implemented)*
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
- [ ] Audit each value-bearing keyword in
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
- [ ] Verify additions do not introduce false positives — suffix groups
  must admit only the legitimate plural ending, not arbitrary letters
  (so `phoned`, `phoning`, `Telefonate` still must not match)
- [ ] Unit tests per language: plural form of each affected keyword
  detected with correct value span. Cover at least one keyword per
  language: e.g. `phone_numbers: 555-123-4567` (En),
  `numéros_de_téléphone: …` (Fr), `Telefonnummern: …` (De)
- [ ] Regression: existing singular-form `#[test_case]` rows still pass
  in every language block
- [ ] Structured-scan smoke test in `keyword_context_detector.rs`: a
  `phone_numbers[0]` context fragment + phone value resolves on iter 1
  (English path); analogous tests for at least one Fr and one De keyword

### 15.2 Author guidance
- [ ] Extend `pii/CLAUDE.md` with a "Adding keyword-context patterns"
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
