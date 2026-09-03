# Load Testing Design

## Goal

Measure the proxy's overhead on the HTTP hot path: added latency and maximum
throughput across modes, body sizes, actions, and concurrency levels. Results
should be reproducible and comparable across commits.

---

## Infrastructure

### Upstream Echo Server

A minimal axum server included in the repo (`benches/echo_server.rs` or a
dedicated `tests/echo-server` binary). It should:

- Accept any method on any path
- Return the request body as-is with 200
- Add no artificial latency
- Be single-purpose — no PII scanning, no logging under load

This keeps the upstream out of the measurement. A real backend would add its
own latency, masking proxy overhead.

### Load Generator

**k6** — scriptable, supports constant-rate and ramping scenarios, outputs
percentile summaries and CSV/JSON for post-processing.

Alternative: **wrk2** for simpler constant-rate tests with accurate latency
histograms. Both can be used; k6 is primary for scripted scenarios, wrk2 for
quick spot-checks.

### Test Payloads

Pre-generated JSON files in `benches/payloads/`:

| File | Size | Content |
|------|------|---------|
| `clean_small.json` | ~100 B | No PII |
| `clean_medium.json` | ~10 KB | No PII |
| `clean_large.json` | ~1 MB | No PII |
| `pii_small.json` | ~100 B | 1-2 PII instances (email, SSN) |
| `pii_medium.json` | ~10 KB | ~10 PII instances mixed across text |
| `pii_large.json` | ~1 MB | ~100 PII instances |
| `pii_nested.json` | ~800 B | 4-5 levels deep; KeywordContext keywords mid-path (`request.user.phone.primary`, `accounts[i].holder.name.first`) |
| `pii_table.csv` | ~9 KB | Header + 100 rows; columns include `first_name`, `last_name`, `phone`, `dob`, `email`, `ssn` |

Clean payloads isolate parsing/proxying overhead from scanner work. PII
payloads measure the full pipeline including detection and action execution.

A script (`benches/generate_payloads.py` or similar) generates these
deterministically so results are reproducible.

---

## Test Scenarios

Each scenario is a k6 script in `benches/k6/`. All scenarios collect: request
rate (req/s), latency percentiles (p50, p95, p99, max), error rate.

### 1. Baseline — Proxy Overhead

**What it measures**: raw cost of proxying without PII scanning.

Setup: reverse proxy mode, single route, actions = `["warn"]`, clean payloads
(no PII detected, scanner runs but finds nothing).

| Variable | Values |
|----------|--------|
| Body size | 100 B, 10 KB, 1 MB |
| Concurrency | 10, 50, 200 |

Compare against direct-to-echo-server (no proxy) to isolate added latency.

### 2. Action Comparison

**What it measures**: cost difference between action types.

Setup: reverse proxy mode, single route, PII payloads (~10 KB).

| Variable | Values |
|----------|--------|
| Actions | `["warn"]`, `["block"]`, `["warn", "redact"]`, `["warn", "header", "redact"]` |
| Concurrency | 50 |

`block` should be fastest (short-circuits after detection, no forwarding).
`redact` adds mutation cost. `warn`-only is the baseline.

### 3. Body Size Scaling

**What it measures**: how throughput degrades with body size.

Setup: reverse proxy mode, `["warn", "redact"]`, PII payloads.

| Variable | Values |
|----------|--------|
| Body size | 100 B, 1 KB, 10 KB, 100 KB, 1 MB |
| Concurrency | 50 |

Expect roughly linear degradation. Identifies if there's an unexpected cliff
(e.g., buffer copy overhead at large sizes).

### 4. Concurrency Scaling

**What it measures**: throughput and tail latency under increasing load.

Setup: reverse proxy mode, `["warn"]`, 10 KB clean payload.

| Variable | Values |
|----------|--------|
| Concurrency | 1, 10, 50, 100, 200, 500 |

Identifies saturation point and tail latency behavior. Look for p99 spikes
that indicate queueing.

### 5. Scanner Thread Scaling

**What it measures**: effect of `scanner_threads` config on throughput.

Setup: reverse proxy mode, `["warn", "redact"]`, 10 KB PII payload,
concurrency 200.

| Variable | Values |
|----------|--------|
| `scanner_threads` | 1, 2, 4, 8 |

Identifies the diminishing-returns point for scanner parallelism.

### 6. Mode Comparison

**What it measures**: overhead differences between proxy modes.

Setup: same 10 KB PII payload, `["warn", "redact"]`, concurrency 50.

| Mode | Notes |
|------|-------|
| Reverse proxy | Route to echo server |
| Forward proxy | Forward to echo server |
| REST API | `POST /v1/redact` (no upstream forwarding) |

REST API should be fastest (no upstream hop). Forward proxy may be slightly
slower due to URI parsing and TLS origination (if HTTPS destination).

### 7. Structured Scanning

**What it measures**: cost of body parsing + path/column-context detection
on bodies whose detection depends on structure rather than nearby plain text.

Setup: reverse proxy mode, `reverse_proxy_redact.toml`, concurrency 50.

| Variable | Values |
|----------|--------|
| `PAYLOAD` | `json` (4-5 level nested), `csv` (100 rows) |

The JSON exercises mid-path keyword cases (e.g. `request.user.phone.primary`,
`accounts[i].holder.name.first`) to ensure KeywordContextDetector has to look
beyond the leaf segment. The CSV exercises header-as-context detection over
many rows.

### 8. Sustained Load (Soak)

**What it measures**: memory leaks, GC pauses, file descriptor exhaustion.

Setup: reverse proxy mode, `["warn", "redact"]`, 10 KB PII payload, constant
rate at 80% of measured max throughput, duration: 30 minutes.

Monitor via admin `/metrics` endpoint:
- RSS memory (from `process_resident_memory_bytes` if exposed, or external `ps`)
- Open file descriptors
- `voidwall_errors_total` — should stay at 0
- Latency p99 — should stay stable, not drift upward

---

## Running

### One-off

```bash
# Terminal 1: echo server
cargo run --release --bin echo-server

# Terminal 2: proxy under test
cargo run --release -- --config benches/configs/reverse_proxy_warn.toml

# Terminal 3: load test
k6 run benches/k6/baseline.js
```

### Automated

A script (`benches/run.sh`) that:

1. Builds release binaries
2. Starts echo server, waits for healthcheck
3. For each scenario config + k6 script:
   a. Starts proxy with the scenario's config
   b. Waits for `/readyz`
   c. Runs k6, saves JSON output to `benches/results/<scenario>_<timestamp>.json`
   d. Stops proxy
4. Stops echo server
5. Prints summary table (req/s and p99 for each scenario)

### Test Configs

TOML files in `benches/configs/`, one per scenario variant:

```
benches/configs/reverse_proxy_warn.toml
benches/configs/reverse_proxy_block.toml
benches/configs/reverse_proxy_redact.toml
benches/configs/forward_proxy_redact.toml
benches/configs/rest_api_redact.toml
benches/configs/scanner_threads_1.toml
benches/configs/scanner_threads_2.toml
...
```

---

## Success Criteria

Not fixed numbers — these depend on hardware. Instead, define relative targets:

| Metric | Target |
|--------|--------|
| Proxy overhead (no PII) | < 1 ms added p99 latency at 10 KB body |
| Block action | Fastest action (no upstream hop) |
| Redact vs warn-only | < 20% throughput reduction |
| Soak test memory | No upward trend over 30 min |
| Soak test p99 | No upward trend over 30 min |

Absolute numbers are recorded per-run and compared across commits. A CI job
could flag regressions (> 10% throughput drop or > 20% p99 increase vs
baseline commit).
