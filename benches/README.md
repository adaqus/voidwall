# Load Testing

## Prerequisites

- [k6](https://grafana.com/docs/k6/latest/set-up/install-k6/) load testing tool
- Python 3 (for payload generation)

## Running Scenarios

```bash
benches/run.sh                                          # run all scenarios
benches/run.sh baseline                                 # run only "baseline"
benches/run.sh action_comparison body_size_scaling       # run two scenarios
```

Available scenarios (matching `k6/` file names): `baseline`, `action_comparison`, `body_size_scaling`, `concurrency_scaling`, `scanner_thread_scaling`.

This generates test payloads if missing, builds release binaries, starts the echo server and proxy for each scenario, runs k6, and prints a summary table. Results are saved to `benches/results/`.

Control duration per stage with the `DURATION` env var (default `30s`):

```bash
DURATION=10s benches/run.sh
```

**Note:** Requires Phase 10 (main entrypoint) to be implemented — the proxy binary must start and expose `/readyz` on the admin port.

## Running Individual Scenarios

Generate payloads first (if not already present), then start the echo server and proxy manually:

```bash
python3 benches/generate_payloads.py
```

```bash
# Terminal 1: echo server
cargo run --release --bin echo-server

# Terminal 2: proxy
cargo run --release -- --config benches/configs/reverse_proxy_redact.toml

# Terminal 3: load test
k6 run benches/k6/baseline.js
```

All k6 scripts accept env vars:

| Variable    | Default                  | Description            |
|-------------|--------------------------|------------------------|
| `PROXY_URL` | `http://127.0.0.1:8082`  | Proxy base URL         |
| `ECHO_URL`  | `http://127.0.0.1:8090`  | Echo server URL        |
| `DURATION`  | `30s`                    | Per-stage duration     |
| `VUS`       | varies per script        | Concurrency override   |

Example:

```bash
k6 run -e DURATION=10s -e VUS=100 benches/k6/action_comparison.js
```

## Scenarios

| Script                     | Config(s)                              | What it measures                        |
|----------------------------|----------------------------------------|-----------------------------------------|
| `baseline.js`              | `reverse_proxy_no_actions.toml`        | Proxy overhead vs direct-to-upstream    |
| `action_comparison.js`     | `reverse_proxy_{no_actions,block,redact,header}.toml` | Cost difference between actions |
| `body_size_scaling.js`     | `reverse_proxy_redact.toml`            | Throughput vs body size                 |
| `concurrency_scaling.js`   | `reverse_proxy_no_actions.toml`        | Saturation point and tail latency       |
| `scanner_thread_scaling.js`| `scanner_threads_{1,2,4,8}.toml`       | Effect of scanner thread count          |

For action comparison and scanner thread scaling, `run.sh` restarts the proxy with each config automatically. When running manually, restart the proxy with the appropriate config between runs.

## Configs

TOML files in `benches/configs/` — one per scenario variant. All use empty `countries`/`languages` lists so the pii crate enables all supported detectors (worst-case).

## Payloads

PII payloads contain 5 PII kinds covering both detector types:

- **Hyperscan-based:** Email, US SSN
- **KeywordContext-based:** Person Name, Date of Birth, GB NHS Number
