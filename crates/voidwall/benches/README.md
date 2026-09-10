# Load Testing

## Prerequisites

- [k6](https://grafana.com/docs/k6/latest/set-up/install-k6/) load testing tool
- Python 3 (for payload generation)

## Running Scenarios

```bash
benches/run.sh                                          # run all scenarios
benches/run.sh baseline                                 # run only "baseline"
benches/run.sh baseline body_size_scaling                # run two scenarios
```

Available scenarios (matching `k6/` file names): `baseline`, `body_size_scaling`, `concurrency_scaling`, `scanner_thread_scaling`, `structured_scanning`, `http_api`.

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
cargo run --release -- --config benches/configs/reverse_proxy_scan_on.toml

# Terminal 3: load test
k6 run benches/k6/baseline.js
```

All k6 scripts accept env vars:

| Variable    | Default                  | Description            |
|-------------|--------------------------|------------------------|
| `PROXY_URL` | `http://127.0.0.1:8082`  | Proxy base URL         |
| `ECHO_URL`  | `http://127.0.0.1:8090`  | Echo server URL        |
| `API_URL`   | `http://127.0.0.1:8083`  | HTTP API base URL (`http_api.js`) |
| `DURATION`  | `30s`                    | Per-stage duration     |
| `VUS`       | varies per script        | Concurrency override   |

Example:

```bash
```

## Scenarios

| Script                     | Config(s)                              | What it measures                        |
|----------------------------|----------------------------------------|-----------------------------------------|
| `baseline.js`              | `reverse_proxy_scan_off.toml`        | Proxy overhead vs direct-to-upstream    |
| `body_size_scaling.js`     | `reverse_proxy_scan_on.toml`            | Throughput vs body size                 |
| `concurrency_scaling.js`   | `reverse_proxy_scan_off.toml`        | Saturation point and tail latency       |
| `scanner_thread_scaling.js`| `scanner_threads_{1,2,4,8}.toml`       | Effect of scanner thread count          |
| `structured_scanning.js`   | `reverse_proxy_scan_on.toml`            | Throughput on nested JSON & 100-row CSV |
| `http_api.js`              | `http_api.toml`                        | `/v1/scan` across text/json/csv & 3 sizes                 |

For action comparison and scanner thread scaling, `run.sh` restarts the proxy with each config automatically. When running manually, restart the proxy with the appropriate config between runs.

## Soak Test

Long-running load test for observing CPU, memory, and other process metrics in Grafana. Requires the Docker dev environment to be running.

```bash
docker/ctl start                          # start proxy, echo, prometheus, grafana
docker/ctl soak                           # 30min soak test with default settings
DURATION=2h docker/ctl soak               # 2 hours with PII payloads
```

The load pattern cycles through: ramp up → sustain → ramp down → idle, then repeats. Idle phases help reveal memory that isn't freed after load drops.

| Variable   | Default  | Description             |
|------------|----------|-------------------------|
| `DURATION` | `30m`    | Total test duration     |
| `PEAK_VUS` | `100`    | Peak concurrency        |
| `CYCLES`   | `1`      | Number of load cycles   |

Open Grafana at `http://localhost:3000` to view the pre-provisioned "PII Proxy" dashboard with RSS, CPU, request rate, latency percentiles, and PII detection panels.

## Configs

TOML files in `benches/configs/` — one per scenario variant. All use empty `countries`/`languages` lists so the pii crate enables all supported detectors (worst-case).

## Payloads

PII payloads contain 5 PII kinds covering both detector types:

- **Hyperscan-based:** Email, US SSN
- **KeywordContext-based:** Person Name, Date of Birth, GB NHS Number
