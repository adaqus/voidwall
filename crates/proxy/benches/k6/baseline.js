// Scenario 1: Baseline — Proxy Overhead
//
// Measures raw cost of proxying with clean payloads (no PII detected).
// Compares direct-to-echo-server vs through-proxy at varying body sizes
// and concurrency levels.
//
// Usage:
//   k6 run benches/k6/baseline.js
//
// Env vars:
//   PROXY_URL   - proxy base URL     (default: http://127.0.0.1:8082)
//   ECHO_URL    - echo server URL     (default: http://127.0.0.1:8090)
//   DURATION    - per-stage duration   (default: 30s)

import http from "k6/http";
import { check } from "k6";
import { Trend, Counter } from "k6/metrics";

const PROXY_URL = __ENV.PROXY_URL || "http://127.0.0.1:8082";
const ECHO_URL = __ENV.ECHO_URL || "http://127.0.0.1:8090";
const DURATION = __ENV.DURATION || "30s";

const payloads = {
  small: open("../payloads/clean_small.json"),
  medium: open("../payloads/clean_medium.json"),
  large: open("../payloads/clean_large.json"),
};

const proxyLatency = new Trend("proxy_latency", true);
const directLatency = new Trend("direct_latency", true);
const errorCount = new Counter("error_count");

const params = {
  headers: { "Content-Type": "application/json" },
};

// PAYLOAD and VUS are set via env vars so run.sh can invoke this script
// once per (payload, concurrency) combination — keeping each k6 process small.
const PAYLOAD = __ENV.PAYLOAD || "medium";  // small | medium | large
const VUS = parseInt(__ENV.VUS || "50");
const TARGET = __ENV.TARGET || "proxy";     // proxy | direct

export const options = {
  discardResponseBodies: true,
  scenarios: {
    baseline: {
      executor: "constant-vus",
      vus: VUS,
      duration: DURATION,
    },
  },
  thresholds: {
    http_req_failed: ["rate<0.01"],
  },
};

const baseUrl = TARGET === "direct" ? ECHO_URL : PROXY_URL;
const payload = payloads[PAYLOAD];
const latency = TARGET === "direct" ? directLatency : proxyLatency;

export default function () {
  const res = http.post(`${baseUrl}/echo`, payload, params);
  latency.add(res.timings.duration);
  check(res, { "status 200": (r) => r.status === 200 }) || errorCount.add(1);
}
