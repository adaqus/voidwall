// Scenario 3: Body Size Scaling
//
// Measures how throughput degrades with body size using PII payloads.
// Proxy should be running with request scanning on. Payloads are clean so
// the message reaches the upstream and the full round trip is measured.
//
// Usage:
//   k6 run benches/k6/body_size_scaling.js
//
// Env vars:
//   PROXY_URL  - proxy base URL    (default: http://127.0.0.1:8082)
//   DURATION   - per-stage duration (default: 30s)
//   VUS        - concurrency        (default: 50)

import http from "k6/http";
import { check } from "k6";
import { Trend, Counter } from "k6/metrics";

const PROXY_URL = __ENV.PROXY_URL || "http://127.0.0.1:8082";
const DURATION = __ENV.DURATION || "30s";
const VUS = parseInt(__ENV.VUS || "50");

// PAYLOAD is set via env var so run.sh can invoke once per size.
const PAYLOAD = __ENV.PAYLOAD || "medium";  // small | medium | large

const payloads = {
  // Clean payloads: a detection now blocks at the proxy, so a PII payload
  // would never reach the upstream and the forward path would go unmeasured.
  // The scan still runs in full — it just finds nothing.
  small: open("../payloads/clean_small.json"),
  medium: open("../payloads/clean_medium.json"),
  large: open("../payloads/clean_large.json"),
};

const latency = new Trend("latency", true);
const errorCount = new Counter("error_count");

const params = {
  headers: { "Content-Type": "application/json" },
};

const payload = payloads[PAYLOAD];

export const options = {
  discardResponseBodies: true,
  scenarios: {
    body_size: {
      executor: "constant-vus",
      vus: VUS,
      duration: DURATION,
    },
  },
  thresholds: {
    http_req_failed: ["rate<0.01"],
  },
};

export default function () {
  const res = http.post(`${PROXY_URL}/echo`, payload, params);
  latency.add(res.timings.duration);
  check(res, { "status 200": (r) => r.status === 200 }) || errorCount.add(1);
}
