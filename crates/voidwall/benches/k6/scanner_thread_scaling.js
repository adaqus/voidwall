// Scenario 5: Scanner Thread Scaling
//
// Measures effect of scanner_threads config on throughput.
// Uses a 10 KB clean payload with request scanning on at high concurrency:
// the scanner does full work and the message still reaches the upstream.
// Run once per scanner_threads config (1, 2, 4, 8), restarting
// the proxy with the appropriate config between runs.
//
// Usage:
//   k6 run benches/k6/scanner_thread_scaling.js
//
// Env vars:
//   PROXY_URL  - proxy base URL    (default: http://127.0.0.1:8082)
//   DURATION   - test duration      (default: 30s)
//   VUS        - concurrency        (default: 200)

import http from "k6/http";
import { check } from "k6";
import { Counter } from "k6/metrics";

const PROXY_URL = __ENV.PROXY_URL || "http://127.0.0.1:8082";
const DURATION = __ENV.DURATION || "30s";
const VUS = parseInt(__ENV.VUS || "200");

const payload = open("../payloads/clean_medium.json");

const errorCount = new Counter("error_count");

const params = {
  headers: { "Content-Type": "application/json" },
};

export const options = {
  discardResponseBodies: true,
  scenarios: {
    scanner_test: {
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
  check(res, { "status 200": (r) => r.status === 200 }) || errorCount.add(1);
}
