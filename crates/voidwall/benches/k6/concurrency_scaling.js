// Scenario 4: Concurrency Scaling
//
// Measures throughput and tail latency under increasing load.
// Uses clean medium payload with scanning off (pure proxying cost).
//
// Usage:
//   k6 run benches/k6/concurrency_scaling.js
//
// Env vars:
//   PROXY_URL  - proxy base URL    (default: http://127.0.0.1:8082)
//   DURATION   - per-stage duration (default: 30s)

import http from "k6/http";
import { check } from "k6";
import { Counter } from "k6/metrics";

const PROXY_URL = __ENV.PROXY_URL || "http://127.0.0.1:8082";
const DURATION = __ENV.DURATION || "30s";

// VUS is set via env var so run.sh can invoke once per concurrency level.
const VUS = parseInt(__ENV.VUS || "50");

const payload = open("../payloads/clean_medium.json");

const errorCount = new Counter("error_count");

const params = {
  headers: { "Content-Type": "application/json" },
};

export const options = {
  discardResponseBodies: true,
  scenarios: {
    concurrency: {
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
