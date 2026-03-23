// Scenario 4: Concurrency Scaling
//
// Measures throughput and tail latency under increasing load.
// Uses clean medium payload with no-actions config (pure proxying cost).
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

const payload = open("../payloads/clean_medium.json");

const errorCount = new Counter("error_count");

const params = {
  headers: { "Content-Type": "application/json" },
};

export const options = {
  scenarios: {
    c1: {
      executor: "constant-vus",
      vus: 1,
      duration: DURATION,
      exec: "run",
      startTime: "0s",
      tags: { concurrency: "1" },
    },
    c10: {
      executor: "constant-vus",
      vus: 10,
      duration: DURATION,
      exec: "run",
      startTime: DURATION,
      tags: { concurrency: "10" },
    },
    c50: {
      executor: "constant-vus",
      vus: 50,
      duration: DURATION,
      exec: "run",
      startTime: `${parseInt(DURATION) * 2}s`,
      tags: { concurrency: "50" },
    },
    c100: {
      executor: "constant-vus",
      vus: 100,
      duration: DURATION,
      exec: "run",
      startTime: `${parseInt(DURATION) * 3}s`,
      tags: { concurrency: "100" },
    },
    c200: {
      executor: "constant-vus",
      vus: 200,
      duration: DURATION,
      exec: "run",
      startTime: `${parseInt(DURATION) * 4}s`,
      tags: { concurrency: "200" },
    },
    c500: {
      executor: "constant-vus",
      vus: 500,
      duration: DURATION,
      exec: "run",
      startTime: `${parseInt(DURATION) * 5}s`,
      tags: { concurrency: "500" },
    },
  },
  thresholds: {
    http_req_failed: ["rate<0.01"],
  },
};

export function run() {
  const res = http.post(`${PROXY_URL}/echo`, payload, params);
  check(res, { "status 200": (r) => r.status === 200 }) || errorCount.add(1);
}
