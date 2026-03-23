// Scenario 2: Action Comparison
//
// Measures cost difference between action types using PII payloads (~10 KB).
// Run once per action config (no_actions, block, redact, header+redact),
// restarting the proxy with the appropriate config between runs.
//
// Usage:
//   k6 run benches/k6/action_comparison.js
//
// Env vars:
//   PROXY_URL  - proxy base URL    (default: http://127.0.0.1:8082)
//   DURATION   - test duration      (default: 30s)
//   VUS        - concurrency        (default: 50)

import http from "k6/http";
import { check } from "k6";
import { Counter } from "k6/metrics";

const PROXY_URL = __ENV.PROXY_URL || "http://127.0.0.1:8082";
const DURATION = __ENV.DURATION || "30s";
const VUS = parseInt(__ENV.VUS || "50");

const payload = open("../payloads/pii_medium.json");

const errorCount = new Counter("error_count");

const params = {
  headers: { "Content-Type": "application/json" },
};

export const options = {
  scenarios: {
    action_test: {
      executor: "constant-vus",
      vus: VUS,
      duration: DURATION,
    },
  },
  thresholds: {
    http_req_failed: ["rate<0.05"],
  },
};

export default function () {
  const res = http.post(`${PROXY_URL}/echo`, payload, params);
  // Block action returns 403, others return 200
  check(res, {
    "status ok": (r) => r.status === 200 || r.status === 403,
  }) || errorCount.add(1);
}
