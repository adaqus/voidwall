// Scenario 3: Body Size Scaling
//
// Measures how throughput degrades with body size using PII payloads.
// Proxy should be running with redact action config.
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

const payloads = {
  small: open("../payloads/pii_small.json"),
  medium: open("../payloads/pii_medium.json"),
  large: open("../payloads/pii_large.json"),
};

const smallLatency = new Trend("latency_small", true);
const mediumLatency = new Trend("latency_medium", true);
const largeLatency = new Trend("latency_large", true);
const errorCount = new Counter("error_count");

const params = {
  headers: { "Content-Type": "application/json" },
};

export const options = {
  scenarios: {
    small: {
      executor: "constant-vus",
      vus: VUS,
      duration: DURATION,
      exec: "testSmall",
      startTime: "0s",
    },
    medium: {
      executor: "constant-vus",
      vus: VUS,
      duration: DURATION,
      exec: "testMedium",
      startTime: DURATION,
    },
    large: {
      executor: "constant-vus",
      vus: VUS,
      duration: DURATION,
      exec: "testLarge",
      startTime: `${parseInt(DURATION) * 2}s`,
    },
  },
  thresholds: {
    http_req_failed: ["rate<0.01"],
  },
};

export function testSmall() {
  const res = http.post(`${PROXY_URL}/echo`, payloads.small, {
    ...params,
    tags: { name: "small" },
  });
  smallLatency.add(res.timings.duration);
  check(res, { "status 200": (r) => r.status === 200 }) || errorCount.add(1);
}

export function testMedium() {
  const res = http.post(`${PROXY_URL}/echo`, payloads.medium, {
    ...params,
    tags: { name: "medium" },
  });
  mediumLatency.add(res.timings.duration);
  check(res, { "status 200": (r) => r.status === 200 }) || errorCount.add(1);
}

export function testLarge() {
  const res = http.post(`${PROXY_URL}/echo`, payloads.large, {
    ...params,
    tags: { name: "large" },
  });
  largeLatency.add(res.timings.duration);
  check(res, { "status 200": (r) => r.status === 200 }) || errorCount.add(1);
}
