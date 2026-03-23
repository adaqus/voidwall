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

export const options = {
  scenarios: {
    // Small payload, varying concurrency
    small_c10: {
      executor: "constant-vus",
      vus: 10,
      duration: DURATION,
      exec: "proxySmall",
      startTime: "0s",
    },
    small_c50: {
      executor: "constant-vus",
      vus: 50,
      duration: DURATION,
      exec: "proxySmall",
      startTime: DURATION,
    },
    small_c200: {
      executor: "constant-vus",
      vus: 200,
      duration: DURATION,
      exec: "proxySmall",
      startTime: `${parseInt(DURATION) * 2}s`,
    },
    // Medium payload
    medium_c10: {
      executor: "constant-vus",
      vus: 10,
      duration: DURATION,
      exec: "proxyMedium",
      startTime: `${parseInt(DURATION) * 3}s`,
    },
    medium_c50: {
      executor: "constant-vus",
      vus: 50,
      duration: DURATION,
      exec: "proxyMedium",
      startTime: `${parseInt(DURATION) * 4}s`,
    },
    medium_c200: {
      executor: "constant-vus",
      vus: 200,
      duration: DURATION,
      exec: "proxyMedium",
      startTime: `${parseInt(DURATION) * 5}s`,
    },
    // Large payload
    large_c10: {
      executor: "constant-vus",
      vus: 10,
      duration: DURATION,
      exec: "proxyLarge",
      startTime: `${parseInt(DURATION) * 6}s`,
    },
    large_c50: {
      executor: "constant-vus",
      vus: 50,
      duration: DURATION,
      exec: "proxyLarge",
      startTime: `${parseInt(DURATION) * 7}s`,
    },
    large_c200: {
      executor: "constant-vus",
      vus: 200,
      duration: DURATION,
      exec: "proxyLarge",
      startTime: `${parseInt(DURATION) * 8}s`,
    },
    // Direct-to-echo baselines (medium payload only)
    direct_c10: {
      executor: "constant-vus",
      vus: 10,
      duration: DURATION,
      exec: "directMedium",
      startTime: `${parseInt(DURATION) * 9}s`,
    },
    direct_c50: {
      executor: "constant-vus",
      vus: 50,
      duration: DURATION,
      exec: "directMedium",
      startTime: `${parseInt(DURATION) * 10}s`,
    },
    direct_c200: {
      executor: "constant-vus",
      vus: 200,
      duration: DURATION,
      exec: "directMedium",
      startTime: `${parseInt(DURATION) * 11}s`,
    },
  },
  thresholds: {
    http_req_failed: ["rate<0.01"],
  },
};

function sendProxy(payload, tag) {
  const res = http.post(`${PROXY_URL}/echo`, payload, {
    ...params,
    tags: { name: tag },
  });
  proxyLatency.add(res.timings.duration);
  check(res, { "status 200": (r) => r.status === 200 }) || errorCount.add(1);
}

function sendDirect(payload, tag) {
  const res = http.post(`${ECHO_URL}/echo`, payload, {
    ...params,
    tags: { name: tag },
  });
  directLatency.add(res.timings.duration);
  check(res, { "status 200": (r) => r.status === 200 }) || errorCount.add(1);
}

export function proxySmall() {
  sendProxy(payloads.small, "proxy_small");
}
export function proxyMedium() {
  sendProxy(payloads.medium, "proxy_medium");
}
export function proxyLarge() {
  sendProxy(payloads.large, "proxy_large");
}
export function directMedium() {
  sendDirect(payloads.medium, "direct_medium");
}
