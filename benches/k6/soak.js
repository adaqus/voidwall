// Soak test — long-running load for observing metrics in Grafana.
//
// Load pattern: ramp up → sustain → ramp down → idle → repeat.
// The idle periods help spot memory that isn't freed after load drops.
//
// Usage:
//   k6 run benches/k6/soak.js
//
// Env vars:
//   PROXY_URL  - proxy base URL        (default: http://127.0.0.1:8082)
//   DURATION   - total test duration    (default: 30m)
//   PEAK_VUS   - peak concurrency       (default: 100)
//   PAYLOAD    - payload size            (default: medium; small|medium|large)
//   PII        - use PII payloads       (default: false; true|false)
//   CYCLES     - number of load cycles  (default: 1)

import http from "k6/http";
import { check } from "k6";
import { Counter } from "k6/metrics";

const PROXY_URL = __ENV.PROXY_URL || "http://127.0.0.1:8082";
const DURATION = __ENV.DURATION || "30m";
const PEAK_VUS = parseInt(__ENV.PEAK_VUS || "100");
const PAYLOAD = __ENV.PAYLOAD || "medium";
const USE_PII = (__ENV.PII || "false") === "true";
const CYCLES = parseInt(__ENV.CYCLES || "1");

const prefix = USE_PII ? "pii" : "clean";
const payload = open(`../payloads/${prefix}_${PAYLOAD}.json`);

const errorCount = new Counter("error_count");

const params = {
  headers: { "Content-Type": "application/json" },
};

// Parse duration string (e.g. "30m", "2h", "1h30m") to seconds.
function parseDuration(s) {
  let total = 0;
  const hours = s.match(/(\d+)h/);
  const mins = s.match(/(\d+)m/);
  const secs = s.match(/(\d+)s/);
  if (hours) total += parseInt(hours[1]) * 3600;
  if (mins) total += parseInt(mins[1]) * 60;
  if (secs) total += parseInt(secs[1]);
  return total || 1800;
}

const totalSecs = parseDuration(DURATION);

// Build repeating cycles of: ramp-up, sustain, ramp-down, idle.
// Total duration is split evenly across the requested number of cycles.
const CYCLE_PARTS = 5;
const partSecs = Math.floor(totalSecs / (CYCLES * CYCLE_PARTS));

function buildStages() {
  const stages = [];
  for (let i = 0; i < CYCLES; i++) {
    // Ramp up to peak
    stages.push({ duration: `${partSecs}s`, target: PEAK_VUS });
    // Sustain at peak
    stages.push({ duration: `${partSecs}s`, target: PEAK_VUS });
    // Sustain at peak (longer hold)
    stages.push({ duration: `${partSecs}s`, target: PEAK_VUS });
    // Ramp down to idle
    stages.push({ duration: `${partSecs}s`, target: 1 });
    // Idle
    stages.push({ duration: `${partSecs}s`, target: 1 });
  }
  return stages;
}

export const options = {
  discardResponseBodies: true,
  stages: buildStages(),
  thresholds: {
    http_req_failed: ["rate<0.01"],
  },
};

export default function () {
  const res = http.post(`${PROXY_URL}/echo`, payload, params);
  check(res, { "status 200": (r) => r.status === 200 }) || errorCount.add(1);
}
