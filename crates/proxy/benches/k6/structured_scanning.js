// Scenario: Structured Scanning — Nested JSON & Tabular CSV
//
// Measures throughput when the proxy must parse and scan structured
// bodies whose detection depends on path/column context (not just
// nearby plain text). The JSON payload nests 4-5 levels deep with
// KeywordContextDetector keywords mid-path (e.g. `request.user.phone.primary`,
// `accounts[i].holder.name.first`). The CSV payload has a header row plus
// 100 data rows with columns matching detector keywords.
//
// Usage:
//   k6 run benches/k6/structured_scanning.js                # default: json
//   k6 run -e PAYLOAD=csv benches/k6/structured_scanning.js
//
// Env vars:
//   PROXY_URL  - proxy base URL          (default: http://127.0.0.1:8082)
//   DURATION   - per-stage duration       (default: 30s)
//   VUS        - concurrent virtual users (default: 50)
//   PAYLOAD    - json | csv               (default: json)

import http from "k6/http";
import { check } from "k6";
import { Trend, Counter } from "k6/metrics";

const PROXY_URL = __ENV.PROXY_URL || "http://127.0.0.1:8082";
const DURATION = __ENV.DURATION || "30s";
const VUS = parseInt(__ENV.VUS || "50");
const PAYLOAD = __ENV.PAYLOAD || "json";

const bodies = {
  json: {
    body: open("../payloads/pii_nested.json"),
    contentType: "application/json",
  },
  csv: {
    body: open("../payloads/pii_table.csv"),
    contentType: "text/csv",
  },
};

const selected = bodies[PAYLOAD];
if (!selected) {
  throw new Error(`unknown PAYLOAD=${PAYLOAD}, expected json|csv`);
}

const params = { headers: { "Content-Type": selected.contentType } };
const latency = new Trend(`structured_${PAYLOAD}_latency`, true);
const errors = new Counter("error_count");

export const options = {
  discardResponseBodies: true,
  scenarios: {
    structured: {
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
  const res = http.post(`${PROXY_URL}/echo`, selected.body, params);
  latency.add(res.timings.duration);
  check(res, { "status 200": (r) => r.status === 200 }) || errors.add(1);
}
