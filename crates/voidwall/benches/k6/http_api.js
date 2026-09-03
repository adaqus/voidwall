// Scenario: HTTP API — /v1/scan and /v1/redact throughput
//
// Measures the cost of the HTTP API endpoints across the supported
// content types (text/plain, application/json, text/csv) and payload
// sizes. Both /v1/scan (no body rewrite) and /v1/redact (in-place
// rewrite) paths are exercised so the cost difference is directly
// observable.
//
// The script runs ONE (endpoint, content type, payload) combination per
// k6 process — driven by env vars — so run.sh can iterate without
// pre-allocating VUs for the peak.
//
// Usage:
//   k6 run benches/k6/http_api.js                            # defaults: redact, json, medium, PII
//   k6 run -e ENDPOINT=scan -e PAYLOAD=large benches/k6/http_api.js
//
// Env vars:
//   API_URL       - HTTP API base URL              (default: http://127.0.0.1:8083)
//   DURATION      - test duration                  (default: 30s)
//   VUS           - concurrency                    (default: 50)
//   ENDPOINT      - scan | redact                  (default: redact)
//   CONTENT_TYPE  - text | json | csv              (default: json)
//   PAYLOAD       - small | medium | large         (default: medium)
//   PII           - true | false                   (default: true)

import http from "k6/http";
import { check } from "k6";
import { Counter } from "k6/metrics";

const API_URL = __ENV.API_URL || "http://127.0.0.1:8083";
const DURATION = __ENV.DURATION || "30s";
const VUS = parseInt(__ENV.VUS || "50");
const ENDPOINT = __ENV.ENDPOINT || "redact";
const CONTENT_TYPE = __ENV.CONTENT_TYPE || "json";
const PAYLOAD = __ENV.PAYLOAD || "medium";
const PII = (__ENV.PII || "true").toLowerCase() !== "false";

// k6's `open()` requires a string literal, so every payload variant must be
// declared up-front. The selector at the bottom of the file picks one.
const bodies = {
  json: {
    pii: {
      small: open("../payloads/pii_small.json"),
      medium: open("../payloads/pii_medium.json"),
      large: open("../payloads/pii_large.json"),
    },
    clean: {
      small: open("../payloads/clean_small.json"),
      medium: open("../payloads/clean_medium.json"),
      large: open("../payloads/clean_large.json"),
    },
    contentType: "application/json",
  },
  // text/plain reuses the JSON byte streams — the API treats the body as
  // opaque text when the declared content type is text/plain, so the bytes
  // exercise the flat-text scanning path without needing a separate corpus.
  text: {
    pii: {
      small: open("../payloads/pii_small.json"),
      medium: open("../payloads/pii_medium.json"),
      large: open("../payloads/pii_large.json"),
    },
    clean: {
      small: open("../payloads/clean_small.json"),
      medium: open("../payloads/clean_medium.json"),
      large: open("../payloads/clean_large.json"),
    },
    contentType: "text/plain",
  },
  csv: {
    pii: {
      small: open("../payloads/pii_table_small.csv"),
      medium: open("../payloads/pii_table_medium.csv"),
      large: open("../payloads/pii_table_large.csv"),
    },
    clean: {
      small: open("../payloads/clean_table_small.csv"),
      medium: open("../payloads/clean_table_medium.csv"),
      large: open("../payloads/clean_table_large.csv"),
    },
    contentType: "text/csv",
  },
};

const variant = bodies[CONTENT_TYPE];
if (!variant) {
  throw new Error(`unknown CONTENT_TYPE=${CONTENT_TYPE}, expected text|json|csv`);
}
const corpus = PII ? variant.pii : variant.clean;
const body = corpus[PAYLOAD];
if (!body) {
  throw new Error(`unknown PAYLOAD=${PAYLOAD}, expected small|medium|large`);
}

if (ENDPOINT !== "scan" && ENDPOINT !== "redact") {
  throw new Error(`unknown ENDPOINT=${ENDPOINT}, expected scan|redact`);
}

const params = { headers: { "Content-Type": variant.contentType } };
// No custom Trend: k6 already records latency in `http_req_duration`. Adding
// a second per-iteration Trend would double the in-memory sample count and
// push memory into OOM territory on long, high-rate runs.
const errors = new Counter("error_count");

export const options = {
  discardResponseBodies: true,
  scenarios: {
    http_api: {
      executor: "constant-vus",
      vus: VUS,
      duration: DURATION,
    },
  },
  thresholds: {
    http_req_failed: ["rate<0.01"],
  },
};

const url = `${API_URL}/v1/${ENDPOINT}`;

export default function () {
  const res = http.post(url, body, params);
  check(res, { "status 200": (r) => r.status === 200 }) || errors.add(1);
}
