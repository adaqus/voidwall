// Scenario: Matomo Specialization — custom event + content tracking + email uid
//
// Measures throughput when the proxy routes a request through the
// `matomo` specialization. Each request POSTs a form-encoded body to
// `/matomo.php` that exercises the three field families the scenario
// targets:
//
//   * Custom event tracking:    e_c, e_a, e_n, e_v
//   * Content tracking:         c_n, c_p, c_i
//   * User ID as email:         uid=<email>
//
// Plus a few platform/skip fields (idsite, rec, apiv, _id, rand) and
// action_name so the payload looks like a realistic Matomo tracker hit.
// Several of the scanned fields embed PII (email, phone) so the redact
// pipeline is fully exercised.
//
// Usage:
//   k6 run benches/k6/matomo_specialization.js
//
// Env vars:
//   PROXY_URL  - proxy base URL          (default: http://127.0.0.1:8082)
//   DURATION   - test duration            (default: 30s)
//   VUS        - concurrency              (default: 50)

import http from "k6/http";
import { check } from "k6";
import { Counter, Trend } from "k6/metrics";

const PROXY_URL = __ENV.PROXY_URL || "http://127.0.0.1:8082";
const DURATION = __ENV.DURATION || "30s";
const VUS = parseInt(__ENV.VUS || "50");

// Matomo POST form body. Custom event params (e_*), content tracking
// (c_*), and user ID set to an email. Skip fields (idsite/rec/apiv/_id/rand)
// keep the payload shape realistic. Values that should be scanned for PII
// embed an email or phone so redaction sees real work.
const BODY = [
  // Skip / platform fields — pass through verbatim.
  "idsite=1",
  "rec=1",
  "apiv=1",
  "_id=a1b2c3d4e5f6a7b8",
  "rand=4242",
  // Page-level context.
  "action_name=Checkout",
  // User ID set to an email.
  "uid=" + encodeURIComponent("jane.doe@example.com"),
  // Custom event tracking.
  "e_c=Newsletter",
  "e_a=Submit",
  "e_n=" + encodeURIComponent("Sign up for jane.doe@example.com"),
  "e_v=1",
  // Content tracking.
  "c_n=" + encodeURIComponent("Newsletter Hero"),
  "c_p=" + encodeURIComponent("phone: 5551234567"),
  "c_i=" + encodeURIComponent("Click — jane.doe@example.com"),
].join("&");

const params = {
  headers: { "Content-Type": "application/x-www-form-urlencoded" },
};
const latency = new Trend("matomo_spec_latency", true);
const errors = new Counter("error_count");

export const options = {
  discardResponseBodies: true,
  scenarios: {
    matomo_specialization: {
      executor: "constant-vus",
      vus: VUS,
      duration: DURATION,
    },
  },
  thresholds: {
    http_req_failed: ["rate<0.01"],
  },
};

const url = `${PROXY_URL}/matomo.php`;

export default function () {
  const res = http.post(url, BODY, params);
  latency.add(res.timings.duration);
  check(res, { "status 200": (r) => r.status === 200 }) || errors.add(1);
}
