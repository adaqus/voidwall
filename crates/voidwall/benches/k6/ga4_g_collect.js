// Scenario: GA4 /g/collect — browser tracker shape
//
// Measures throughput when the proxy routes a request through the `ga4`
// specialization for the gtag.js browser shape: a POST to /g/collect with
// the full short-key payload as `application/x-www-form-urlencoded` body.
// No JSON is involved on this endpoint — it is form-only.
//
// The body covers most of the GA4 short-key allowlist:
//
//   * opaque / skip:   v, tid, cid, _s, _et, _p, gtm
//   * flat-scanned:    dt, uid, en, cu, cm, cs, _uip, ip_override,
//                      ep.<custom>, up.<custom>
//   * recursive URL:   dl, dr   (inner query carries PII)
//
// Usage:
//   k6 run benches/k6/ga4_g_collect.js
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

// `dl` / `dr` carry an inner URL whose query parameters are themselves
// scanned per-field by the recursive URL handler. The inner emails fire
// PII detection inside the URL layer.
const innerDl =
  "https://shop.example.com/checkout" +
  "?email=jane.doe@example.com" +
  "&ssn=123-45-6789";
const innerDr = "https://referrer.example.com/?email=referrer@example.com";

const BODY =
  "v=2" +
  "&tid=G-ABC1234567" +
  "&cid=35009a79-1a05-49d7-b876-2b884d0f825b" +
  "&_s=1" +
  "&_et=42" +
  "&_p=1234567890" +
  "&gtm=2u123" +
  "&en=signup" +
  "&dt=Checkout%20for%20jane.doe%40example.com" +
  "&uid=jane.doe%40example.com" +
  "&cu=USD" +
  "&cm=email" +
  "&cs=newsletter" +
  "&_uip=192.168.1.42" +
  "&ip_override=10.0.0.255" +
  "&ep.full_name=Jane%20Doe" +
  "&ep.phone=%2B14155551234" +
  "&ep.notes=ping%20us%20at%20support%40example.com" +
  "&up.account_tier=gold" +
  "&up.contact_phone=phone%3A%205551234567" +
  "&dl=" + encodeURIComponent(innerDl) +
  "&dr=" + encodeURIComponent(innerDr);

const params = {
  headers: { "Content-Type": "application/x-www-form-urlencoded" },
};
const latency = new Trend("ga4_g_collect_latency", true);
const errors = new Counter("error_count");

export const options = {
  discardResponseBodies: true,
  scenarios: {
    ga4_g_collect: {
      executor: "constant-vus",
      vus: VUS,
      duration: DURATION,
    },
  },
  thresholds: {
    http_req_failed: ["rate<0.01"],
  },
};

const url = `${PROXY_URL}/g/collect`;

export default function () {
  const res = http.post(url, BODY, params);
  latency.add(res.timings.duration);
  check(res, { "status 200": (r) => r.status === 200 }) || errors.add(1);
}
