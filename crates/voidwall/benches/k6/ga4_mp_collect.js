// Scenario: GA4 /mp/collect — server-side Measurement Protocol shape
//
// Measures throughput when the proxy routes a request through the `ga4`
// specialization for the server-side Measurement Protocol shape: a POST
// to /mp/collect with `?api_secret=…&measurement_id=G-…` credentials in
// the query and a JSON body. The query carries only the credential pair
// (both are opaque/skip from the spec's perspective), so this scenario
// isolates the JSON processor in the spec.
//
// The JSON body covers every top-level allowlisted key plus a
// representative spread of `events[].params`:
//
//   * client_id, user_id, ip_override
//   * user_data         (email_address, phone_number, sha256_*, address)
//   * user_location     (city, region_id, country_id, …)
//   * user_properties   (each `.value` walked as a string leaf)
//   * events[]          (name + params.{items, page_location, link_url,
//                        form_destination, search_term, transaction_id,
//                        coupon, currency, value, custom params, …})
//
// Usage:
//   k6 run benches/k6/ga4_mp_collect.js
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

// /mp/collect query carries only the credentials. Both are opaque to GA4
// — neither api_secret nor measurement_id is on the scanned allowlist —
// so the form processor walks the pair quickly and the JSON body is
// where the real work lives.
const QUERY = "api_secret=fake_secret&measurement_id=G-ABC1234567";

const BODY = JSON.stringify({
  client_id: "35009a79-1a05-49d7-b876-2b884d0f825b",
  user_id: "jane.doe@example.com",
  ip_override: "10.0.0.255",
  timestamp_micros: 1715600000000000,
  non_personalized_ads: false,
  user_data: {
    email_address: "jane.doe@example.com",
    phone_number: "+1 415 555 1234",
    sha256_email_address:
      "f4c1c1cd8f4ed3eaaee6caa0a214e25b3a7d2b4d1f8f0a7b5e0b54bb2bb6f00d",
    address: {
      first_name: "Jane",
      last_name: "Doe",
      street: "742 Evergreen Terrace",
      city: "Springfield",
      region: "OR",
      postal_code: "97403",
      country: "US",
    },
  },
  user_location: {
    city: "Springfield",
    region_id: "US-OR",
    country_id: "US",
  },
  user_properties: {
    account_tier: { value: "gold" },
    favourite_color: { value: "blue" },
    contact_phone: { value: "phone: 5551234567" },
  },
  consent: { ad_user_data: "GRANTED", ad_personalization: "GRANTED" },
  events: [
    {
      name: "page_view",
      params: {
        page_location:
          "https://app.example.com/users/jane.doe@example.com/profile",
        page_title: "Profile — Jane Doe",
        page_referrer: "https://shop.example.com/?email=jane.doe@example.com",
        language: "en-US",
        screen_resolution: "1920x1080",
      },
    },
    {
      name: "view_search_results",
      params: {
        search_term: "looking for jane.doe@example.com",
        search_category: "users",
      },
    },
    {
      name: "purchase",
      params: {
        transaction_id: "order-jane.doe@example.com-2026",
        currency: "USD",
        value: 199.99,
        coupon: "promo for user@example.com",
        affiliation: "Web Store",
        shipping: 9.5,
        tax: 14.99,
        items: [
          {
            item_id: "SKU-1",
            item_name: "Engraved mug — Vorname: Hans",
            item_brand: "Acme",
            item_category: "Gifts",
            item_variant: "Tall",
            price: 19.99,
            quantity: 1,
          },
          {
            item_id: "SKU-2",
            item_name: "Gift card for support@example.com",
            item_brand: "Acme",
            item_category: "Gifts",
            price: 50.0,
            quantity: 2,
          },
        ],
      },
    },
    {
      name: "form_submit",
      params: {
        form_destination:
          "https://app.example.com/checkout?email=user@example.com",
        form_id: "newsletter",
        form_submit_text: "Sign up",
      },
    },
    {
      name: "click",
      params: {
        link_url: "https://partner.example.com/redir?email=user@example.com",
        link_classes: "cta",
        link_text: "Reach out at hello@example.com",
        outbound: true,
      },
    },
    {
      name: "newsletter_signup",
      params: {
        email: "user@example.com",
        method: "footer-form",
      },
    },
    {
      name: "exception",
      params: {
        description: "AuthError\nIP: 10.0.0.255 ok",
        fatal: false,
      },
    },
  ],
});

const params = { headers: { "Content-Type": "application/json" } };
const latency = new Trend("ga4_mp_collect_latency", true);
const errors = new Counter("error_count");

export const options = {
  discardResponseBodies: true,
  scenarios: {
    ga4_mp_collect: {
      executor: "constant-vus",
      vus: VUS,
      duration: DURATION,
    },
  },
  thresholds: {
    http_req_failed: ["rate<0.01"],
  },
};

const url = `${PROXY_URL}/mp/collect?${QUERY}`;

export default function () {
  const res = http.post(url, BODY, params);
  latency.add(res.timings.duration);
  check(res, { "status 200": (r) => r.status === 200 }) || errors.add(1);
}
