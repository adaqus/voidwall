# PII Proxy — Design Document

## Overview

A multi-mode HTTP proxy that inspects HTTP traffic for sensitive data (PII) using
the `pii` crate. Depending on configuration, the proxy can block, redact, or add
headers for detected PII. Prometheus metrics are always updated when PII is
detected, regardless of action configuration.

It is not an ingress controller. It may integrate with existing ingress controllers
(NGINX, HAProxy, Envoy/Istio) and can also operate as a standalone reverse/forward
proxy or an HTTP API microservice.

---

## Operating Modes

The proxy supports four operating modes that can be enabled independently or in any
combination within a single binary/deployment.

### 1. Ingress Controller Integration Mode — Deferred

Integration with existing ingress controllers as an external processing service.
Sub-modes (HAProxy, NGINX, Envoy ext_proc) will be discussed later. Support for
HAProxy, NGINX, and Envoy is considered.

### 2. Standalone Reverse Proxy Mode

The proxy accepts HTTP requests directly, inspects them, and forwards to configured
upstream backends based on path prefix and Host header matching. TLS termination is
supported.

- Capabilities: **block, header, redact**
- Use case: non-Kubernetes deployments, or when no ingress controller is present

### 3. Standalone Forward Proxy Mode

The proxy acts as a forward proxy for HTTP clients. Clients configure the proxy
via `HTTP_PROXY` / `HTTPS_PROXY` environment variables or client library settings.

The proxy does not support CONNECT tunneling. For HTTPS destinations, it terminates
the client's TLS connection and establishes a new TLS connection to the destination
server. This gives the proxy full visibility into the request content.

- Capabilities: **block, header, redact**
- Use case: containers or services making outbound HTTP/HTTPS requests

### 4. HTTP API Mode

Internal microservice exposing PII scanning and redaction as HTTP endpoints. Other
services in the cluster call it to check or sanitize content. Accepts plain text,
JSON, and CSV/TSV bodies; structured formats reuse the proxy's structured-scanning
path so detection benefits from key-path / column-name context.

- Capabilities: **scan (detect), redact**
- Use case: application-level integration, pre-processing pipelines, batch scanning

---

## Architecture

```
                    Single Binary / Container
  ┌─────────────────────────────────────────────────────────┐
  │                                                         │
  │  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐  │
  │  │ Reverse Proxy │  │ Forward      │  │ HTTP API     │  │
  │  │ HTTP :8082    │  │ Proxy        │  │ HTTP :8083   │  │
  │  │               │  │ HTTP :8084   │  │              │  │
  │  └──────┬───────┘  └──────┬───────┘  └──────┬───────┘  │
  │         │                 │                  │          │
  │         └────────┬────────┴──────────────────┘          │
  │                  │                                      │
  │          ┌───────▼────────┐                             │
  │          │  PII Scanner   │                             │
  │          └───────┬────────┘                             │
  │                  │                                      │
  │          ┌───────▼────────┐                             │
  │          │ Action Engine  │                             │
  │          │ (block/        │                             │
  │          │  header/redact)│                             │
  │          └───────┬────────┘                             │
  │                  │                                      │
  │          ┌───────▼────────┐                             │
  │          │ Metrics        │                             │
  │          │ (Prometheus)   │                             │
  │          └────────────────┘                             │
  │                                                         │
  │  ┌────────────────────────────────────────────┐        │
  │  │ Admin                         HTTP :9090   │        │
  │  │ /metrics  /healthz  /readyz                │        │
  │  └────────────────────────────────────────────┘        │
  │                                                         │
  │  ┌────────────────────────────────────────────┐        │
  │  │ Ingress Controller Integration  [DEFERRED] │        │
  │  │ (External Auth / ext_proc)                 │        │
  │  └────────────────────────────────────────────┘        │
  └─────────────────────────────────────────────────────────┘
```

---

## PII Inspection

### Scan Targets

Configurable per mode. Not all targets apply to all modes. In reverse
proxy and forward proxy modes, both requests and responses are scannable
(controlled by `request_actions` and `response_actions`).

| Scan target         | Reverse Proxy | Forward Proxy | HTTP API |
|----------------------|:---:|:---:|:---:|
| URL path             | request | request | n/a |
| Query parameters     | request | request | n/a |
| Request headers      | request | request | n/a |
| Request body         | request | request | yes (raw body) |
| Response headers     | response | response | n/a |
| Response body        | response | response | n/a |

### Body Scanning Constraints

- **Max body size**: Configurable (default: 1 MB). Bodies exceeding this limit are
  not scanned. The behavior is governed by the `on_error` setting: in `fail_open`
  mode the request is passed through; in `fail_close` mode the request is blocked.
  A metric `pii_proxy_errors_total` is incremented in either case.
- **Content types**: Only text-based content types are scanned by default:
  `application/json`, `text/plain`, `text/html`, `application/x-www-form-urlencoded`,
  `text/csv`, `text/tab-separated-values`.
  Configurable via allowlist.

### Structured Body Scanning

For certain content types, the proxy parses body structure before scanning to
improve detection accuracy. This is especially important for keyword-context PII
patterns (e.g., `phone_number: 555-1234`) where the keyword and value may be
separated by document structure rather than appearing as adjacent text.

**Structured scanning replaces flat text scanning for these content types** —
they are not scanned through both paths.

#### JSON (`application/json`)

The proxy recursively flattens nested JSON into context-value fragments before
scanning. Each JSON string value becomes a fragment where the context is the
dot-separated key path and the value is the string content.

| JSON input | Context | Value |
|------------|---------|-------|
| `{"phone_number": "555-1234"}` | `phone_number` | `555-1234` |
| `{"user": {"phone_number": "555-1234"}}` | `user.phone_number` | `555-1234` |
| `{"phones": ["555-1234", "555-5678"]}` | `phones[0]` | `555-1234` |
| `{"users": [{"name": "John"}]}` | `users[0].name` | `John` |

Only string values produce fragments. Numbers, booleans, and nulls are skipped.
Fragment offsets point to the value content bytes within the original JSON body
(excluding surrounding quotes), enabling in-place redaction that preserves valid
JSON structure.

#### CSV (`text/csv`) and TSV (`text/tab-separated-values`)

The proxy parses the header row and then produces a fragment for each data cell,
using the column name as context. Array-style indexing tracks the row:

| CSV input | Context | Value |
|-----------|---------|-------|
| `phone_number,name\n555-1234,John` | `phone_number[0]` | `555-1234` |
| (same, column 2) | `name[0]` | `John` |

If no header row is detected (e.g., all fields are numeric or the file has a
single row), the body falls back to flat text scanning.

Fragment offsets point to the cell content bytes within the original CSV/TSV body,
enabling in-place redaction that preserves the delimiter structure.

#### How Structured Scanning Works

The proxy passes context-value fragments to the `pii` crate via a structured
scanning API (`Scanner::mark_piis_structured`). For each fragment, the crate:

1. **Pattern-only detectors** (e.g., email, SSN regex): scan the value
   independently and offset-adjust results.
2. **Keyword-context detectors**: synthesize `"{context}: {value}"` and run
   through the existing keyword+separator+value detection pipeline. The `:`
   separator matches the existing separator regex. Results are offset-adjusted
   back to document-absolute positions.

   The PII keyword may sit at any position in the key path, not just the
   leaf — e.g. `phone_number.primary` or `email.work`. Because the separator
   regex only accepts a restricted character class (`[\s:.#/\-"=,\]]`) between
   the keyword and the value, any alphabetic segment *between* the keyword and
   the value breaks the match. Synthesizing a single fragment per value is
   therefore insufficient.

   Instead, the scanner iterates over the path, starting from the full
   prefix and progressively dropping the last segment:

   ```
   iter 1:  data.user.phone_number: 555-1234   → exposes `phone_number`
   iter 2:  data.user: 555-1234                 → exposes `user`
   iter 3:  data: 555-1234                      → exposes `data`
   ```

   Each iteration exposes a different segment as the token adjacent to `:`,
   giving the keyword detector a chance to match it. The common case (PII
   keyword at the leaf, e.g. `user.phone_number`) resolves on iteration 1.
   Iteration short-circuits as soon as any match is recorded for the value's
   byte range; since every iteration maps to the same document-absolute
   offsets, dedup is implicit.

   If the synthesized prefix would exceed the detector's lookback window
   (512 bytes), the scanner falls back to per-segment synthesis
   (`"{segment}: {value}"`, one fragment per segment).

This approach reuses all existing detection logic without modification. The
`Detector` trait gains a `mark_piis_structured` method with a default no-op
implementation, so only detectors that benefit from context need to override it.

#### Redaction of Structured Bodies

Redaction operates on the original raw bytes using document-absolute offsets
returned by structured scanning. Both `char` and `type_label` strategies produce
replacements that are safe inside JSON string values and CSV cells:

- JSON: replacement text goes between the existing quote delimiters, preserving
  valid JSON.
- CSV/TSV: replacement text stays within cell boundaries, preserving delimiter
  structure.

### User-Defined PII Definitions

In addition to the built-in PII kinds, operators may supply their own PII
definitions under the `[pii]` section. Each definition is a regex pattern with
an operator-chosen label and optional keyword context. Matches surface with the
operator's label in metrics, block responses, `X-PII-Detected` headers, and
`[LABEL]`-style redaction output — exactly like built-in kinds.

```toml
[[pii.custom]]
label    = "EMPLOYEE_ID"
pattern  = 'EMP-\d{6}'

[[pii.custom]]
label    = "PROJECT_CODE"
pattern  = '[A-Z]{3}-\d{3}'
keywords = ["project code", "proj id"]
country  = "International"   # default
```

| Field      | Required | Description |
|------------|:--------:|-------------|
| `label`    | yes | Label reported on matches. Must be unique and must not collide with any built-in `PiiKind` label. |
| `pattern`  | yes | Regex for the value. Must compile in both the `regex` crate and vectorscan — no backreferences or lookaround. |
| `keywords` | no  | Optional context keywords. When non-empty, a match requires one of the keywords to appear just before the pattern; the reported span covers only the pattern. |
| `country`  | no  | Country scope. Defaults to `International`. Entries whose country is not in the scanner's enabled set are dropped at build time. |

**Behaviour:**

- User definitions run independently of `detect`/`ignore`; those fields apply
  only to built-in kinds. Disabling a user entry is done by removing it from
  config. The literal `"CUSTOM"` is rejected in `detect`/`ignore`.
- Labels propagate to Prometheus `pii_kind` labels, 403 block response
  `kinds` lists, `X-PII-Detected` headers, and `type_label` redaction output.
- Label cardinality is bounded by config size and fully operator-controlled, so
  no cardinality explosion risk in metrics.

**Validation (at startup):**

- Each `label` is non-empty and unique across `[[pii.custom]]` entries.
- No `label` collides with any built-in `PiiKind` label — checked against the
  full namespace, independent of `detect`/`ignore`, so a later change to
  those fields cannot silently introduce a collision.
- Each `pattern` is non-empty. Regex compilation is enforced by the `pii` crate
  at scanner build; failures surface as a startup error.
- Total entry count is capped (default: 64).

**PII safety:** labels are operator-supplied config, not matched values — the
existing rules (no PII in logs/metrics/responses) are unaffected.

---

## Specializations

A *specialization* is an adapter that knows the wire format of a specific
third-party endpoint (Google Analytics 4 `/mp/collect`, Matomo
`/matomo.php`, etc.), parses the payload, hands a curated subset of fields
to the PII scanner, and re-encodes the result. Specializations sit between
the proxy's content-type routing and the scanner.

### Why specializations exist

Flat scanning of opaque, multi-layer-encoded payloads has two failure modes
that specializations fix:

1. **Encoding round-trip correctness.** Naive byte-level redaction inserts
   the label (`[EMAIL]`) into the raw body regardless of surrounding
   encoding. Inside `application/x-www-form-urlencoded`, `[EMAIL]` should
   be `%5BEMAIL%5D`; inside a Matomo `url=` parameter (which is itself a
   URL-encoded URL), the inner email needs to be re-encoded twice. A
   specialization owns the codec, so each layer is re-encoded correctly.
2. **Field-level relevance.** Analytics endpoints carry many opaque IDs
   (`_id`, `cid`, session tokens, hashed identifiers) that look enough
   like PII to produce false positives — and are not PII the operator
   needs to act on. A specialization declares which fields are
   PII-candidates and scans only those, eliminating false positives and
   saving scanner cycles.

### Selection

Specializations are always selected **explicitly**. There is no
auto-detection from path, User-Agent, or payload sniffing — guessing wrong
in either direction (false positive or false negative) is worse than
forcing the operator to declare intent.

| Mode | Selection mechanism |
|------|----------------------|
| HTTP API | Query parameter on `POST /v1/scan` and `POST /v1/redact`: `?specialization=ga4` |
| Reverse Proxy | Optional `specialization = "ga4"` field on each `[[reverse_proxy.routes]]` entry |
| Forward Proxy | (Deferred — same field on the forward-proxy route table introduced in Phase 9) |

Omitting `specialization` preserves today's behaviour: content-type
routing picks flat or structured scanning, and the body is scanned as-is.

### Contract

A specialization owns the full decode → scan → encode loop for the parts
of an HTTP request that the analytics platform itself defines. The proxy
hands it the query string and the body together (a tracker call may put
its payload in either, or split across both, depending on transport); the
specialization returns re-encoded versions of both. The callback shape
means specializations never expose raw byte offsets to the redaction
code, which sidesteps the offset remapping bug class that drove the
design in the first place.

```text
trait Specialization {
    fn name(&self) -> &str;                          // stable id: "ga4", "matomo"

    async fn process(
        query: Option<&str>,                          // raw URL query string
        body: Option<&[u8]>,                          // raw request body
        body_content_type: Option<&str>,
        scan: &ScanHandle,                            // borrows ScannerPool
    ) -> Result<ProcessedRequest, SpecializationError>;
}
```

`ScanHandle` exposes one async method: scan (and optionally redact) a
single field value, returning the matched kinds and the redacted
replacement (when redaction is enabled for the direction). The
specialization calls this once per declared field and stitches the
results back into the re-encoded payload.

`ProcessedRequest` carries:

- the re-encoded query string (`None` when input was `None` or when the
  specialization left it untouched),
- the re-encoded body bytes plus its content-type (same `None` semantics),
- the aggregated `ScanResult` (detected kinds, total match count) for
  metrics and downstream actions.

Recursive decoding is natural in this shape: when Matomo sees `url=` or
`urlref=`, it parses the value as a URL, recursively scans its query
parameters via the same `ScanHandle`, and re-encodes both layers. GA4
applies the same treatment to its `dl` (page_location) and `dr`
(page_referrer) parameters.

#### Boundary with default proxy scanning

The specialization **replaces** the proxy's default scanning of the
query string and the body for the matched request. It does **not**
replace scanning of:

- the URL **path** (governed by `scan.url_path`), or
- request **headers** (governed by `scan.headers`).

Those still go through the proxy's default scanner with their existing
config. Rationale: the analytics platform owns the meaning of its query
parameters and body schema, but it does not own request headers or the
URL path component that routes the request. Path/header PII is an
operator concern that applies equally with or without a specialization.

In response-direction scanning, the specialization is offered the body
only (no query). For tracker endpoints this almost always returns
`UnsupportedContentType` (1x1 `image/gif` or `204`), and processing falls
through to default scanning — see "Response-path note" below.

### Failure handling

When a specialization returns `SpecializationError` (malformed payload,
unexpected shape, unsupported content-type for that specialization):

1. The proxy falls back to the existing scanning path (flat or
   structured, based on content-type) using the raw body. The request
   completes normally.
2. The proxy emits one log line per specialization per minute, at most
   (rate-limited per process). Log message names the specialization and
   the failure category; **never** logs payload contents.
3. `pii_proxy_specialization_errors_total{specialization, reason}` is
   incremented unconditionally on every failure (no rate limit).
4. `on_error` is **not** consulted. Specialization decoding failure is
   recoverable — scanning still happens against raw bytes — so it is
   distinct from a true scanner crash. `on_error` continues to govern
   only scanner failures and limit violations.

### Built-in specializations

The initial set ships with the proxy. Field allowlists are declared in
code, not config — adding a field is a code change with a unit test, so
the documented behaviour cannot drift from deployment to deployment.

The allowlists below are derived from the existing GA4 and Matomo
integration tests under `crates/proxy/tests/`. Every field shown to leak
PII in those tests is allowlisted, so enabling a specialization on a
route that already passes those tests must not regress detection
coverage — only improve precision (fewer false positives on opaque IDs)
and encoding correctness (proper percent-encoding of redaction labels).

#### `ga4`

Targets: `/g/collect` (browser `gtag.js`, short keys in query string or
form-encoded POST body), `/mp/collect` (Measurement Protocol, JSON
body), `/debug/mp/collect`, and `/batch`.

**Query string and `/g/collect` POST form body** (short-key transport):

| Field | Treatment |
|-------|-----------|
| `dl` (page_location) | Recursively decoded as a URL; each inner query parameter scanned individually and re-encoded |
| `dr` (page_referrer) | Same recursive URL treatment as `dl` |
| `dt` (page_title) | Scanned as a flat string |
| `en` (event name) | Scanned (sometimes carries semantic PII) |
| `ep.*` (event params) | Every parameter whose name starts with `ep.` scanned as a flat string |
| `up.*` (user properties) | Same as `ep.*` |
| `cu` (currency), `cm` (campaign-medium), `cs` (campaign-source) | Scanned as flat strings — short, but devs occasionally substitute identifiers |

Skipped: `v` (version), `tid` (measurement ID), `cid` (auto-generated
client ID), `_s`, `_et`, `_p`, `_z`, `gtm`, `sid`, `seg`, `sct` —
opaque/numeric identifiers that match no real PII but generate noise.

Also skipped as **operator-acknowledged channels**: `uid`, `_uip`,
`ip_override`. `uid` is the integrator's chosen user identifier (almost
always an email by design — it's the cross-device join key). `_uip` /
`ip_override` exist for the explicit purpose of overriding the client IP
(server-side gateways, edge anonymisation). Redacting these doesn't
catch a leak, it breaks the integration. The allowlist still scans
every field not designed to carry identifiers, so accidental PII in
`dt`, `en`, `ep.*`, `up.*`, etc. is caught.

**JSON body** (`/mp/collect`, `/debug/mp/collect`, `/batch`):

| Path | Treatment |
|------|-----------|
| `client_id` | Scanned (auto-generated by gtag.js, so an email landing here is always accidental) |
| `user_data.*` (all string leaves: `email_address`, `phone_number`, `address.*`, `sha256_*`) | Scanned. `sha256_*` fields generally won't match, but cost is trivial and protects against unhashed-by-mistake leaks |
| `user_properties.*.value` (all string leaves under each user property) | Scanned |
| `user_location.*` (all string leaves: `city`, `region_id`, `country_id`) | Scanned |
| `events[].name` | Scanned (event names sometimes encode user intent like `"email_capture"`) |
| `events[].params.*` (all string leaves, including `page_title`, `page_location`, `search_term`, `transaction_id`, `coupon`, `affiliation`, `link_url`, `form_destination`, `description`, custom keys) | Scanned. `page_location` and `link_url` are also recursively decoded as URLs |
| `events[].params.items[].*` (all string leaves: `item_id`, `item_name`, `item_brand`, `item_category*`, `item_variant`, `affiliation`, `coupon`, custom strings) | Scanned |

Skipped: numeric/boolean/null leaves anywhere in the tree;
`timestamp_micros`, `message_id`, `non_personalized_ads`, `consent.*`,
and the analytics platform's own diagnostic flags.

Also skipped as **operator-acknowledged channels**: `user_id`,
`ip_override`. Same reasoning as the query-string `uid` / `_uip` /
`ip_override` — these are deliberate identifier / IP-override channels,
not accidental leak vectors. `client_id` is auto-generated and stays
scanned.

**Tier-A skips** (SDK-auto-captured values from a closed vocabulary —
scanning them is overhead with no realistic PII to find):

| Path | Why |
|------|-----|
| `user_location.country_id` | ISO 3166 2-letter code |
| `user_location.region_id` | ISO 3166-2 region code (`"US-OR"`) |
| `events[].params.screen_resolution` | `WxH` metric from `window.screen` |
| `events[].params.language` | IETF tag from `navigator.language` |
| `events[].params.currency` | ISO 4217 3-letter code |

Carve-outs (deliberately stay scanned):
- `user_data.address.country` — `user_data` is the explicit PII envelope, so defense-in-depth catches integrators who substitute the wrong value into the wrong leaf.
- `events[].params.items[].currency` — `items[]` is operator-controlled custom-vocabulary territory.
- `events[].params.<custom>.language` (and similar nested names under custom subtrees) — the skip applies only to the direct child of `events[N].params`, never a nested namespace.

**Batch endpoint (`/batch`).** Treated identically to `/mp/collect` —
the JSON body shape is the same with multiple events in `events[]`.
There is no separate batch-of-bodies wrapper at this endpoint.

#### `matomo`

Targets: `/matomo.php`, `/piwik.php` (legacy alias). Payloads come in
three transports: GET query string, POST form-encoded body, and POST
JSON body for the bulk endpoint (`{"requests": ["?idsite=1&...", ...]}`).

**Query string and form-encoded body fields:**

| Field | Treatment |
|-------|-----------|
| `url` | Recursively decoded as a URL; inner query parameters scanned and re-encoded; path scanned as a flat string for embedded PII (SPA routing leaks) |
| `urlref` | Same recursive URL treatment as `url` |
| `action_name` | Scanned |
| `dimension<N>` (any `dimension` followed by digits) | Scanned |
| `cvar`, `_cvar` | JSON values; parsed and each inner string scanned |
| `e_c`, `e_a`, `e_n`, `e_v` (event category / action / name / value) | Scanned |
| `search`, `search_cat` | Scanned (search-box leaks) |
| `link`, `download` | Recursively decoded as URLs; inner query parameters scanned and re-encoded |
| `ec_id` | Scanned (ecommerce order ID) |
| `ec_items` | JSON array of `[sku, name, category, price, quantity]` tuples; each string element scanned |
| `cra`, `cra_st`, `cra_ru` (crash analytics: message, stack trace, source URI) | Scanned. `cra_ru` recursively decoded as a URL |
| `c_n`, `c_p`, `c_i` (heatmap / form-input content) | Scanned |
| `pv_id`, `gt_ms`, page generation time | Skipped |

Skipped: `idsite`, `rec`, `apiv`, `_id`, `rand`, `revenue`, `idgoal`,
`res`, `h`, `m`, `s`, `fla`, `qt`, `realp`, `wma`, `dir`, `java`,
`cookie`, screen/time/capability metadata, numeric fields.

Also skipped as **operator-acknowledged channels**: `uid`, `cip`. `uid`
is the integrator's chosen user identifier (cross-visit join key —
frequently an email by design), and `cip` is the explicit client-IP
override (server-side gateways, edge anonymisation). Redacting these
doesn't catch a leak, it breaks the integration. The allowlist still
scans every field not designed to carry identifiers (`action_name`,
`dimension*`, `search*`, `e_*`, `c_*`, `cra*`, `ec_*`, `cvar` JSON
leaves, recursive URL fields), so accidental PII is still caught.

**Bulk endpoint (JSON body).** When the body is
`{"requests": [...], "token_auth": "..."}`, the specialization unwraps
each request entry (a query-string starting with `?`) and processes it
through the same field allowlist as a flat tracker call, then re-emits
the bulk JSON envelope with each entry's redacted query string in
place. `token_auth` is not scanned (operator credential, not subject
PII) but is preserved verbatim on output.

#### General rules

Fields outside the allowlist pass through unchanged. Fields inside the
allowlist that contain no PII also pass through unchanged. Adding a
field requires a code change and a corresponding test asserting either
(a) the field is now scanned with PII redacted, or (b) the field is
explicitly skipped with a comment explaining why.

**Response-path note.** Both GA4 and Matomo answer tracking calls with a
1x1 `image/gif` pixel or `204 No Content`. Configuring a route's
specialization therefore applies meaningfully to the *request* direction
only; on the response, the specialization will reject the unfamiliar
content-type and the proxy falls through to its normal content-type
allowlist (which skips images). This is the expected common case — it
does **not** count toward `pii_proxy_specialization_errors_total` and
does **not** emit a warning.

### Metrics

A `specialization` label is added to detection-related counters:

- `pii_proxy_detections_total{specialization, …}` — value is the
  specialization name when active, `"none"` otherwise.
- `pii_proxy_redacted_total{specialization, …}` — same.
- `pii_proxy_specialization_errors_total{specialization, reason}` — new
  counter for decode failures. Distinct from `pii_proxy_errors_total`
  because failure here means *fallback succeeded*, not that the request
  errored.

The `specialization` label is operator-controlled (config + built-in
names), so cardinality is bounded.

### Configuration

```toml
[[reverse_proxy.routes]]
path_prefix = "/mp/collect"
upstream    = "https://www.google-analytics.com"
specialization = "ga4"

[[reverse_proxy.routes]]
path_prefix = "/matomo.php"
upstream    = "http://matomo.internal:8080"
specialization = "matomo"

[[reverse_proxy.routes]]
path_prefix = "/api"
upstream    = "http://backend-api:8080"
# specialization omitted — content-type routing applies as today
```

Validation:

| Rule | Description |
|------|-------------|
| Known name | `specialization` value must match a built-in specialization. Unknown names rejected at startup. |
| Optional | `specialization` is optional; omitting it preserves existing scanning behaviour. |
| API-level | `?specialization=` on `/v1/scan` and `/v1/redact` is validated per-request; unknown name returns `400`. |

### Non-goals (initial release)

- **Auto-detection** of specialization from path or User-Agent.
- **Operator-defined specializations.** Custom decoders are a much bigger
  surface (sandboxing, error model, perf) and are out of scope. Operators
  who need a new format file an issue or contribute a Rust impl.
- **Per-field action overrides** (e.g., "block on `uid`, redact on
  `email`"). The specialization picks which fields are scannable; the
  route's existing action set still governs what happens on detection.

---

## Metrics

Prometheus metrics are **always** updated when PII is detected, regardless of
which actions are configured or which mode is active. There is no separate "warn"
action — observability is built-in and unconditional.

## Actions

Actions define what happens when PII is detected. In reverse proxy and forward
proxy modes, actions are configured **separately for requests and responses**.

| Action     | Behavior                                                                 |
|------------|--------------------------------------------------------------------------|
| **block**  | Return a configurable error response. The request/response is not forwarded. |
| **header** | Add `X-PII-Detected: EMAIL,US_SSN,...` header to the forwarded request/response. |
| **redact** | Replace PII in-place before forwarding. Strategy is configurable.        |

### Request vs Response Actions

In reverse proxy and forward proxy modes, scanning and actions apply to both
directions independently:

- **Request actions**: applied to the incoming request before forwarding upstream.
- **Response actions**: applied to the upstream response before sending to the client.

Each direction has its own `actions` list. An **empty action list disables PII
scanning and actions for that direction entirely**. This allows turning off
inspection for a direction without disabling the mode.

### Default Action Sets

When no actions are explicitly configured, the following defaults apply. These
defaults are also used in the default configuration file.

| Mode / Direction       | Default Actions     |
|------------------------|---------------------|
| Reverse Proxy (request)  | `redact`, `header` |
| Reverse Proxy (response) | `redact`           |
| Forward Proxy (request)  | `redact`           |
| Forward Proxy (response) | `redact`, `header` |

### Block Action

When PII is detected and block is enabled:

- **Blocking a request**: the proxy returns a configurable error response to the
  client. The request is not forwarded to the upstream.
- **Blocking a response**: the proxy discards the upstream response and returns
  a configurable error response to the client instead.

The block response is configurable per direction:

- `block_status` — HTTP status code (default: 403)
- `block_body` — JSON body template. Default: `{"error": "PII detected", "kinds": [...]}`
- `block_headers` — additional headers to include in the block response

### Header Action

The header action adds an `X-PII-Detected` header listing detected PII kinds.
It is applicable for:

- **Reverse proxy requests** — adding PII metadata to forwarded requests so
  upstream services can react to it.
- **Forward proxy responses** — adding PII metadata to responses returned to
  the client so the calling service knows what was detected.

### Action Constraints

- **`block` and `header` are mutually exclusive**: when a request/response is
  blocked, it is not forwarded, so adding a header serves no purpose.
- **`header` can be combined with `redact` or used alone**.
- **`header` is only valid for reverse proxy requests and forward proxy responses.**

### Action Applicability by Mode

| Action     | Reverse Proxy (req) | Reverse Proxy (resp) | Forward Proxy (req) | Forward Proxy (resp) | HTTP API |
|------------|:---:|:---:|:---:|:---:|:---:|
| **block**  | yes | yes | yes | yes | n/a |
| **header** | yes | n/a | n/a | yes | n/a |
| **redact** | yes | yes | yes | yes | yes (via /v1/redact) |

### Action Precedence

When multiple actions are configured for a direction, they are evaluated in
this order:

1. **block** — if enabled and PII detected, short-circuit with error response. No further actions.
2. **redact** — mutate body/URL/headers in-place.
3. **header** — add detection header to the (possibly redacted) request/response.

### Redaction Strategies

| Strategy     | Example                                        |
|--------------|------------------------------------------------|
| `char`       | `john@example.com` -> `*****************`      |
| `type_label` | `john@example.com` -> `[EMAIL]`                |

Configurable `mask_char` when using `char` strategy (default: `*`).

### Error Handling: Fail-Open vs Fail-Close

When the scanner itself errors (crash, timeout, OOM) or a request exceeds
configured limits (body size, unsupported content type), the proxy must decide
whether to allow or block the request. This is a global setting:

- `fail_open` — allow request through (availability over security). Default.
- `fail_close` — block request (security over availability).

A metric `pii_proxy_errors_total{outcome="passed"|"blocked"}` tracks which
path was taken.

---

## HTTP API Endpoints

```
POST /v1/scan        — detect PII in the request body, return matched kinds and count
POST /v1/redact      — detect and redact PII in the request body, return sanitized body
GET  /openapi.json   — OpenAPI 3.x specification for the HTTP API
```

Health and readiness probes are served by the admin port (`/healthz`, `/readyz`)
and are not duplicated here. There is no `/v1/config` endpoint — exposing scanner
configuration on a potentially public surface is unnecessary and a low-value
information leak.

### Request Format

The request body **is** the content to scan — no JSON envelope, no `text` field.
The `Content-Type` header drives body parsing and reuses the same content-type
routing as the proxy modes:

| Content-Type | Scanning |
|--------------|----------|
| `text/plain` | flat text |
| `application/json` | structured (recursive key-path flatten) |
| `text/csv` | structured (header row + cells) |
| `text/tab-separated-values` | structured (header row + cells) |

The `[scan]` allowlist (`content_types`) and `max_body_size` apply identically
to the API. CSV/TSV without a detectable header row falls back to flat text
scanning, matching proxy-mode behaviour.

An optional `?specialization=<name>` query parameter selects a built-in
specialization (see § "Specializations"). When set, the specialization owns
parsing, field selection, and re-encoding; content-type routing is
bypassed. Unknown specialization names return `400`. Omitting the
parameter preserves content-type-based routing.

| Status | When |
|--------|------|
| `400` | Body cannot be parsed as the declared `Content-Type`, or `?specialization=` value is unknown |
| `413` | Body exceeds `max_body_size` |
| `415` | `Content-Type` not in `scan.content_types` |
| `500` | Scanner error and `on_error = "fail_close"` |

Note: unlike proxy modes, a malformed structured body is always rejected with
`400` regardless of `on_error`. The caller explicitly declared the content
type, so silently falling back to flat-text would mask their bug.

### `POST /v1/scan`

Returns detected PII kinds and a match count. The original body is not echoed
back. Response is always JSON:

```json
{
  "detected": true,
  "matches_count": 2,
  "kinds": ["EMAIL", "US_SSN"]
}
```

### `POST /v1/redact`

Returns the body with PII redacted in place. The response `Content-Type`
mirrors the request — JSON in stays valid JSON, CSV stays valid CSV, plain
text stays plain text. Match metadata travels in response headers so the body
retains its original format and is byte-comparable to the input save for the
redacted spans:

| Header | Description |
|--------|-------------|
| `X-PII-Detected` | Comma-separated kinds detected. Omitted when none detected. |
| `X-PII-Redacted-Count` | Total redactions performed. `0` when none. |

### Authentication

The HTTP API does not provide built-in authentication. When exposed publicly,
place it behind an authenticating gateway (ingress controller, API gateway,
service mesh sidecar). Network-level isolation (NetworkPolicy on Kubernetes,
Security Groups on AWS) is the default access control.

### OpenAPI Specification

The HTTP API surface is described by an OpenAPI 3.x specification generated
from the axum route handlers and request/response types using `utoipa` (or
equivalent). Generation happens at build time so the spec cannot drift from
the implementation. The proxy serves the spec at `GET /openapi.json` on the
HTTP API listener.

Interactive documentation is provided by a Swagger UI service in the
project's `docker/docker-compose.yml`. The service points at the proxy's
`/openapi.json` and renders browseable docs (with "Try It Out") on a local
port:

```yaml
services:
  api-docs:
    image: swaggerapi/swagger-ui:latest
    ports:
      - "8088:8080"
    environment:
      SWAGGER_JSON_URL: http://proxy:8083/openapi.json
    depends_on:
      - proxy
```

The Swagger UI service is intended for local development and operator use,
not for production deployment of the API itself.

---

## Configuration

### Format

TOML configuration file, path specified via `--config` CLI argument or
`PII_PROXY_CONFIG` environment variable.

### Mode Activation

Each mode is independently enabled/disabled. At least one mode must be enabled.
The proxy validates at startup that the configuration is consistent and refuses to
start if it is not.

### Configuration Structure

```toml
# --- PII Scanner (shared across all modes) ---
[pii]
countries = ["International", "Us", "Gb"]
languages = ["En"]
# Number of dedicated scanner threads. Each thread owns its own Scanner
# instance to avoid synchronization overhead. Defaults to the number of
# available CPU cores (capped at 4 when total cores <= 8, half of cores
# otherwise).
# scanner_threads = 4
#
# Which PII kinds to detect. Two mutually exclusive options:
#
# detect — closed set: only these PII kinds are detected. All other kinds
#   are ignored. Use this when the proxy should act on a known, fixed set of
#   PII types (e.g. blocking mode). This prevents proxy upgrades that add
#   new PII kinds from unintentionally triggering actions on data that was
#   previously allowed through.
# detect = [
#   # International
#   "Email", "UsPhoneNumber", "CreditCard", "Iban", "PassportNumber",
#   "IpAddress", "MacAddress", "Vin", "SwiftBic", "Imei",
#   "PreciseGeolocation", "PersonName", "AwsAccessKey", "GithubToken",
#   "AwsSecretKey", "DateOfBirth", "BitcoinAddress", "EthereumAddress",
#   # US
#   "UsSsn", "UsItin", "UsPassportNew", "UsEin", "UsAbaRouting",
#   "UsDriversLicense", "UsAlienNumber", "UsUscisReceiptNumber",
#   # GB
#   "GbNino", "GbDrivingLicence", "GbNhsNumber", "GbUtr", "GbSortCode",
#   "GbPhoneNumber", "GbZaPassportNumber", "GbPostcode",
#   # AU
#   "AuTfn", "AuMedicare", "AuPhoneNumber", "AuPassportNumber",
#   "AuBankAccount", "AuDriversLicense", "AuAbn",
#   # NZ
#   "NzIrdNumber", "NzNhiNumber", "NzDriverLicence", "NzPhoneNumber",
#   "NzPassportNumber",
#   # CA
#   "CaSin", "CaOhip", "CaPassportNumber", "CaPostalCode", "CaBankAccount",
#   # IE
#   "IePpsn", "IeDriverNumber", "IePhoneNumber", "IePassportNumber",
#   # ZA
#   "ZaId", "ZaTaxReference", "ZaPhoneNumber", "ZaDriversLicense",
#   "ZaPostalCode",
#   # FR
#   "FrNir", "FrSiret", "FrSiren", "FrPassportNumber", "FrCni",
#   "FrDriversLicense", "FrPhoneNumber", "FrPostalCode", "FrNif",
#   "FrChAddress", "FrChBoitePostale",
#   # DE
#   "DeSteuerId", "DePersonalausweis", "DePhoneNumber", "DePostalCode",
#   "DeAtChAddress", "DeAtChPostfach", "DePackstation",
#   # AT
#   "AtSvnr", "AtPhoneNumber", "AtPostalCode",
#   # CH
#   "ChAhv", "ChPhoneNumber", "ChPostalCode",
# ]
#
# ignore — open set: all PII kinds are detected except those listed. Use
#   this when you want broad coverage and are comfortable with new PII kinds
#   being automatically detected after a proxy upgrade.
# ignore = ["IpAddress"]
#
# NOTE: "Custom" is reserved — it is the marker kind for user-defined PII
# definitions (see `[[pii.custom]]` below) and must not appear in detect/ignore.

# User-defined PII — operator-supplied regex definitions with chosen labels.
# See "User-Defined PII Definitions" above. Runs independently of detect/ignore.
# [[pii.custom]]
# label    = "EMPLOYEE_ID"
# pattern  = 'EMP-\d{6}'
#
# [[pii.custom]]
# label    = "PROJECT_CODE"
# pattern  = '[A-Z]{3}-\d{3}'
# keywords = ["project code", "proj id"]
# country  = "International"

# --- Scan settings (shared defaults, overridable per route in reverse proxy) ---
[scan]
max_body_size = 1_048_576  # 1 MB, in bytes
content_types = [
    "application/json",
    "text/plain",
    "text/html",
    "application/x-www-form-urlencoded",
    "text/csv",
    "text/tab-separated-values",
]
url_path = true
query_params = true
headers = ["Authorization", "Cookie", "X-Api-Key"]
body = true
on_error = "fail_open"  # "fail_open" | "fail_close"

# --- Standalone Reverse Proxy mode ---
[reverse_proxy]
enabled = false
listen = "0.0.0.0:8082"

# Request/response actions for all routes (not overridable per route — use
# separate proxy instances for different action policies)
[reverse_proxy.request]
actions = ["redact", "header"]
redact_strategy = "type_label"

[reverse_proxy.response]
actions = ["redact"]
redact_strategy = "type_label"

[reverse_proxy.tls]
enabled = false
cert_path = "/tls/tls.crt"
key_path = "/tls/tls.key"

# Routes only define routing and optional scan overrides. Actions are set at
# the mode level above and apply uniformly to all routes. For different action
# policies, deploy separate proxy instances.
[[reverse_proxy.routes]]
path_prefix = "/api"
upstream = "http://backend-api:8080"
# Per-route scan overrides (fully replaces defaults, no merging)
# [reverse_proxy.routes.scan]
# body = true
# headers = ["Authorization"]

[[reverse_proxy.routes]]
path_prefix = "/payments"
upstream = "http://payments-svc:9090"

# --- Standalone Forward Proxy mode ---
[forward_proxy]
enabled = true
listen = "0.0.0.0:8084"

[forward_proxy.request]
actions = ["redact"]
redact_strategy = "type_label"
# redact_strategy = "char"
# mask_char = "*"

[forward_proxy.response]
actions = ["redact", "header"]
redact_strategy = "type_label"

[forward_proxy.tls]
# TLS certificate used when terminating client HTTPS connections
cert_path = "/tls/tls.crt"
key_path = "/tls/tls.key"

# --- HTTP API mode ---
[http_api]
enabled = true
listen = "0.0.0.0:8083"
redact_strategy = "type_label"

# --- Admin ---
[admin]
listen = "127.0.0.1:9090"  # localhost-only by default
metrics_path = "/metrics"
health_path = "/healthz"
ready_path = "/readyz"
```

### Configuration Validation Rules

The proxy validates the entire configuration at startup and exits with a clear
error message if any rule is violated.

#### Global rules

| Rule | Description |
|------|-------------|
| At least one mode enabled | At least one of `reverse_proxy`, `forward_proxy`, `http_api` must be enabled |
| No port conflicts | All enabled listeners must bind to different `host:port` combinations |
| PII scanner valid | `detect` and `ignore` are mutually exclusive (enforced by `pii` crate) |
| Countries/PII kinds consistent | All PII kinds in `detect` must be reachable from specified countries (enforced by `pii` crate) |
| Scanner threads valid | `scanner_threads` must be >= 1 if specified |
| User-defined PII labels | Non-empty, unique across `[[pii.custom]]`, and non-colliding with built-in `PiiKind` labels (full namespace) |
| User-defined PII patterns | Non-empty; regex compilation enforced by `pii` crate at build |
| User-defined PII cap | Total `[[pii.custom]]` entries <= 64 |
| `CUSTOM` reserved | `"CUSTOM"` must not appear in `detect` or `ignore` |

#### Per-mode action validation

| Rule | Description |
|------|-------------|
| HTTP API: no `block`/`header` | `block` and `header` actions have no meaning in HTTP API mode — it always returns scan/redact results |
| `block` and `header` mutually exclusive | `block` and `header` cannot both appear in the same direction's action list |
| `header` direction restriction | `header` is only valid in reverse proxy request actions and forward proxy response actions |
| `redact` requires strategy | If `redact` is in actions, `redact_strategy` must be specified |
| `char` strategy requires `mask_char` | If `redact_strategy` is `char`, `mask_char` must be specified |

#### Reverse proxy route validation

| Rule | Description |
|------|-------------|
| No overlapping path prefixes | Two routes must not have the same `path_prefix` |
| Valid upstream URLs | Each `upstream` must be a valid URL |
| Per-route scan override | If a route specifies `scan`, it fully replaces the defaults (no merging) |
| No per-route actions | Routes must not define `request` or `response` action overrides — actions are set at the mode level only |
| Known specialization | If a route specifies `specialization`, its value must match a built-in specialization name |

### Pre-flight Validation

Config validation must be available as a standalone, offline check so that bad
configs are caught in CI/CD before they reach production. Silent regressions
(e.g. a typo in a `[[pii.custom]]` regex) must not be discovered only when a
pod fails to start.

The proxy exposes a `--validate` option that takes the config path directly
and switches into a validate-only mode:

```
pii-proxy --validate /etc/pii-proxy/config.toml
```

`--validate` and `--config` are mutually exclusive; exactly one must be
provided. This avoids the awkwardness of requiring both flags together when
one always implies the other.

Behaviour:

1. Load and parse the TOML file.
2. Run the full `AppConfig::validate()` routine (global rules, per-mode action
   rules, route rules, user-defined PII rules).
3. Build a `pii::Scanner` via `build_scanner`. This exercises the `regex`
   crate *and* vectorscan compilation identically to the startup path, so a
   successful validation guarantees the scanner will build at runtime.
4. Exit `0` on success. On failure, print a structured diagnostic identifying
   the offending rule or entry and exit non-zero.

In validate mode no listeners are bound, no scanner threads are spawned, no
TLS material is opened, and no upstream clients are created.

**Excluded from `--validate`** (environment-specific, left to startup):

- Listen-address availability
- TLS cert/key file contents (only that the path field is present)
- Upstream reachability
- Filesystem permissions on metric/log sinks

A separate `--check-env` flag may be added later if these checks become
useful to run out-of-band.

**Intentional non-goal: partial start.** The proxy does not support a "skip
invalid entries and continue" mode. Silently dropping declared PII definitions
is a security regression — strict startup failure combined with pre-flight
validation is the correct pair.

**Integration targets:**

- CI pipeline on the config repository (run on every PR).
- Git pre-commit hook for operators editing configs locally.
- GitOps controller pre-sync hook (Flux / ArgoCD).
- Kubernetes `ValidatingWebhookConfiguration` that shells out to the binary.

### Configuration by Mode — What Applies Where

| Setting | Reverse Proxy | Forward Proxy | HTTP API | Admin |
|---------|:---:|:---:|:---:|:---:|
| `pii.*` | yes | yes | yes | n/a |
| `scan.*` (defaults) | yes (overridable per route) | yes | `content_types`, `max_body_size`, body only | n/a |
| `on_error` | yes | yes | yes (scanner errors only — body parse failures always 400) | n/a |
| `request.*` | yes (mode level only) | yes | n/a | n/a |
| `response.*` | yes (mode level only) | yes | n/a | n/a |
| `redact_strategy` | yes (in direction sub-tables) | yes (in direction sub-tables) | yes | n/a |
| `routes` | yes | n/a | n/a | n/a |
| `tls` | yes | yes | no | no |
| `metrics_path` | n/a | n/a | n/a | yes |

---

## Prometheus Metrics

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `pii_proxy_detections_total` | counter | `pii_kind`, `mode`, `route`, `direction`, `specialization` | PII detections (always incremented, regardless of actions) |
| `pii_proxy_blocked_total` | counter | `mode`, `route`, `direction` | Blocked requests/responses |
| `pii_proxy_redacted_total` | counter | `pii_kind`, `mode`, `route`, `direction`, `specialization` | Redacted PII instances |
| `pii_proxy_requests_total` | counter | `mode`, `route`, `method`, `status` | Total requests |
| `pii_proxy_request_duration_seconds` | histogram | `mode`, `route` | Processing time |
| `pii_proxy_errors_total` | counter | `outcome` (`passed`, `blocked`), `reason` | Scanner failures, body size exceeded, and other errors with fail-open/close outcome |
| `pii_proxy_specialization_errors_total` | counter | `specialization`, `reason` | Specialization decoder failures (fallback to raw scan succeeded) |

The `mode` label is one of: `reverse_proxy`, `forward_proxy`, `http_api`.
The `route` label is the path prefix for reverse proxy, or `global` for other modes.
The `direction` label is `request` or `response`.
The `specialization` label is the active specialization name (e.g. `ga4`, `matomo`) or `none` when no specialization is selected.

---

## Security

### Port Separation

Data plane and admin run on separate ports. In Kubernetes, they are exposed as
separate Services with independent NetworkPolicies.

```
pii-proxy         (ClusterIP) — ports 8082, 8083, 8084
pii-proxy-admin   (ClusterIP) — port 9090
```

The admin port binds to `127.0.0.1` by default. In Kubernetes, kubelet accesses
pods directly for liveness/readiness probes, so this works without exposing the
admin service externally. Override to `0.0.0.0` only when Prometheus needs to
scrape from a separate pod (in which case NetworkPolicy restricts access to the
monitoring namespace).
Fa
### PII Data Handling

| Rule | Detail |
|------|--------|
| No PII in logs | Log PII kinds and match counts, never matched text |
| No PII in metrics | Metric labels use PII kind names, never PII values |
| No PII in error responses | 403 responses list detected PII kinds, never the values |
| Memory hygiene | Drop request body buffers promptly after scanning, avoid unnecessary copies |

### Container Hardening

```yaml
securityContext:
  runAsNonRoot: true
  runAsUser: 65534
  readOnlyRootFilesystem: true
  allowPrivilegeEscalation: false
  capabilities:
    drop: [ALL]
```

### Network Access Control (Kubernetes)

The Helm chart bundles NetworkPolicy resources:

- `pii-proxy`: ingress only from authorized client namespaces
- `pii-proxy-admin`: ingress only from monitoring namespace

### Authentication — Deferred

Authentication support is deferred. Access control relies on network-level
isolation (NetworkPolicy in Kubernetes, Security Groups on AWS).

### Forward Proxy TLS

The forward proxy terminates client TLS and establishes new TLS connections to
destination servers. This requires a CA certificate that clients trust. In
Kubernetes, this is typically distributed via ConfigMap/Secret mounted into client
containers.
