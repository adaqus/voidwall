# PII Proxy — Design Document

## Overview

A multi-mode HTTP proxy that inspects HTTP traffic for sensitive data (PII) using
the `pii` crate. Depending on configuration, the proxy can block, redact, or add
headers for detected PII. Prometheus metrics are always updated when PII is
detected, regardless of action configuration.

It is not an ingress controller. It may integrate with existing ingress controllers
(NGINX, HAProxy, Envoy/Istio) and can also operate as a standalone reverse/forward
proxy or a REST API microservice.

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

### 4. REST API Mode

Internal microservice exposing PII scanning and redaction as HTTP endpoints. Other
services in the cluster call it to check or sanitize text.

- Capabilities: **scan (detect), redact**
- Use case: application-level integration, pre-processing pipelines, batch scanning

---

## Architecture

```
                    Single Binary / Container
  ┌─────────────────────────────────────────────────────────┐
  │                                                         │
  │  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐  │
  │  │ Reverse Proxy │  │ Forward      │  │ REST API     │  │
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

| Scan target         | Reverse Proxy | Forward Proxy | REST API |
|----------------------|:---:|:---:|:---:|
| URL path             | request | request | n/a |
| Query parameters     | request | request | n/a |
| Request headers      | request | request | n/a |
| Request body         | request | request | yes (text field) |
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

| Action     | Reverse Proxy (req) | Reverse Proxy (resp) | Forward Proxy (req) | Forward Proxy (resp) | REST API |
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

## REST API Endpoints

```
POST /v1/scan     — detect PII, return matched PII kinds and match count
POST /v1/redact   — detect and redact PII, return sanitized text
GET  /v1/health   — health check (identical to admin /healthz)
GET  /v1/config   — current scanner configuration (PII kinds, countries, languages)
```

### Response Design

`/v1/scan` returns detected PII kinds and count, not positions:

```json
{
  "detected": true,
  "matches_count": 2,
  "kinds": ["EMAIL", "US_SSN"]
}
```

`/v1/redact` returns sanitized text and match metadata:

```json
{
  "text": "Email me at [EMAIL], SSN [US_SSN]",
  "redacted_count": 2,
  "kinds": ["EMAIL", "US_SSN"]
}
```

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
#   "Email", "PhoneNumber", "CreditCard", "Iban", "PassportNumber",
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

# --- REST API mode ---
[rest_api]
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
| At least one mode enabled | At least one of `reverse_proxy`, `forward_proxy`, `rest_api` must be enabled |
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
| REST API: no `block`/`header` | `block` and `header` actions have no meaning in REST API mode — it always returns scan/redact results |
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

| Setting | Reverse Proxy | Forward Proxy | REST API | Admin |
|---------|:---:|:---:|:---:|:---:|
| `pii.*` | yes | yes | yes | n/a |
| `scan.*` (defaults) | yes (overridable per route) | yes | body only | n/a |
| `on_error` | yes | yes | yes | n/a |
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
| `pii_proxy_detections_total` | counter | `pii_kind`, `mode`, `route`, `direction` | PII detections (always incremented, regardless of actions) |
| `pii_proxy_blocked_total` | counter | `mode`, `route`, `direction` | Blocked requests/responses |
| `pii_proxy_redacted_total` | counter | `pii_kind`, `mode`, `route`, `direction` | Redacted PII instances |
| `pii_proxy_requests_total` | counter | `mode`, `route`, `method`, `status` | Total requests |
| `pii_proxy_request_duration_seconds` | histogram | `mode`, `route` | Processing time |
| `pii_proxy_errors_total` | counter | `outcome` (`passed`, `blocked`), `reason` | Scanner failures, body size exceeded, and other errors with fail-open/close outcome |

The `mode` label is one of: `reverse_proxy`, `forward_proxy`, `rest_api`.
The `route` label is the path prefix for reverse proxy, or `global` for other modes.
The `direction` label is `request` or `response`.

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
