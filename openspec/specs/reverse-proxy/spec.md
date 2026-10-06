## Purpose

The reverse proxy accepts HTTP requests, inspects them for PII, applies the configured
actions, and forwards them to a configured upstream. It inspects the upstream response
on the way back.

## Requirements

### Requirement: Routing matches the longest path prefix

The proxy SHALL select the route whose `path_prefix` is the longest prefix of the
request path. It SHALL return 404 when no route matches. Routing SHALL use the path
only. The proxy SHALL NOT route on the Host header.

#### Scenario: Two prefixes both match

- **WHEN** the path matches `/api` and `/api/v2`, and the request path starts with
  `/api/v2`
- **THEN** the proxy selects the `/api/v2` route

#### Scenario: No route matches

- **WHEN** the request path matches no configured prefix
- **THEN** the proxy returns 404 and records the request metric with status 404

### Requirement: One pooled client per upstream

The proxy SHALL build one pooling HTTP client per distinct upstream. The idle timeout
SHALL be 30 seconds. Two routes naming the same upstream SHALL share one client.

#### Scenario: Two routes share an upstream

- **WHEN** two routes name the same upstream
- **THEN** the proxy builds one client and both routes use it

### Requirement: The request body is buffered before the scan

The proxy SHALL buffer the request body up to the route's `max_body_size` before it
scans. An oversize body SHALL follow the `on_error` policy.

#### Scenario: Body fits the limit

- **WHEN** the request body is within `max_body_size`
- **THEN** the proxy buffers it and scans it

### Requirement: Request and response are inspected independently

The proxy SHALL inspect the incoming request when `request.scan` is true, and the
upstream response when `response.scan` is true. `scan = false` for a direction SHALL
disable inspection for that direction and SHALL leave the other direction untouched.

#### Scenario: Request only

- **WHEN** `request.scan` is true and `response.scan` is false
- **THEN** the proxy inspects the request and forwards the upstream response untouched

#### Scenario: Response only

- **WHEN** `request.scan` is false and `response.scan` is true
- **THEN** the proxy forwards the request untouched and inspects the upstream response

### Requirement: Body scanning respects the content type and the target flags

The proxy SHALL scan a body only when at least one guard selected for the route admits
the body in its surface, the body is non-empty, and the content type appears in the
top-level `content_types` list.

#### Scenario: Content type is outside the allowlist

- **WHEN** a request body carries a content type outside `content_types`
- **THEN** the proxy does not scan the body

#### Scenario: Body is empty

- **WHEN** a request carries no body bytes
- **THEN** the proxy does not scan the body

#### Scenario: No selected guard admits the body

- **WHEN** every guard selected for the route sets `surface.body` to false
- **THEN** the proxy does not scan the body

### Requirement: The URL path, the query, and listed headers are scannable

The proxy SHALL scan the URL path and the query string for a guard whose surface admits
them, and SHALL scan the value of every header the route names. A unit no selected guard
admits SHALL NOT be built, and a header the route does not name SHALL NOT be built.

#### Scenario: PII sits in the query string

- **WHEN** a selected guard sets `surface.query_params` to true and the query holds an
  email address
- **THEN** the proxy detects it and blocks the request

#### Scenario: PII sits in a header the route names

- **WHEN** a route names a header and a request carries an email address in it
- **THEN** the proxy detects it and blocks the request

#### Scenario: Two guards admit different surfaces

- **WHEN** one selected guard admits the body only and another admits the query only
- **THEN** each guard is called with its own units and neither sees the other's

### Requirement: A detection blocks with a fixed 403

When a guard reports a finding, the proxy SHALL stop the message and SHALL answer 403.
The body SHALL be a JSON object holding an `error` field and a `kinds` array. The `error`
field SHALL be exactly `content blocked`, whatever guard reported the finding. The array
SHALL list the detected kind names of every guard sorted, holding each kind once, and
SHALL carry no matched text. The status, the body, and the response headers SHALL NOT be
configurable. The proxy SHALL increment `voidwall_blocked_total` once and
`voidwall_detections_total` once per guard that reported a finding. When the `pii` guard
reported a finding, the proxy SHALL also increment `voidwall_pii_blocked_total` once and
the PII detection counter once per kind that guard found.

#### Scenario: PII is found in a request

- **WHEN** a scan of the incoming request detects PII
- **THEN** the proxy answers 403 and does not reach the upstream

#### Scenario: PII is found in a response

- **WHEN** a scan of the upstream response detects PII
- **THEN** the proxy answers 403 and the upstream body does not reach the client

#### Scenario: Three kinds are found

- **WHEN** a scan detects three kinds
- **THEN** the `kinds` array names them sorted, each once, with no matched value

#### Scenario: A block increments the guard metrics

- **WHEN** the PII guard's finding blocks a request
- **THEN** `voidwall_blocked_total` increments by one and `voidwall_detections_total`
  increments by one with `guard="pii"`

#### Scenario: A model guard detects an injection

- **WHEN** a model guard with `labels = ["PROMPT_INJECTION"]` scores a request body at or
  above its threshold
- **THEN** the proxy answers 403 with `error` `content blocked` and `kinds`
  `["PROMPT_INJECTION"]`, and does not reach the upstream
- **AND** `voidwall_detections_total` increments with that guard's name, and
  `voidwall_pii_blocked_total` does not increment

### Requirement: A clean message is forwarded unchanged

When a scan detects nothing, the proxy SHALL forward the message unchanged and SHALL
increment no detection metric. The proxy SHALL NOT rewrite a body, a URL path, a query
string, or a header value at any point.

#### Scenario: A clean request

- **WHEN** a scan of the request detects nothing
- **THEN** the request reaches the upstream as it arrived, minus the hop-by-hop headers

#### Scenario: A clean response

- **WHEN** a scan of the upstream response detects nothing
- **THEN** the client receives the upstream body unchanged

### Requirement: Hop-by-hop headers are stripped

The proxy SHALL remove the hop-by-hop headers before it forwards: `connection`,
`keep-alive`, `proxy-authenticate`, `proxy-authorization`, `te`, `trailers`,
`transfer-encoding`, and `upgrade`. The comparison SHALL ignore case.

#### Scenario: Client sends a hop-by-hop header

- **WHEN** a request carries `Transfer-Encoding`
- **THEN** the forwarded request does not carry it

### Requirement: Every request records metrics

The proxy SHALL record a request metric carrying the mode, the route, the method, and
the status. It SHALL observe the request duration per mode and route.

#### Scenario: A request completes

- **WHEN** the proxy answers a request
- **THEN** it increments the request counter and observes the duration

### Requirement: The proxy serves plain HTTP only

The reverse proxy listener SHALL accept plain HTTP. TLS termination is not built. The
`tls` table parses and validates, and nothing reads it.

#### Scenario: TLS is enabled in the config

- **WHEN** `reverse_proxy.tls.enabled` is true
- **THEN** the listener still accepts plain HTTP, because the TLS path does not exist

### Requirement: The proxy shuts down gracefully

The proxy SHALL stop when the shutdown token is cancelled, and SHALL drain the requests
in flight.

#### Scenario: Shutdown signal arrives

- **WHEN** the cancellation token is triggered
- **THEN** the listener stops accepting connections and the in-flight requests finish

### Requirement: A blocked error names the party at fault

When the `on_error` policy blocks a message, the reverse proxy SHALL answer a status that
names the party at fault.

- A body larger than `max_body_size` SHALL answer 413.
- A unit that needs more windows than a model guard's window limit SHALL answer 413.
- A body that fails to parse SHALL answer 400. The client declared the content type and
  sent bytes that do not match it.
- A scanner failure SHALL answer 500. The scanner belongs to the proxy. A model guard's
  inference failure SHALL count as a scanner failure.

The proxy SHALL reserve 502 for a failure of the upstream itself. Each of these response
bodies SHALL be a JSON object holding an `error` field, and SHALL carry no matched text
and no fragment of the message that was scanned.

The window-limit 413 body SHALL be exactly
`{"error":"tokenized content too long to scan"}`. The 500 body SHALL be exactly
`{"error":"internal error"}`. Every 502 body SHALL be
exactly `{"error":"upstream error"}`. Neither body SHALL carry a detail of the failure.

#### Scenario: Oversize body under fail_close

- **WHEN** a request body is larger than `max_body_size` and `on_error` is `fail_close`
- **THEN** the proxy answers 413 and does not forward the request

#### Scenario: Window limit under fail_close

- **WHEN** a model guard needs more windows for a unit than its window limit, no guard
  reports a finding, and `on_error` is `fail_close`
- **THEN** the proxy answers 413 and does not forward the message
- **AND** the body is exactly `{"error":"tokenized content too long to scan"}`

#### Scenario: Window limit under fail_open

- **WHEN** a model guard needs more windows for a unit than its window limit, no guard
  reports a finding, and `on_error` is `fail_open`
- **THEN** the proxy forwards the message

#### Scenario: Malformed body under fail_close

- **WHEN** a request declares a JSON content type, its body does not parse, and `on_error`
  is `fail_close`
- **THEN** the proxy answers 400 and does not forward the request

#### Scenario: Scanner failure under fail_close

- **WHEN** the scanner returns an error and `on_error` is `fail_close`
- **THEN** the proxy answers 500 and does not forward the request
- **AND** the body is exactly `{"error":"internal error"}`

#### Scenario: Model inference failure under fail_close

- **WHEN** a model guard's inference fails, no guard reports a finding, and `on_error` is
  `fail_close`
- **THEN** the proxy answers 500 with the body `{"error":"internal error"}`, and the log
  names the guard

#### Scenario: The upstream cannot be reached

- **WHEN** the proxy forwards a clean request and the upstream connection fails
- **THEN** the proxy answers 502
- **AND** the body is exactly `{"error":"upstream error"}`

#### Scenario: An error body carries no scanned text

- **WHEN** the proxy answers 400, 413, or 500 for a message that held a detected value
- **THEN** the body names the error only and carries no matched text

### Requirement: A block from another guard wins over a guard error

When one guard fails and another guard reports a finding for the same message, the proxy
SHALL answer the fixed 403 for the detection, under `fail_open` and under `fail_close`
alike. The `on_error` policy SHALL apply only when no guard reports a finding.

When the engine receives the guard error before the block, the proxy SHALL still write
the error to the log, and SHALL still increment `voidwall_errors_total` for it. A guard
still running when the block arrives is abandoned, so an error it would have returned is
neither logged nor counted.

#### Scenario: A guard fails and another guard detects under fail_open

- **WHEN** one guard fails, another guard reports a finding, and `on_error` is `fail_open`
- **THEN** the proxy answers 403 naming the detected kind and does not forward the message

#### Scenario: A guard error that arrives before the block is counted

- **WHEN** one guard fails and another guard then reports a finding
- **THEN** the proxy answers 403, logs the error, and increments `voidwall_errors_total`
  with `outcome="blocked"`

#### Scenario: A guard fails and another guard detects under fail_close

- **WHEN** one guard fails, another guard reports a finding, and `on_error` is `fail_close`
- **THEN** the proxy answers 403 naming the detected kind, not 500

#### Scenario: A guard fails and no guard detects under fail_open

- **WHEN** one guard fails, no guard reports a finding, and `on_error` is `fail_open`
- **THEN** the proxy forwards the message

#### Scenario: A guard fails and no guard detects under fail_close

- **WHEN** one guard fails, no guard reports a finding, and `on_error` is `fail_close`
- **THEN** the proxy answers 500 with the body `{"error":"internal error"}`
