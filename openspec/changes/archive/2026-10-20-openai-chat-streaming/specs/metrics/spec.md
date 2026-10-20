## RENAMED Requirements

- FROM: `### Requirement: The proxy publishes eight application metrics`
- TO: `### Requirement: The proxy publishes nine application metrics`

- FROM: `### Requirement: Unscannable content and streams carry their own reasons`
- TO: `### Requirement: Unscannable content carries its own reason`

- FROM: `### Requirement: Upstream limit errors carry their own reasons`
- TO: `### Requirement: Upstream errors carry their own reasons`

## MODIFIED Requirements

### Requirement: Upstream errors carry their own reasons

An upstream timeout SHALL increment `voidwall_errors_total` with `outcome="blocked"` and
`reason="upstream_timeout"`. An upstream response body larger than `max_body_size` under
response scan SHALL increment it with `outcome="blocked"` and
`reason="response_too_large"`. An upstream failure SHALL increment it with
`outcome="blocked"` and `reason="upstream_error"`: a connection to the upstream that
fails before the response headers, a read of a buffered response body that fails, and a
stream on an `openai-chat` route under response scan, in hold-back or buffer mode, whose
upstream connection fails before the body ends.

#### Scenario: The upstream times out

- **WHEN** the reverse proxy answers 504 because the upstream exchange timed out
- **THEN** `voidwall_errors_total` increments with `outcome="blocked"` and
  `reason="upstream_timeout"`

#### Scenario: The upstream response is too large

- **WHEN** the reverse proxy answers 502 because the upstream response body is larger
  than `max_body_size`
- **THEN** `voidwall_errors_total` increments with `outcome="blocked"` and
  `reason="response_too_large"`

#### Scenario: The upstream cannot be reached

- **WHEN** the reverse proxy answers 502 because the connection to the upstream fails
- **THEN** `voidwall_errors_total` increments with `outcome="blocked"` and
  `reason="upstream_error"`

#### Scenario: The upstream response body fails

- **WHEN** response scan is on and the upstream connection fails while the proxy reads a
  buffered response body
- **THEN** the proxy answers 502 and `voidwall_errors_total` increments with
  `outcome="blocked"` and `reason="upstream_error"`

#### Scenario: The upstream stream fails

- **WHEN** the upstream connection fails before a stream on an `openai-chat` route ends
- **THEN** `voidwall_errors_total` increments with `outcome="blocked"` and
  `reason="upstream_error"`

### Requirement: The proxy publishes nine application metrics

The proxy SHALL register these metric families:

- `voidwall_pii_detections_total`, a counter labelled `pii_kind`, `mode`, `route`, and
  `direction`.
- `voidwall_pii_blocked_total`, a counter labelled `mode`, `route`, and `direction`.
- `voidwall_detections_total`, a counter labelled `guard`, `mode`, `route`, and
  `direction`.
- `voidwall_blocked_total`, a counter labelled `mode`, `route`, and `direction`.
- `voidwall_requests_total`, a counter labelled `mode`, `route`, `method`, and
  `status`.
- `voidwall_request_duration_seconds`, a histogram labelled `mode` and `route`.
- `voidwall_errors_total`, a counter labelled `outcome` and `reason`.
- `voidwall_unscanned_total`, a counter labelled `mode`, `route`, `direction`, and
  `reason`.
- `voidwall_streams_cut_total`, a counter labelled `mode`, `route`, and `reason`.

A family that names a detection tier SHALL carry that tier in its name. A family that
describes the engine as a whole SHALL NOT name a tier.

#### Scenario: Prometheus scrapes a running proxy

- **WHEN** a client scrapes the admin metrics endpoint
- **THEN** the response carries these nine families with these label sets

#### Scenario: A retired family is absent

- **WHEN** a client scrapes the admin metrics endpoint
- **THEN** no family named `voidwall_specialization_errors_total` or
  `voidwall_pii_redacted_total` appears

#### Scenario: The guard families carry no kind label

- **WHEN** the proxy increments `voidwall_detections_total` or `voidwall_blocked_total`
- **THEN** the sample carries no `pii_kind` label and no other kind label

### Requirement: The blocked counter increments once per message the reverse proxy stops

The reverse proxy SHALL increment `voidwall_blocked_total` once for each message it
stops. A message is stopped when the proxy answers a detection with the route's block
(403, or 400 on a route with `format = "openai-chat"`), or when an error answers instead
of forwarding: under `on_error = "fail_close"`, 413 for an oversize body or a window
limit, 400 for a body that does not parse as its declared content type, 422 for
unscannable content, or 500 for a scanner failure; and, on an `openai-chat` route, 400
for a request that is not a Chat Completions request, under either `on_error`. A stream
that the proxy stops for one of these causes after its first byte SHALL count as a
stopped message. The counter SHALL carry the message's `mode`, `route`, and
`direction`.

The counter SHALL increment once for a message however many guards reported findings
in it, and when a guard error and a detection come together.

A message that passes under `on_error = "fail_open"`, a 502 for an upstream failure, a
stream stopped by the idle timeout, the size limit, or an upstream failure, and every
answer of `/v1/scan` SHALL NOT increment the counter.

`voidwall_pii_blocked_total` SHALL count only a block for a detection in which the `pii`
guard reported a finding.

#### Scenario: A detection blocks a request

- **WHEN** a PII detection blocks a request on the reverse proxy
- **THEN** `voidwall_blocked_total` and `voidwall_pii_blocked_total` each increment by
  one with `direction="request"`

#### Scenario: A detection blocks a request on an openai-chat route

- **WHEN** a PII detection on a route with `format = "openai-chat"` answers 400
- **THEN** `voidwall_blocked_total` and `voidwall_pii_blocked_total` each increment by
  one

#### Scenario: Only a model guard detects

- **WHEN** only a model guard reports a finding and the reverse proxy answers 403
- **THEN** `voidwall_blocked_total` increments by one and `voidwall_pii_blocked_total`
  does not increment

#### Scenario: Two guards report findings in one blocked message

- **WHEN** two guards each report a finding in one request that the reverse proxy blocks
- **THEN** `voidwall_blocked_total` increments by one

#### Scenario: An oversize body under fail_close

- **WHEN** a request body is oversize and `on_error` is `fail_close`
- **THEN** the proxy answers 413, `voidwall_blocked_total` increments by one with
  `direction="request"`, and `voidwall_pii_blocked_total` does not increment

#### Scenario: A window limit under fail_close

- **WHEN** a model guard hits its window limit, no guard reports a finding, and
  `on_error` is `fail_close`
- **THEN** the proxy answers 413 and `voidwall_blocked_total` increments by one

#### Scenario: An unparseable body under fail_close

- **WHEN** a response body does not parse as its declared content type and `on_error` is
  `fail_close`
- **THEN** the proxy answers 400, and `voidwall_blocked_total` increments by one with
  `direction="response"`

#### Scenario: A stream under fail_close

- **WHEN** a request with `"stream": true` reaches a route with
  `format = "openai-chat"`, response scan is on, `on_error` is `fail_close`, and a PII
  detection stops the stream after it has sent bytes to the client
- **THEN** `voidwall_blocked_total` and `voidwall_pii_blocked_total` each increment by
  one with `direction="response"`

#### Scenario: An idle stream

- **WHEN** the idle timeout stops a stream
- **THEN** `voidwall_blocked_total` does not increment

#### Scenario: A scanner failure under fail_close

- **WHEN** a guard fails, no guard reports a finding, and `on_error` is `fail_close`
- **THEN** the proxy answers 500, `voidwall_blocked_total` increments by one, and
  `voidwall_pii_blocked_total` does not increment

#### Scenario: A scanner failure and a detection together

- **WHEN** one guard fails and another guard's finding blocks the message
- **THEN** `voidwall_blocked_total` increments by one

#### Scenario: A scanner failure under fail_open

- **WHEN** a guard fails, no guard reports a finding, and `on_error` is `fail_open`
- **THEN** the message is forwarded and `voidwall_blocked_total` does not increment

#### Scenario: The REST API never counts a block

- **WHEN** `/v1/scan` detects PII, or answers 400 or 500
- **THEN** `voidwall_blocked_total` does not increment

### Requirement: Unscannable content carries its own reason

When a decoder meets content it cannot inspect, `voidwall_errors_total` SHALL increment
with `reason="unscannable_content"`. The `outcome` label SHALL follow the rules of
"Errors record the fail-open or fail-close outcome". No sample SHALL carry
`reason="unscannable_stream"`.

#### Scenario: An unknown content part

- **WHEN** a decoder meets a content part of an unknown type and `on_error` is
  `fail_close`
- **THEN** `voidwall_errors_total` increments with `outcome="blocked"` and
  `reason="unscannable_content"`

#### Scenario: A stream passes under fail_open

- **WHEN** a client sends `"stream": true` to an `openai-chat` route with response scan
  on, `on_error` is `fail_open`, and the upstream answers a clean `text/event-stream`
- **THEN** no `voidwall_errors_total` sample carries `reason="unscannable_stream"`

## ADDED Requirements

### Requirement: A stream cut after its first byte is counted by reason

The reverse proxy SHALL increment `voidwall_streams_cut_total` once for each stream it
stops after a byte of the body has reached the client. A stop before the first byte
SHALL NOT increment it. The `mode` and `route` labels SHALL follow the rules of "Metric
label values are drawn from fixed sets". The `reason` label SHALL be one of:

- `detection`: a guard reported a finding.
- `scan_error`: a guard error under `fail_close`.
- `idle_timeout`: the idle timeout expired.
- `too_large`: the stream passed `max_body_size`.
- `upstream_error`: the upstream connection failed before the body ended.
- `malformed_body`: a `data:` payload did not parse, under `fail_close`.
- `unscannable_content`: a content part of an unknown type, under `fail_close`.

#### Scenario: A detection after the first byte

- **WHEN** a detection stops a stream that has sent bytes to the client
- **THEN** `voidwall_streams_cut_total` increments by one with `mode="reverse_proxy"`,
  the route's prefix, and `reason="detection"`

#### Scenario: A detection before the first byte

- **WHEN** a detection stops a stream before any byte reaches the client
- **THEN** the proxy answers 400 and `voidwall_streams_cut_total` does not increment

#### Scenario: An idle stream after the first byte

- **WHEN** the idle timeout stops a stream that has sent bytes to the client
- **THEN** `voidwall_streams_cut_total` increments by one with `reason="idle_timeout"`

#### Scenario: An unknown content part after the first byte

- **WHEN** a content part of an unknown type stops a stream that has sent bytes to the
  client, and `on_error` is `fail_close`
- **THEN** `voidwall_streams_cut_total` increments by one with
  `reason="unscannable_content"`

#### Scenario: A clean stream

- **WHEN** a clean stream ends
- **THEN** `voidwall_streams_cut_total` does not increment
