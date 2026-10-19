## MODIFIED Requirements

### Requirement: The blocked counter increments once per message the reverse proxy stops

The reverse proxy SHALL increment `voidwall_blocked_total` once for each message it
stops. A message is stopped when the proxy answers a detection with the route's block
(403, or 400 on a route with `format = "openai-chat"`), or when an error answers instead
of forwarding: under `on_error = "fail_close"`, 413 for an oversize body or a window
limit, 400 for a body that does not parse as its declared content type, 422 for
unscannable content or an unscannable stream, or 500 for a scanner failure; and, on an
`openai-chat` route, 400 for a request that is not a Chat Completions request, under
either `on_error`. The counter SHALL carry the message's `mode`, `route`, and
`direction`.

The counter SHALL increment once for a message however many guards reported findings
in it, and when a guard error and a detection come together.

A message that passes under `on_error = "fail_open"`, a 502 for an upstream failure, and
every answer of `/v1/scan` SHALL NOT increment the counter.

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
  `format = "openai-chat"`, response scan is on, and `on_error` is `fail_close`
- **THEN** the proxy answers 422 and `voidwall_blocked_total` increments by one with
  `direction="request"`

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

## ADDED Requirements

### Requirement: Unscannable content and streams carry their own reasons

When a decoder meets content it cannot inspect, `voidwall_errors_total` SHALL increment
with `reason="unscannable_content"`. When the reverse proxy meets a stream it cannot
inspect, `voidwall_errors_total` SHALL increment with `reason="unscannable_stream"`. A
message SHALL increment the counter once for an unscannable stream, whatever direction
the stream is found in. The `outcome` label SHALL follow the rules of "Errors record the
fail-open or fail-close outcome".

#### Scenario: An unknown content part

- **WHEN** a decoder meets a content part of an unknown type and `on_error` is
  `fail_close`
- **THEN** `voidwall_errors_total` increments with `outcome="blocked"` and
  `reason="unscannable_content"`

#### Scenario: A stream passes under fail_open

- **WHEN** a client sends `"stream": true` to an `openai-chat` route with response scan
  on, `on_error` is `fail_open`, and the upstream answers `text/event-stream`
- **THEN** `voidwall_errors_total` increments once with `outcome="passed"` and
  `reason="unscannable_stream"`
