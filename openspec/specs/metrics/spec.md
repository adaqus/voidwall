## Purpose

The proxy publishes Prometheus metrics that describe detections, actions, traffic,
errors, and process health. The admin listener serves them.

## Requirements

### Requirement: The proxy publishes seven application metrics

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

A family that names a detection tier SHALL carry that tier in its name. A family that
describes the engine as a whole SHALL NOT name a tier.

#### Scenario: Prometheus scrapes a running proxy

- **WHEN** a client scrapes the admin metrics endpoint
- **THEN** the response carries these seven families with these label sets

#### Scenario: A retired family is absent

- **WHEN** a client scrapes the admin metrics endpoint
- **THEN** no family named `voidwall_specialization_errors_total` or
  `voidwall_pii_redacted_total` appears

#### Scenario: The guard families carry no kind label

- **WHEN** the proxy increments `voidwall_detections_total` or `voidwall_blocked_total`
- **THEN** the sample carries no `pii_kind` label and no other kind label

### Requirement: Metric label values are drawn from fixed sets

The `mode` label SHALL be `reverse_proxy`, `forward_proxy`, or `http_api`. The `route`
label SHALL be the path prefix in reverse proxy mode, and `global` in every other mode.
The `direction` label SHALL be `request` or `response`. The `outcome` label SHALL be
`passed` or `blocked`. The `guard` label SHALL be the name configuration gave the guard,
so the set of its values is fixed at startup. The built-in regex PII guard SHALL carry
`guard="pii"`.

#### Scenario: HTTP API records a detection

- **WHEN** the HTTP API detects PII
- **THEN** the detection metric carries `mode="http_api"` and `route="global"`

#### Scenario: A detection carries no specialization label

- **WHEN** the proxy increments the detection counter
- **THEN** the sample carries no `specialization` label

#### Scenario: The PII guard records a detection

- **WHEN** the built-in regex PII guard reports a finding
- **THEN** `voidwall_detections_total` increments with `guard="pii"`

### Requirement: A metric label never carries a PII value

Every label SHALL carry a kind name, a guard name, a mode, a route, a direction, a
method, a status, or a reason. No label SHALL ever carry matched text.

#### Scenario: A detection is recorded

- **WHEN** the proxy increments the detection counter for a match
- **THEN** the `pii_kind` label holds the kind name and no matched value

#### Scenario: A guard detection is recorded

- **WHEN** the proxy increments `voidwall_detections_total`
- **THEN** the `guard` label holds the guard's configured name and no matched value

### Requirement: Detections increment once per resolved kind, whatever happens to the message

The proxy SHALL increment `voidwall_pii_detections_total` once per kind in the resolved
finding set the detection engine returns. It SHALL increment once for a kind however many
findings, and however many guards, reported that kind. It SHALL do so whether the message
is blocked or reported on, and when a guard error makes the API answer 500.

#### Scenario: A blocked message increments the detection counter

- **WHEN** a detection blocks a request
- **THEN** the detection counter increments for each detected kind, and the blocked
  counter increments once

#### Scenario: A reported detection increments the counter

- **WHEN** `/v1/scan` detects PII and blocks nothing
- **THEN** the detection counter still increments for each detected kind

#### Scenario: One kind is found many times

- **WHEN** a scan returns four findings of the same kind
- **THEN** the counter for that kind increments by one

#### Scenario: Two guards report the same kind

- **WHEN** two guards each report a finding of the same kind in one message
- **THEN** the counter for that kind increments by one

#### Scenario: A guard error makes the API answer 500

- **WHEN** one guard fails on `/v1/scan`, another guard reports a finding, and `on_error`
  is `fail_close`
- **THEN** the detection counter increments for each kind the guard that succeeded found

### Requirement: Errors record the fail-open or fail-close outcome

Every scanner failure and limit violation SHALL increment `voidwall_errors_total`. The
`outcome` label SHALL name the path the message took: `passed` when it went through,
`blocked` when it was stopped. The `reason` label SHALL name the cause.

When a detection from another guard blocks the message, a scanner failure that the engine
received before the block SHALL increment the counter with `outcome="blocked"`, whatever
`on_error` says. A guard still running when the block arrives is abandoned, so an error it
would have returned is not counted.

#### Scenario: Body exceeds the size limit under fail_open

- **WHEN** a body is oversize and `on_error` is `fail_open`
- **THEN** the error counter increments with `outcome="passed"` and a reason naming the
  size limit

#### Scenario: A detection overrules a scanner failure under fail_open

- **WHEN** one guard fails, another guard then reports a finding that blocks the message,
  and `on_error` is `fail_open`
- **THEN** the error counter increments with `outcome="blocked"` and
  `reason="scanner_failure"`

### Requirement: Process metrics refresh on every scrape

The proxy SHALL publish `process_resident_memory_bytes`,
`process_virtual_memory_bytes`, `process_cpu_seconds_total`, `process_threads`, and
`process_open_fds`. It SHALL refresh them from the operating system on each scrape of
the metrics endpoint.

#### Scenario: Two scrapes in a row

- **WHEN** a client scrapes the metrics endpoint twice
- **THEN** each response carries process values read at that moment

### Requirement: Guard detections increment once per guard per message

The proxy SHALL increment `voidwall_detections_total` once for each guard that reported
at least one finding in a message, with that guard's name as the `guard` label. It SHALL
increment once for a guard however many findings, and however many units, that guard
reported in the message. It SHALL do so whether the message is blocked or reported on,
and when a guard error makes the API answer 500.

The counter SHALL count the guards whose findings the detection engine returned. When a
detection blocks the message, a guard still running is abandoned, and the counter SHALL
NOT increment for it.

#### Scenario: One guard finds many matches

- **WHEN** one guard reports four findings in one message
- **THEN** `voidwall_detections_total` for that guard increments by one

#### Scenario: One guard finds matches in two units

- **WHEN** one guard reports a finding in the body and a finding in a header of one
  request
- **THEN** `voidwall_detections_total` for that guard increments by one

#### Scenario: Two guards report findings

- **WHEN** two guards each report a finding in one message
- **THEN** `voidwall_detections_total` increments by one for each guard

#### Scenario: A reported detection increments the guard counter

- **WHEN** `/v1/scan` detects PII
- **THEN** `voidwall_detections_total` increments with `guard="pii"`, `mode="http_api"`,
  `route="global"`, and `direction="request"`

#### Scenario: A guard error makes the API answer 500

- **WHEN** one guard fails on `/v1/scan`, another guard reports a finding, and `on_error`
  is `fail_close`
- **THEN** `voidwall_detections_total` increments for the guard that reported the
  finding, and not for the guard that failed

#### Scenario: A block abandons a guard

- **WHEN** one guard's finding blocks a message on the reverse proxy while another
  selected guard is still running
- **THEN** `voidwall_detections_total` increments for the guard that blocked, and not for
  the guard that was abandoned

#### Scenario: A clean message

- **WHEN** no guard reports a finding in a message
- **THEN** `voidwall_detections_total` does not increment

### Requirement: The blocked counter increments once per message the reverse proxy stops

The reverse proxy SHALL increment `voidwall_blocked_total` once for each message it
stops. A message is stopped when the proxy answers 403 for a detection, or when an
`on_error = "fail_close"` error answers instead of forwarding: 413 for an oversize body,
400 for a body that does not parse as its declared content type, or 500 for a scanner
failure. The counter SHALL carry the message's `mode`, `route`, and `direction`.

The counter SHALL increment once for a message however many guards reported findings
in it, and when a guard error and a detection come together.

A message that passes under `on_error = "fail_open"`, a 502 for an upstream failure, and
every answer of `/v1/scan` SHALL NOT increment the counter.

`voidwall_pii_blocked_total` SHALL keep counting only the 403 for a detection.

#### Scenario: A detection blocks a request

- **WHEN** a detection blocks a request on the reverse proxy
- **THEN** `voidwall_blocked_total` and `voidwall_pii_blocked_total` each increment by
  one with `direction="request"`

#### Scenario: Two guards report findings in one blocked message

- **WHEN** two guards each report a finding in one request that the reverse proxy blocks
- **THEN** `voidwall_blocked_total` increments by one

#### Scenario: An oversize body under fail_close

- **WHEN** a request body is oversize and `on_error` is `fail_close`
- **THEN** the proxy answers 413, `voidwall_blocked_total` increments by one with
  `direction="request"`, and `voidwall_pii_blocked_total` does not increment

#### Scenario: An unparseable body under fail_close

- **WHEN** a response body does not parse as its declared content type and `on_error` is
  `fail_close`
- **THEN** the proxy answers 400, and `voidwall_blocked_total` increments by one with
  `direction="response"`

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
