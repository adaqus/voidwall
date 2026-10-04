## Purpose

The proxy publishes Prometheus metrics that describe detections, actions, traffic,
errors, and process health. The admin listener serves them.

## Requirements

### Requirement: The proxy publishes five application metrics

The proxy SHALL register these metric families:

- `voidwall_pii_detections_total`, a counter labelled `pii_kind`, `mode`, `route`, and
  `direction`.
- `voidwall_pii_blocked_total`, a counter labelled `mode`, `route`, and `direction`.
- `voidwall_requests_total`, a counter labelled `mode`, `route`, `method`, and
  `status`.
- `voidwall_request_duration_seconds`, a histogram labelled `mode` and `route`.
- `voidwall_errors_total`, a counter labelled `outcome` and `reason`.

A family that names a detection tier SHALL carry that tier in its name. A family that
describes the engine as a whole SHALL NOT name a tier.

#### Scenario: Prometheus scrapes a running proxy

- **WHEN** a client scrapes the admin metrics endpoint
- **THEN** the response carries these five families with these label sets

#### Scenario: A retired family is absent

- **WHEN** a client scrapes the admin metrics endpoint
- **THEN** no family named `voidwall_specialization_errors_total` or
  `voidwall_pii_redacted_total` appears

### Requirement: Metric label values are drawn from fixed sets

The `mode` label SHALL be `reverse_proxy`, `forward_proxy`, or `http_api`. The `route`
label SHALL be the path prefix in reverse proxy mode, and `global` in every other mode.
The `direction` label SHALL be `request` or `response`. The `outcome` label SHALL be
`passed` or `blocked`.

#### Scenario: HTTP API records a detection

- **WHEN** the HTTP API detects PII
- **THEN** the detection metric carries `mode="http_api"` and `route="global"`

#### Scenario: A detection carries no specialization label

- **WHEN** the proxy increments the detection counter
- **THEN** the sample carries no `specialization` label

### Requirement: A metric label never carries a PII value

Every label SHALL carry a kind name, a mode, a route, a direction, a method, a status,
or a reason. No label SHALL ever carry matched text.

#### Scenario: A detection is recorded

- **WHEN** the proxy increments the detection counter for a match
- **THEN** the `pii_kind` label holds the kind name and no matched value

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
