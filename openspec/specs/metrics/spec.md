## Purpose

The proxy publishes Prometheus metrics that describe detections, actions, traffic,
errors, and process health. The admin listener serves them.

## Requirements

### Requirement: The proxy publishes six application metrics

The proxy SHALL register these metric families:

- `voidwall_pii_detections_total`, a counter labelled `pii_kind`, `mode`, `route`, and
  `direction`.
- `voidwall_pii_blocked_total`, a counter labelled `mode`, `route`, and `direction`.
- `voidwall_pii_redacted_total`, a counter labelled `pii_kind`, `mode`, `route`, and
  `direction`.
- `voidwall_requests_total`, a counter labelled `mode`, `route`, `method`, and
  `status`.
- `voidwall_request_duration_seconds`, a histogram labelled `mode` and `route`.
- `voidwall_errors_total`, a counter labelled `outcome` and `reason`.

A family that names a detection tier SHALL carry that tier in its name. A family that
describes the engine as a whole SHALL NOT name a tier.

#### Scenario: Prometheus scrapes a running proxy

- **WHEN** a client scrapes the admin metrics endpoint
- **THEN** the response carries these six families with these label sets

#### Scenario: The retired family is absent

- **WHEN** a client scrapes the admin metrics endpoint
- **THEN** no family named `voidwall_specialization_errors_total` appears

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

### Requirement: Detections increment once per resolved kind

The proxy SHALL increment `voidwall_pii_detections_total` once per kind in the resolved
finding set the detection engine returns. It SHALL increment once for a kind however
many findings, and however many guards, reported that kind. It SHALL do so whatever
action list is configured, including an empty one.

#### Scenario: PII detected with no action configured

- **WHEN** the action list for a direction is empty and PII is detected
- **THEN** the detection counter still increments

#### Scenario: One kind is found many times

- **WHEN** a scan returns four findings of the same kind
- **THEN** the counter for that kind increments by one

#### Scenario: Two guards report the same kind

- **WHEN** two guards each report a finding of the same kind in one message
- **THEN** the counter for that kind increments by one

### Requirement: Errors record the fail-open or fail-close outcome

Every scanner failure and limit violation SHALL increment `voidwall_errors_total`. The
`outcome` label SHALL name the path taken: `passed` under `fail_open`, `blocked` under
`fail_close`. The `reason` label SHALL name the cause.

#### Scenario: Body exceeds the size limit under fail_open

- **WHEN** a body is oversize and `on_error` is `fail_open`
- **THEN** the error counter increments with `outcome="passed"` and a reason naming the
  size limit

### Requirement: Process metrics refresh on every scrape

The proxy SHALL publish `process_resident_memory_bytes`,
`process_virtual_memory_bytes`, `process_cpu_seconds_total`, `process_threads`, and
`process_open_fds`. It SHALL refresh them from the operating system on each scrape of
the metrics endpoint.

#### Scenario: Two scrapes in a row

- **WHEN** a client scrapes the metrics endpoint twice
- **THEN** each response carries process values read at that moment
