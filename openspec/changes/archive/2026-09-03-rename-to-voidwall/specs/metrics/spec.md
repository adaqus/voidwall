## MODIFIED Requirements

### Requirement: The proxy publishes seven application metrics

The proxy SHALL register these metric families:

- `voidwall_pii_detections_total`, a counter labelled `pii_kind`, `mode`, `route`,
  `direction`, and `specialization`.
- `voidwall_pii_blocked_total`, a counter labelled `mode`, `route`, and `direction`.
- `voidwall_pii_redacted_total`, a counter labelled `pii_kind`, `mode`, `route`,
  `direction`, and `specialization`.
- `voidwall_requests_total`, a counter labelled `mode`, `route`, `method`, and
  `status`.
- `voidwall_request_duration_seconds`, a histogram labelled `mode` and `route`.
- `voidwall_errors_total`, a counter labelled `outcome` and `reason`.
- `voidwall_specialization_errors_total`, a counter labelled `specialization` and
  `reason`.

A family that names a detection tier SHALL carry that tier in its name. A family that
describes the engine as a whole SHALL NOT name a tier.

#### Scenario: Prometheus scrapes a running proxy

- **WHEN** a client scrapes the admin metrics endpoint
- **THEN** the response carries these seven families with these label sets

### Requirement: Detections increment once per resolved match

The proxy SHALL increment `voidwall_pii_detections_total` once per kind in the resolved
match set. It SHALL do so whatever action list is configured, including an empty one.

#### Scenario: PII detected with no action configured

- **WHEN** the action list for a direction is empty and PII is detected
- **THEN** the detection counter still increments

### Requirement: Errors record the fail-open or fail-close outcome

Every scanner failure and limit violation SHALL increment `voidwall_errors_total`. The
`outcome` label SHALL name the path taken: `passed` under `fail_open`, `blocked` under
`fail_close`. The `reason` label SHALL name the cause.

#### Scenario: Body exceeds the size limit under fail_open

- **WHEN** a body is oversize and `on_error` is `fail_open`
- **THEN** the error counter increments with `outcome="passed"` and a reason naming the
  size limit

### Requirement: A specialization decoder failure is counted separately

A specialization decode failure that falls back to a raw scan SHALL increment
`voidwall_specialization_errors_total`, labelled by specialization and reason. It SHALL
not be counted as a scanner error.

#### Scenario: A specialization cannot decode a field

- **WHEN** a specialization fails to decode a field and falls back to a raw scan
- **THEN** the specialization error counter increments with that specialization and
  reason
