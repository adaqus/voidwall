## ADDED Requirements

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

## REMOVED Requirements

### Requirement: The proxy publishes seven application metrics

**Reason**: `voidwall_specialization_errors_total` is removed with the analytics
specializations, and the `specialization` label leaves the detection and redaction counters.
Both the family count in the requirement name and two label sets change, so the requirement
is replaced rather than edited.

**Migration**: Replaced by "The proxy publishes six application metrics". A dashboard or
alert that queries `voidwall_specialization_errors_total` must be removed. A query that
groups or filters `voidwall_pii_detections_total` or `voidwall_pii_redacted_total` by
`specialization` must drop that label; a query that aggregates it away needs no change.

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

### Requirement: Label values are drawn from fixed sets

**Reason**: The `specialization` label is removed, so the sentence fixing its values and the
scenario covering its `none` default describe behaviour that no longer exists.

**Migration**: Replaced by "Metric label values are drawn from fixed sets", which carries
every surviving label unchanged.

The `mode` label SHALL be `reverse_proxy`, `forward_proxy`, or `http_api`. The `route`
label SHALL be the path prefix in reverse proxy mode, and `global` in every other mode.
The `direction` label SHALL be `request` or `response`. The `specialization` label SHALL
be the active specialization name, or `none`. The `outcome` label SHALL be `passed` or
`blocked`.

#### Scenario: HTTP API records a detection

- **WHEN** the HTTP API detects PII
- **THEN** the detection metric carries `mode="http_api"` and `route="global"`

#### Scenario: No specialization is active

- **WHEN** a route names no specialization
- **THEN** the detection metric carries `specialization="none"`

### Requirement: A specialization decoder failure is counted separately

**Reason**: The analytics specializations are retired, so there is no decoder failure to
count and `voidwall_specialization_errors_total` is removed.

**Migration**: Remove any alert or dashboard panel that queries
`voidwall_specialization_errors_total`. No other counter replaces it.

A specialization decode failure that falls back to a raw scan SHALL increment
`voidwall_specialization_errors_total`, labelled by specialization and reason. It SHALL
not be counted as a scanner error.

#### Scenario: A specialization cannot decode a field

- **WHEN** a specialization fails to decode a field and falls back to a raw scan
- **THEN** the specialization error counter increments with that specialization and
  reason
