## ADDED Requirements

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

### Requirement: Detections increment once per resolved kind, whatever happens to the message

The proxy SHALL increment `voidwall_pii_detections_total` once per kind in the resolved
finding set the detection engine returns. It SHALL increment once for a kind however many
findings, and however many guards, reported that kind. It SHALL do so whether the message
is blocked or reported on.

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

## REMOVED Requirements

### Requirement: The proxy publishes six application metrics

**Reason**: `voidwall_pii_redacted_total` counted redactions that no longer happen. The
rule survives as *The proxy publishes five application metrics*, with the same label sets
on every surviving family.
**Migration**: Remove any dashboard panel or alert that reads
`voidwall_pii_redacted_total`. `voidwall_pii_detections_total` reports the same kinds, and
`voidwall_pii_blocked_total` reports what happened to the message.

### Requirement: Detections increment once per resolved kind

**Reason**: The requirement gated the counter on the configured action list, and its
scenario described an empty one. There is no action list. The rule survives as *Detections
increment once per resolved kind, whatever happens to the message*, which keeps the
once-per-kind guarantee across findings and guards.
**Migration**: None. The counter behaves as before.
