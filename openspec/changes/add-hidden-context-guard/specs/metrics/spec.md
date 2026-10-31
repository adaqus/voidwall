## ADDED Requirements

### Requirement: A /v1/scan detection carries the scanned direction

A detection on `/v1/scan` SHALL carry the `direction` label of the scanned direction:
`request` without the `direction` parameter or with `direction=request`, and `response`
with `direction=response`.

#### Scenario: A response scan detects a marker

- **WHEN** `/v1/scan?direction=response` reports a `hidden_context` finding
- **THEN** `voidwall_detections_total` increments with `guard="hidden_context"`,
  `mode="http_api"`, `route="global"`, and `direction="response"`

#### Scenario: A scan without the parameter

- **WHEN** `/v1/scan` without the `direction` parameter detects PII
- **THEN** the detection metrics carry `direction="request"`
