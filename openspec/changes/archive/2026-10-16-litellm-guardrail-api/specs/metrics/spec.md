## RENAMED Requirements

- FROM: `### Requirement: The proxy publishes seven application metrics`
- TO: `### Requirement: The proxy publishes eight application metrics`

## MODIFIED Requirements

### Requirement: The proxy publishes eight application metrics

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

A family that names a detection tier SHALL carry that tier in its name. A family that
describes the engine as a whole SHALL NOT name a tier.

#### Scenario: Prometheus scrapes a running proxy

- **WHEN** a client scrapes the admin metrics endpoint
- **THEN** the response carries these eight families with these label sets

#### Scenario: A retired family is absent

- **WHEN** a client scrapes the admin metrics endpoint
- **THEN** no family named `voidwall_specialization_errors_total` or
  `voidwall_pii_redacted_total` appears

#### Scenario: The guard families carry no kind label

- **WHEN** the proxy increments `voidwall_detections_total` or `voidwall_blocked_total`
- **THEN** the sample carries no `pii_kind` label and no other kind label

## ADDED Requirements

### Requirement: Values skipped without a scan are counted by reason

`voidwall_unscanned_total` SHALL increment once for each value a decoder skips on
purpose without a scan. Its `reason` label SHALL be drawn from a fixed set. The only
value SHALL be `encoded_data`, for a base64 value. The `mode`, `route`, and `direction`
labels SHALL follow the rules of "Metric label values are drawn from fixed sets".

#### Scenario: Two inline images

- **WHEN** the LiteLLM route skips two base64 images in one request payload
- **THEN** `voidwall_unscanned_total` increments by two with `mode="http_api"`,
  `route="global"`, `direction="request"`, and `reason="encoded_data"`

#### Scenario: Nothing is skipped

- **WHEN** a payload holds no base64 value
- **THEN** `voidwall_unscanned_total` does not increment
