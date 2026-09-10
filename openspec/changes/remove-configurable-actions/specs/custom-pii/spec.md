## ADDED Requirements

### Requirement: The operator label surfaces wherever a kind name appears

A custom match SHALL report the operator's label in the Prometheus `pii_kind` label, in
the `kinds` list of a block response, and in the `kinds` array of `/v1/scan`.

#### Scenario: A custom definition matches in the reverse proxy

- **WHEN** a custom definition matches a forwarded request
- **THEN** the proxy blocks it and the `kinds` array of the 403 body carries the
  operator's label

#### Scenario: A custom definition matches on the HTTP API

- **WHEN** a custom definition matches a body posted to `/v1/scan`
- **THEN** the `kinds` array lists the operator's label

#### Scenario: A custom match is counted

- **WHEN** a custom definition matches
- **THEN** `voidwall_pii_detections_total` carries the operator's label as `pii_kind`

## REMOVED Requirements

### Requirement: The operator label surfaces everywhere a kind name does

**Reason**: Two of the five surfaces it named are deleted — the `X-PII-Detected` header
and the `type_label` redaction replacement. The rule survives as *The operator label
surfaces wherever a kind name appears* over the three surfaces that remain.
**Migration**: None for the surviving surfaces. A consumer that read the operator's label
out of `X-PII-Detected` or a `[LABEL]` replacement must read it from the 403 `kinds`
array, from `/v1/scan`, or from the `pii_kind` metric label.
