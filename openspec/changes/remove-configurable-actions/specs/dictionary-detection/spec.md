## ADDED Requirements

### Requirement: A person-name match uses the existing proxy surface

A match SHALL flow through the existing pipeline as `PersonName`. It SHALL appear in
`voidwall_pii_detections_total` with the `PERSON_NAME` kind, and in the `kinds` array of a
block response. The detector SHALL add no config key, no metric, and no response field.

#### Scenario: A name is detected in a forwarded request

- **WHEN** the detector matches a person name in a request body
- **THEN** the proxy blocks the request and the `kinds` array names `PERSON_NAME`

#### Scenario: A name is counted

- **WHEN** the detector matches
- **THEN** `voidwall_pii_detections_total` increments with `pii_kind="PERSON_NAME"`

## REMOVED Requirements

### Requirement: The proxy surface is unchanged

**Reason**: Two of the three surfaces it named are deleted — the `X-PII-Detected` header
and the `[PERSON_NAME]` redaction replacement. The rule survives as *A person-name match
uses the existing proxy surface*, keeping the metric kind, the block `kinds` array, and
the prohibition on adding a config key, a metric, or a response field.
**Migration**: None. A person-name match is reported the same way every other kind is.
