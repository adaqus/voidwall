## MODIFIED Requirements

### Requirement: The detector runs last in the chain

The detector SHALL be registered after the keyword-context detector. Chain order SHALL
NOT change the `mark_piis` output, because the proxy resolves the union through
`voidwall_pii::resolve_overlaps`. Running last SHALL let `has_piis` short-circuit on a
cheaper detector first.

#### Scenario: A cheaper detector already matched

- **WHEN** `has_piis` finds a match in an earlier detector
- **THEN** the tokenization work of the dictionary detector is skipped

### Requirement: The proxy surface is unchanged

A match SHALL flow through the existing pipeline as `PersonName`. It SHALL appear in
`voidwall_pii_detections_total` with the `PERSON_NAME` kind, in `X-PII-Detected`, and as
the `[PERSON_NAME]` redaction replacement. The detector SHALL add no config key, no
metric, and no response field.

#### Scenario: A name is redacted under type_label

- **WHEN** the detector matches and `redact_strategy` is `type_label`
- **THEN** the replacement is `[PERSON_NAME]`
