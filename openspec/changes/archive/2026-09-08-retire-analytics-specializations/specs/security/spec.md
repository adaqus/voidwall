## ADDED Requirements

### Requirement: A log line never carries a PII value

The proxy SHALL log the PII kind name and the match count only. No log line, at any
level, SHALL carry matched text, a body fragment, or a redaction input.

#### Scenario: A detection is logged

- **WHEN** the proxy logs a detection
- **THEN** the line names the kind and the count and carries no matched text

#### Scenario: A scan failure is logged

- **WHEN** the proxy logs a scan failure
- **THEN** the line names the reason and carries no payload

## MODIFIED Requirements

### Requirement: A PII value never reaches a metric

Every metric label SHALL hold a kind name, a mode, a route, a direction, a method, a
status, an outcome, or a reason. No label SHALL ever hold a matched value.

#### Scenario: A detection increments a counter

- **WHEN** the proxy increments the detection counter
- **THEN** the `pii_kind` label holds the kind name and no value

## REMOVED Requirements

### Requirement: A PII value never reaches a log

**Reason**: The normative rule is unchanged, but one of its two scenarios covers a
specialization decode failure. That failure category is retired with the analytics
specializations, and a scenario cannot be dropped from a requirement in place.

**Migration**: None. Replaced by "A log line never carries a PII value", whose normative
text is identical and whose second scenario covers the surviving scan-failure log path
instead. The PII-safety rule is unchanged and no behaviour moves.

The proxy SHALL log the PII kind name and the match count only. No log line, at any
level, SHALL carry matched text, a body fragment, or a redaction input.

#### Scenario: A detection is logged

- **WHEN** the proxy logs a detection
- **THEN** the line names the kind and the count and carries no matched text

#### Scenario: A specialization fails to decode

- **WHEN** the proxy logs a specialization decode failure
- **THEN** the line names the specialization and the reason and carries no payload
