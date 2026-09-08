## ADDED Requirements

### Requirement: Every kind list the engine emits is deterministically ordered

Every kind list the action engine writes SHALL carry the kinds in sorted order and SHALL
hold each kind once. This SHALL hold for the `kinds` array of the default block body and
for the `X-PII-Detected` header value. Two runs over the same content SHALL produce the
same order.

#### Scenario: A block body names three kinds

- **WHEN** a scan detects three kinds and the action list holds block
- **THEN** the `kinds` array of the block body names them in sorted order

#### Scenario: The header names three kinds

- **WHEN** a scan detects three kinds and the action list holds header
- **THEN** `X-PII-Detected` joins them in sorted order

#### Scenario: The same content is scanned twice

- **WHEN** the same content is scanned twice with the same configuration
- **THEN** both block bodies list the kinds in the same order

## MODIFIED Requirements

### Requirement: Redact forwards the mutated body

The redact action SHALL produce the redacted content from the findings of the scan and
SHALL forward it. It SHALL increment the per-kind redaction metric.

#### Scenario: Scan produced a redacted body

- **WHEN** a scan detects PII, the findings carry byte spans, and the action list holds
  redact
- **THEN** the engine replaces each span and forwards the redacted body

#### Scenario: Scan produced no redacted body

- **WHEN** a scan detects PII, no finding carries a byte span, and the action list holds
  redact
- **THEN** the engine forwards no replacement body
