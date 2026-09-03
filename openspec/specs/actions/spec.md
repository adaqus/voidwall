## Purpose

The action engine decides what happens after a scan finds PII. It can block the
message, redact the PII in place, or add a header that names the detected kinds.

## Requirements

### Requirement: No detection passes the message through untouched

The action engine SHALL return a pass outcome when the scan detects no PII. It SHALL
apply no action and SHALL increment no detection metric.

#### Scenario: Clean message with every action configured

- **WHEN** a scan reports no detection and the action list holds block, redact, and
  header
- **THEN** the engine returns a pass outcome and the message is forwarded unchanged

### Requirement: Detection metrics increment unconditionally

The action engine SHALL increment the per-kind detection metric for every detected
kind, whatever the configured action list contains. There is no `warn` action.

#### Scenario: PII detected with an empty action list

- **WHEN** a scan detects PII and the action list for that direction is empty
- **THEN** the engine increments the detection metric for each kind
- **AND** the engine forwards the message unchanged

### Requirement: Action precedence is block, then redact, then header

The action engine SHALL evaluate the actions in this order: block, redact, header.
Block SHALL short-circuit. The engine SHALL apply no later action after a block.

#### Scenario: Block combined with redact and header

- **WHEN** a scan detects PII and the action list holds block together with redact or
  header
- **THEN** the engine returns a block outcome
- **AND** the engine applies neither the redaction nor the header

#### Scenario: Redact and header combined

- **WHEN** a scan detects PII and the action list holds redact and header
- **THEN** the engine forwards the redacted body
- **AND** the engine adds the detection header describing the same detection

### Requirement: Block returns a configurable error response

The block action SHALL return the configured status, body, and headers. The status
SHALL default to 403. The body SHALL default to a JSON object holding an `error` field
and a `kinds` array. The engine SHALL increment the blocked metric.

#### Scenario: Block with default settings

- **WHEN** a scan detects PII and the action list holds block, with no block settings
  configured
- **THEN** the engine returns status 403
- **AND** the body is JSON naming the detected kinds and no matched value

#### Scenario: Block with custom settings

- **WHEN** `block_status`, `block_body`, and `block_headers` are configured
- **THEN** the engine returns that status, that body, and those headers

### Requirement: Block responses never carry a PII value

The block body SHALL list detected kind names only. It SHALL never carry matched text.

#### Scenario: Default block body is built

- **WHEN** the engine builds the default block body for a detection
- **THEN** the `kinds` array holds kind names only, and no matched value appears

### Requirement: Redact forwards the mutated body

The redact action SHALL forward the redacted body produced by the scan. It SHALL
increment the per-kind redaction metric.

#### Scenario: Scan produced a redacted body

- **WHEN** a scan detects PII, produces a redacted body, and the action list holds
  redact
- **THEN** the engine forwards the redacted body

#### Scenario: Scan produced no redacted body

- **WHEN** a scan detects PII but produces no redacted body, and the action list holds
  redact
- **THEN** the engine forwards no replacement body

### Requirement: Header action adds X-PII-Detected

The header action SHALL add an `X-PII-Detected` header. Its value SHALL be the
detected kind names, joined by a comma. It SHALL carry no matched value.

#### Scenario: PII detected with the header action

- **WHEN** a scan detects PII and the action list holds header
- **THEN** the forwarded message carries `X-PII-Detected` listing the detected kinds

### Requirement: Redaction strategy is configurable

The redaction SHALL support two strategies. `char` SHALL replace each PII character
with `mask_char`, which defaults to `*`. `type_label` SHALL replace the match with the
kind name in square brackets.

#### Scenario: Character strategy

- **WHEN** `redact_strategy` is `char` and the scan detects an email address
- **THEN** the redacted body carries the mask character in place of the value

#### Scenario: Type label strategy

- **WHEN** `redact_strategy` is `type_label` and the scan detects an email address
- **THEN** the redacted body carries `[EMAIL]` in place of the value

### Requirement: Scanner failures follow the on_error policy

When the scanner fails, or the message exceeds a configured limit, the proxy SHALL
follow the `on_error` policy. `fail_open` SHALL forward the message. `fail_close` SHALL
block it. `fail_open` SHALL be the default. The proxy SHALL increment
`voidwall_errors_total` with the outcome that was taken.

#### Scenario: Scanner fails under fail_open

- **WHEN** the scanner returns an error and `on_error` is `fail_open`
- **THEN** the proxy forwards the message
- **AND** `voidwall_errors_total{outcome="passed"}` increments

#### Scenario: Scanner fails under fail_close

- **WHEN** the scanner returns an error and `on_error` is `fail_close`
- **THEN** the proxy blocks the message
- **AND** `voidwall_errors_total{outcome="blocked"}` increments

