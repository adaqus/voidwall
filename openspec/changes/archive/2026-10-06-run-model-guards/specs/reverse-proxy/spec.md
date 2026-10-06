## MODIFIED Requirements

### Requirement: A detection blocks with a fixed 403

When a guard reports a finding, the proxy SHALL stop the message and SHALL answer 403.
The body SHALL be a JSON object holding an `error` field and a `kinds` array. The `error`
field SHALL be exactly `content blocked`, whatever guard reported the finding. The array
SHALL list the detected kind names of every guard sorted, holding each kind once, and
SHALL carry no matched text. The status, the body, and the response headers SHALL NOT be
configurable. The proxy SHALL increment `voidwall_blocked_total` once and
`voidwall_detections_total` once per guard that reported a finding. When the `pii` guard
reported a finding, the proxy SHALL also increment `voidwall_pii_blocked_total` once and
the PII detection counter once per kind that guard found.

#### Scenario: PII is found in a request

- **WHEN** a scan of the incoming request detects PII
- **THEN** the proxy answers 403 and does not reach the upstream

#### Scenario: PII is found in a response

- **WHEN** a scan of the upstream response detects PII
- **THEN** the proxy answers 403 and the upstream body does not reach the client

#### Scenario: Three kinds are found

- **WHEN** a scan detects three kinds
- **THEN** the `kinds` array names them sorted, each once, with no matched value

#### Scenario: A block increments the guard metrics

- **WHEN** the PII guard's finding blocks a request
- **THEN** `voidwall_blocked_total` increments by one and `voidwall_detections_total`
  increments by one with `guard="pii"`

#### Scenario: A model guard detects an injection

- **WHEN** a model guard with `labels = ["PROMPT_INJECTION"]` scores a request body at or
  above its threshold
- **THEN** the proxy answers 403 with `error` `content blocked` and `kinds`
  `["PROMPT_INJECTION"]`, and does not reach the upstream
- **AND** `voidwall_detections_total` increments with that guard's name, and
  `voidwall_pii_blocked_total` does not increment

### Requirement: A blocked error names the party at fault

When the `on_error` policy blocks a message, the reverse proxy SHALL answer a status that
names the party at fault.

- A body larger than `max_body_size` SHALL answer 413.
- A unit that needs more windows than a model guard's window limit SHALL answer 413.
- A body that fails to parse SHALL answer 400. The client declared the content type and
  sent bytes that do not match it.
- A scanner failure SHALL answer 500. The scanner belongs to the proxy. A model guard's
  inference failure SHALL count as a scanner failure.

The proxy SHALL reserve 502 for a failure of the upstream itself. Each of these response
bodies SHALL be a JSON object holding an `error` field, and SHALL carry no matched text
and no fragment of the message that was scanned.

The window-limit 413 body SHALL be exactly
`{"error":"tokenized content too long to scan"}`. The 500 body SHALL be exactly
`{"error":"internal error"}`. Every 502 body SHALL be
exactly `{"error":"upstream error"}`. Neither body SHALL carry a detail of the failure.

#### Scenario: Oversize body under fail_close

- **WHEN** a request body is larger than `max_body_size` and `on_error` is `fail_close`
- **THEN** the proxy answers 413 and does not forward the request

#### Scenario: Window limit under fail_close

- **WHEN** a model guard needs more windows for a unit than its window limit, no guard
  reports a finding, and `on_error` is `fail_close`
- **THEN** the proxy answers 413 and does not forward the message
- **AND** the body is exactly `{"error":"tokenized content too long to scan"}`

#### Scenario: Window limit under fail_open

- **WHEN** a model guard needs more windows for a unit than its window limit, no guard
  reports a finding, and `on_error` is `fail_open`
- **THEN** the proxy forwards the message

#### Scenario: Malformed body under fail_close

- **WHEN** a request declares a JSON content type, its body does not parse, and `on_error`
  is `fail_close`
- **THEN** the proxy answers 400 and does not forward the request

#### Scenario: Scanner failure under fail_close

- **WHEN** the scanner returns an error and `on_error` is `fail_close`
- **THEN** the proxy answers 500 and does not forward the request
- **AND** the body is exactly `{"error":"internal error"}`

#### Scenario: Model inference failure under fail_close

- **WHEN** a model guard's inference fails, no guard reports a finding, and `on_error` is
  `fail_close`
- **THEN** the proxy answers 500 with the body `{"error":"internal error"}`, and the log
  names the guard

#### Scenario: The upstream cannot be reached

- **WHEN** the proxy forwards a clean request and the upstream connection fails
- **THEN** the proxy answers 502
- **AND** the body is exactly `{"error":"upstream error"}`

#### Scenario: An error body carries no scanned text

- **WHEN** the proxy answers 400, 413, or 500 for a message that held a detected value
- **THEN** the body names the error only and carries no matched text
