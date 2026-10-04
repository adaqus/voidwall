## MODIFIED Requirements

### Requirement: Detections increment once per resolved kind, whatever happens to the message

The proxy SHALL increment `voidwall_pii_detections_total` once per kind in the resolved
finding set the detection engine returns. It SHALL increment once for a kind however many
findings, and however many guards, reported that kind. It SHALL do so whether the message
is blocked or reported on, and when a guard error makes the API answer 500.

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

#### Scenario: A guard error makes the API answer 500

- **WHEN** one guard fails on `/v1/scan`, another guard reports a finding, and `on_error`
  is `fail_close`
- **THEN** the detection counter increments for each kind the guard that succeeded found

### Requirement: Errors record the fail-open or fail-close outcome

Every scanner failure and limit violation SHALL increment `voidwall_errors_total`. The
`outcome` label SHALL name the path the message took: `passed` when it went through,
`blocked` when it was stopped. The `reason` label SHALL name the cause.

When a detection from another guard blocks the message, a scanner failure that the engine
received before the block SHALL increment the counter with `outcome="blocked"`, whatever
`on_error` says. A guard still running when the block arrives is abandoned, so an error it
would have returned is not counted.

#### Scenario: Body exceeds the size limit under fail_open

- **WHEN** a body is oversize and `on_error` is `fail_open`
- **THEN** the error counter increments with `outcome="passed"` and a reason naming the
  size limit

#### Scenario: A detection overrules a scanner failure under fail_open

- **WHEN** one guard fails, another guard then reports a finding that blocks the message,
  and `on_error` is `fail_open`
- **THEN** the error counter increments with `outcome="blocked"` and
  `reason="scanner_failure"`
