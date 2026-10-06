## MODIFIED Requirements

### Requirement: Detections increment once per resolved kind, whatever happens to the message

The proxy SHALL increment `voidwall_pii_detections_total` once per kind in the resolved
finding set of the `pii` guard. It SHALL increment once for a kind however many findings
reported that kind. It SHALL NOT increment for a kind that only another guard reported.
It SHALL do so whether the message is blocked or reported on, and when a guard error
makes the API answer 500.

#### Scenario: A blocked message increments the detection counter

- **WHEN** a PII detection blocks a request
- **THEN** the detection counter increments for each detected kind, and the blocked
  counter increments once

#### Scenario: A reported detection increments the counter

- **WHEN** `/v1/scan` detects PII and blocks nothing
- **THEN** the detection counter still increments for each detected kind

#### Scenario: One kind is found many times

- **WHEN** a scan returns four findings of the same kind
- **THEN** the counter for that kind increments by one

#### Scenario: Two guards report the same kind

- **WHEN** the `pii` guard and a model guard each report a finding of the same kind in one
  message
- **THEN** the counter for that kind increments by one

#### Scenario: A model guard's kind is not a PII kind

- **WHEN** a model guard reports a `PROMPT_INJECTION` finding
- **THEN** `voidwall_pii_detections_total` does not increment for `PROMPT_INJECTION`

#### Scenario: A guard error makes the API answer 500

- **WHEN** one guard fails on `/v1/scan`, the `pii` guard reports a finding, and
  `on_error` is `fail_close`
- **THEN** the detection counter increments for each kind the `pii` guard found

### Requirement: The blocked counter increments once per message the reverse proxy stops

The reverse proxy SHALL increment `voidwall_blocked_total` once for each message it
stops. A message is stopped when the proxy answers 403 for a detection, or when an
`on_error = "fail_close"` error answers instead of forwarding: 413 for an oversize body
or a window limit, 400 for a body that does not parse as its declared content type, or
500 for a scanner failure. The counter SHALL carry the message's `mode`, `route`, and
`direction`.

The counter SHALL increment once for a message however many guards reported findings
in it, and when a guard error and a detection come together.

A message that passes under `on_error = "fail_open"`, a 502 for an upstream failure, and
every answer of `/v1/scan` SHALL NOT increment the counter.

`voidwall_pii_blocked_total` SHALL count only a 403 for a detection in which the `pii`
guard reported a finding.

#### Scenario: A detection blocks a request

- **WHEN** a PII detection blocks a request on the reverse proxy
- **THEN** `voidwall_blocked_total` and `voidwall_pii_blocked_total` each increment by
  one with `direction="request"`

#### Scenario: Only a model guard detects

- **WHEN** only a model guard reports a finding and the reverse proxy answers 403
- **THEN** `voidwall_blocked_total` increments by one and `voidwall_pii_blocked_total`
  does not increment

#### Scenario: Two guards report findings in one blocked message

- **WHEN** two guards each report a finding in one request that the reverse proxy blocks
- **THEN** `voidwall_blocked_total` increments by one

#### Scenario: An oversize body under fail_close

- **WHEN** a request body is oversize and `on_error` is `fail_close`
- **THEN** the proxy answers 413, `voidwall_blocked_total` increments by one with
  `direction="request"`, and `voidwall_pii_blocked_total` does not increment

#### Scenario: A window limit under fail_close

- **WHEN** a model guard hits its window limit, no guard reports a finding, and
  `on_error` is `fail_close`
- **THEN** the proxy answers 413 and `voidwall_blocked_total` increments by one

#### Scenario: An unparseable body under fail_close

- **WHEN** a response body does not parse as its declared content type and `on_error` is
  `fail_close`
- **THEN** the proxy answers 400, and `voidwall_blocked_total` increments by one with
  `direction="response"`

#### Scenario: A scanner failure under fail_close

- **WHEN** a guard fails, no guard reports a finding, and `on_error` is `fail_close`
- **THEN** the proxy answers 500, `voidwall_blocked_total` increments by one, and
  `voidwall_pii_blocked_total` does not increment

#### Scenario: A scanner failure and a detection together

- **WHEN** one guard fails and another guard's finding blocks the message
- **THEN** `voidwall_blocked_total` increments by one

#### Scenario: A scanner failure under fail_open

- **WHEN** a guard fails, no guard reports a finding, and `on_error` is `fail_open`
- **THEN** the message is forwarded and `voidwall_blocked_total` does not increment

#### Scenario: The REST API never counts a block

- **WHEN** `/v1/scan` detects PII, or answers 400 or 500
- **THEN** `voidwall_blocked_total` does not increment

## ADDED Requirements

### Requirement: Model guard errors carry their own reasons

A model guard's runtime failure SHALL increment `voidwall_errors_total` with
`reason="inference_failure"`. A runtime failure is a full worker queue, a worker thread
that died, a tokenizer error, an ONNX Runtime error, or an output that is not finite or
has the wrong shape. A unit past a model guard's window limit SHALL increment it with
`reason="window_limit"`. The regex PII guard's failure SHALL keep
`reason="scanner_failure"`. The `outcome` label SHALL follow the rules of "Errors record
the fail-open or fail-close outcome".

#### Scenario: Inference fails under fail_close

- **WHEN** a model guard's inference fails, no guard reports a finding, and `on_error` is
  `fail_close`
- **THEN** `voidwall_errors_total` increments with `outcome="blocked"` and
  `reason="inference_failure"`

#### Scenario: Window limit under fail_open

- **WHEN** a model guard hits its window limit, no guard reports a finding, and
  `on_error` is `fail_open`
- **THEN** `voidwall_errors_total` increments with `outcome="passed"` and
  `reason="window_limit"`

#### Scenario: The PII guard fails

- **WHEN** the regex PII guard fails
- **THEN** `voidwall_errors_total` increments with `reason="scanner_failure"`, not
  `inference_failure`
