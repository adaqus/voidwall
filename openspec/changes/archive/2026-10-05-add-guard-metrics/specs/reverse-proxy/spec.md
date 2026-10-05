## MODIFIED Requirements

### Requirement: A detection blocks with a fixed 403

When a scan detects PII, the proxy SHALL stop the message and SHALL answer 403. The body
SHALL be a JSON object holding an `error` field and a `kinds` array. The array SHALL list
the detected kind names sorted, holding each kind once, and SHALL carry no matched text.
The status, the body, and the response headers SHALL NOT be configurable. The proxy SHALL
increment `voidwall_pii_blocked_total` once, `voidwall_blocked_total` once, the PII
detection counter once per kind, and `voidwall_detections_total` once per guard that
reported a finding.

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
