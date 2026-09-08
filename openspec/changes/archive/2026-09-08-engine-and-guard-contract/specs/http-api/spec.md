## MODIFIED Requirements

### Requirement: POST /v1/scan reports the detection

`/v1/scan` SHALL return JSON holding `detected`, `matches_count`, and `kinds`. It SHALL
NOT echo the body. `matches_count` SHALL be the size of the resolved match set. `kinds`
SHALL hold kind names only, never a matched value. `kinds` SHALL be sorted and SHALL
hold each kind once, so two scans of the same body return the same array.

#### Scenario: Body carries PII

- **WHEN** a client posts a body holding an email address and a national number
- **THEN** the response reports `detected` true, the resolved match count, and both kind
  names

#### Scenario: Body is clean

- **WHEN** a client posts a body with no PII
- **THEN** the response reports `detected` false and an empty `kinds` array

#### Scenario: The same body is posted twice

- **WHEN** a client posts the same body holding two kinds twice
- **THEN** both responses carry the same `kinds` array in the same sorted order

### Requirement: Redaction metadata travels in headers

`/v1/redact` SHALL set `X-PII-Detected` to the comma-separated kind names, and SHALL
omit that header when nothing is detected. The kind names SHALL be sorted and SHALL
appear once each. It SHALL set `X-PII-Redacted-Count` to the number of redactions, and
SHALL set it to `0` when there are none.

#### Scenario: PII was redacted

- **WHEN** the API redacts two matches
- **THEN** `X-PII-Detected` names the kinds and `X-PII-Redacted-Count` is 2

#### Scenario: Nothing was detected

- **WHEN** the API detects nothing
- **THEN** `X-PII-Detected` is absent and `X-PII-Redacted-Count` is 0

#### Scenario: The same body is redacted twice

- **WHEN** a client posts the same body holding two kinds twice
- **THEN** both responses carry the same `X-PII-Detected` value
