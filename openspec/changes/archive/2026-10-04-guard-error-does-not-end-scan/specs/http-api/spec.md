## MODIFIED Requirements

### Requirement: A scanner error follows the on_error policy

A scanner failure SHALL return 500 under `fail_close`, even when another guard reported a
finding. Under `fail_open` the API SHALL answer 200 with a report built from the findings
of the guards that succeeded.

The 500 body SHALL be exactly `{"error":"internal error"}`. It SHALL carry no detail of
the failure.

#### Scenario: Scanner fails under fail_close

- **WHEN** the scanner errors and `on_error` is `fail_close`
- **THEN** the API returns 500
- **AND** the body is exactly `{"error":"internal error"}`

#### Scenario: Scanner fails under fail_open

- **WHEN** the scanner errors on `/v1/scan` and `on_error` is `fail_open`
- **THEN** the API answers 200 with a report that detects nothing

#### Scenario: A guard fails and another guard detects under fail_open

- **WHEN** one guard fails on `/v1/scan`, another guard reports a finding, and `on_error`
  is `fail_open`
- **THEN** the API answers 200 with a report holding the finding of the guard that
  succeeded

#### Scenario: A guard fails and another guard detects under fail_close

- **WHEN** one guard fails on `/v1/scan`, another guard reports a finding, and `on_error`
  is `fail_close`
- **THEN** the API returns 500
- **AND** the body is exactly `{"error":"internal error"}`
