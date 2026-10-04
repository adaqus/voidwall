## MODIFIED Requirements

### Requirement: A scanner error follows the on_error policy

A scanner failure SHALL return 500 under `fail_close`. Under `fail_open` the API SHALL
answer normally.

The 500 body SHALL be exactly `{"error":"internal error"}`. It SHALL carry no detail of
the failure.

#### Scenario: Scanner fails under fail_close

- **WHEN** the scanner errors and `on_error` is `fail_close`
- **THEN** the API returns 500
- **AND** the body is exactly `{"error":"internal error"}`

#### Scenario: Scanner fails under fail_open

- **WHEN** the scanner errors on `/v1/scan` and `on_error` is `fail_open`
- **THEN** the API answers 200 with a report that detects nothing
