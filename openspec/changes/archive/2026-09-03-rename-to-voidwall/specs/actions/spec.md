## MODIFIED Requirements

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
