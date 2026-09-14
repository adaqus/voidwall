## MODIFIED Requirements

### Requirement: Scanner failures follow the on_error policy

When the scanner fails, or the message exceeds a configured limit, the proxy SHALL follow
the `on_error` policy. `fail_open` SHALL forward the message. `fail_close` SHALL block it.
`fail_close` SHALL be the default. The proxy SHALL increment `voidwall_errors_total` with
the outcome that was taken.

#### Scenario: Scanner fails under fail_open

- **WHEN** the scanner returns an error and `on_error` is `fail_open`
- **THEN** the proxy forwards the message
- **AND** `voidwall_errors_total{outcome="passed"}` increments

#### Scenario: Scanner fails under fail_close

- **WHEN** the scanner returns an error and `on_error` is `fail_close`
- **THEN** the proxy blocks the message
- **AND** `voidwall_errors_total{outcome="blocked"}` increments

#### Scenario: The configuration names no policy

- **WHEN** `scan.on_error` is absent from the configuration and the scanner returns an error
- **THEN** the proxy blocks the message
- **AND** `voidwall_errors_total{outcome="blocked"}` increments

### Requirement: Content type allowlist

The scanner SHALL scan a body only when its content type appears in
`scan.content_types`. The default list SHALL hold `application/json`, `text/plain`,
`text/html`, `application/x-www-form-urlencoded`, `text/csv`, and
`text/tab-separated-values`.

A body whose content type sits outside the list SHALL be skipped in silence. That is not
an error. The `on_error` policy SHALL NOT apply to it and `voidwall_errors_total` SHALL
NOT increment.

#### Scenario: Content type is not allowed

- **WHEN** a body carries a content type outside the allowlist
- **THEN** the scanner does not scan the body

#### Scenario: A skipped content type is not an error

- **WHEN** a body carries a content type outside the allowlist and `on_error` is `fail_close`
- **THEN** the proxy forwards the message to the upstream unchanged
