## ADDED Requirements

### Requirement: A block from another guard wins over a guard error

When one guard fails and another guard reports a finding for the same message, the proxy
SHALL answer the fixed 403 for the detection, under `fail_open` and under `fail_close`
alike. The `on_error` policy SHALL apply only when no guard reports a finding.

When the engine receives the guard error before the block, the proxy SHALL still write
the error to the log, and SHALL still increment `voidwall_errors_total` for it. A guard
still running when the block arrives is abandoned, so an error it would have returned is
neither logged nor counted.

#### Scenario: A guard fails and another guard detects under fail_open

- **WHEN** one guard fails, another guard reports a finding, and `on_error` is `fail_open`
- **THEN** the proxy answers 403 naming the detected kind and does not forward the message

#### Scenario: A guard error that arrives before the block is counted

- **WHEN** one guard fails and another guard then reports a finding
- **THEN** the proxy answers 403, logs the error, and increments `voidwall_errors_total`
  with `outcome="blocked"`

#### Scenario: A guard fails and another guard detects under fail_close

- **WHEN** one guard fails, another guard reports a finding, and `on_error` is `fail_close`
- **THEN** the proxy answers 403 naming the detected kind, not 500

#### Scenario: A guard fails and no guard detects under fail_open

- **WHEN** one guard fails, no guard reports a finding, and `on_error` is `fail_open`
- **THEN** the proxy forwards the message

#### Scenario: A guard fails and no guard detects under fail_close

- **WHEN** one guard fails, no guard reports a finding, and `on_error` is `fail_close`
- **THEN** the proxy answers 500 with the body `{"error":"internal error"}`
