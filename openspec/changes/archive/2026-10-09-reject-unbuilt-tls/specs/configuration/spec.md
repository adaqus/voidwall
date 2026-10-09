## MODIFIED Requirements

### Requirement: Forward proxy and TLS settings parse but the mode does not run

The config schema SHALL accept a `forward_proxy` table and a `tls` table, and SHALL
validate them. The forward proxy runtime is not built. The proxy SHALL log one warning at
startup when `forward_proxy.enabled` is true, and SHALL continue with the other modes.
TLS is not built either, so validation SHALL reject a `tls` table that sets `enabled` to
true.

#### Scenario: Forward proxy is enabled

- **WHEN** `forward_proxy.enabled` is true
- **THEN** the proxy logs a warning that the mode is not yet implemented
- **AND** the proxy continues to start every other enabled mode

#### Scenario: Forward proxy schema rules still apply

- **WHEN** `forward_proxy.request` carries a key the schema does not define
- **THEN** validation fails, even though the mode does not run

#### Scenario: A disabled TLS table parses

- **WHEN** a `tls` table sets `enabled = false` and names `cert_path` and `key_path`
- **THEN** validation passes

## ADDED Requirements

### Requirement: Enabling TLS fails validation

Validation SHALL fail when `reverse_proxy.tls.enabled` or `forward_proxy.tls.enabled` is
true, whether or not that mode is enabled. The failure SHALL carry the `semantic`
category and SHALL name the key. The proxy SHALL NOT start and serve plaintext in place
of the TLS the config asks for.

#### Scenario: Reverse proxy TLS is enabled

- **WHEN** `reverse_proxy.tls.enabled` is true
- **THEN** validation fails with the `semantic` category naming `reverse_proxy.tls.enabled`
- **AND** the proxy does not start

#### Scenario: Forward proxy TLS is enabled

- **WHEN** `forward_proxy.tls.enabled` is true
- **THEN** validation fails with the `semantic` category naming `forward_proxy.tls.enabled`
- **AND** the proxy does not start

#### Scenario: TLS is enabled for a disabled mode

- **WHEN** `forward_proxy.enabled` is false and `forward_proxy.tls.enabled` is true
- **THEN** validation fails naming `forward_proxy.tls.enabled`
