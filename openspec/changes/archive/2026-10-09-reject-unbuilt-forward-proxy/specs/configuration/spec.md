## MODIFIED Requirements

### Requirement: At least one mode must be enabled

Validation SHALL fail when `reverse_proxy` and `http_api` are both disabled. The forward
proxy is not a mode that can be enabled, so it does not count.

#### Scenario: Every mode is disabled

- **WHEN** no mode has `enabled = true`
- **THEN** validation fails naming the missing mode

### Requirement: Forward proxy and TLS settings parse but the mode does not run

The config schema SHALL accept a `forward_proxy` table and a `tls` table, and SHALL
validate them. The forward proxy runtime is not built, so validation SHALL fail when
`forward_proxy.enabled` is true. The failure SHALL carry the `semantic` category and SHALL
name the key. This check SHALL run before the check that at least one mode is enabled.
TLS is not built either, so validation SHALL reject a `tls` table that sets `enabled` to
true.

#### Scenario: Forward proxy is enabled

- **WHEN** `forward_proxy.enabled` is true and another mode is enabled
- **THEN** validation fails with the `semantic` category naming `forward_proxy.enabled`
- **AND** the proxy does not start

#### Scenario: Only the forward proxy is enabled

- **WHEN** `forward_proxy.enabled` is true and no other mode is enabled
- **THEN** validation fails naming `forward_proxy.enabled`, not the missing mode

#### Scenario: A disabled forward proxy table parses

- **WHEN** a `forward_proxy` table sets `enabled = false` and names `listen`, `request`,
  and `response`
- **THEN** validation passes

#### Scenario: Forward proxy schema rules still apply

- **WHEN** `forward_proxy.request` carries a key the schema does not define
- **THEN** validation fails, even though the mode does not run

#### Scenario: A disabled TLS table parses

- **WHEN** a `tls` table sets `enabled = false` and names `cert_path` and `key_path`
- **THEN** validation passes
