## MODIFIED Requirements

### Requirement: The proxy serves plain HTTP only

The reverse proxy listener SHALL accept plain HTTP. TLS termination is not built. A
config that sets `reverse_proxy.tls.enabled` to true SHALL fail validation, so the
listener never serves plaintext under a config that asks for TLS.

#### Scenario: TLS is enabled in the config

- **WHEN** `reverse_proxy.tls.enabled` is true
- **THEN** the proxy does not start, and no listener is bound

#### Scenario: TLS is disabled in the config

- **WHEN** `reverse_proxy.tls.enabled` is false or the `tls` table is absent
- **THEN** the listener accepts plain HTTP
