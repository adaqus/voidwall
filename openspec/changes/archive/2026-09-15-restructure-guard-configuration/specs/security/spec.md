## MODIFIED Requirements

### Requirement: An invalid configuration stops the start

The proxy SHALL refuse to start on an invalid config. It SHALL NOT drop an invalid entry
and continue. Silently dropping a declared PII definition would weaken detection without
telling the operator.

Enabling no guard SHALL NOT be treated as an invalid config. It SHALL warn at startup
instead, because it states a deployment with nothing to inspect rather than a
configuration the proxy cannot honour.

#### Scenario: A custom pattern does not compile

- **WHEN** one `[[builtin_guards.pii.custom]]` pattern fails to compile
- **THEN** the proxy exits with an error instead of running without that definition

#### Scenario: No guard is enabled

- **WHEN** the config enables a mode and no guard
- **THEN** the proxy starts and logs a warning naming the empty guard set
