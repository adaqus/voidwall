## ADDED Requirements

### Requirement: The upstream timeout is a top-level key

`upstream_timeout_secs` SHALL be a top-level key. It SHALL be a whole number of seconds
from 1 to 3600 and SHALL default to 300. A value outside that range SHALL fail
validation with the `schema` category and prevent startup.

#### Scenario: The key is absent

- **WHEN** the config does not set `upstream_timeout_secs`
- **THEN** the upstream timeout is 300 seconds

#### Scenario: The key is set

- **WHEN** the config sets `upstream_timeout_secs = 60`
- **THEN** the upstream timeout is 60 seconds

#### Scenario: The key is zero

- **WHEN** the config sets `upstream_timeout_secs = 0`
- **THEN** validation fails naming `upstream_timeout_secs` and the proxy does not start

#### Scenario: The key is negative

- **WHEN** the config sets `upstream_timeout_secs = -1`
- **THEN** validation fails naming `upstream_timeout_secs` and the proxy does not start

#### Scenario: The key is at the upper bound

- **WHEN** the config sets `upstream_timeout_secs = 3600`
- **THEN** the upstream timeout is 3600 seconds

#### Scenario: The key is above the upper bound

- **WHEN** the config sets `upstream_timeout_secs = 3601`
- **THEN** validation fails naming `upstream_timeout_secs` and the proxy does not start
