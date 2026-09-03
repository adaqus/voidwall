## MODIFIED Requirements

### Requirement: A specialization failure is logged at a bounded rate and always counted

The proxy SHALL emit at most one log line per specialization per minute. The line SHALL
name the specialization and the failure category, and SHALL never carry payload
content. The proxy SHALL increment `voidwall_specialization_errors_total` on every
failure, with no rate limit.

#### Scenario: Many failures in one minute

- **WHEN** a specialization fails many times inside one minute
- **THEN** the proxy logs once and increments the counter once per failure

#### Scenario: A failure is logged

- **WHEN** the proxy logs a specialization failure
- **THEN** the line names the specialization and the reason, and carries no payload text
