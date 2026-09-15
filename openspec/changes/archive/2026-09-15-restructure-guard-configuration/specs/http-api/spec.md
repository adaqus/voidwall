## MODIFIED Requirements

### Requirement: Scan and body limits match the proxy

The top-level `content_types` allowlist and `max_body_size` SHALL apply to the API
exactly as they apply to a proxy mode.

The API SHALL run every enabled guard. It SHALL NOT carry a guard selection of its own,
because it has no route to attach one to.

#### Scenario: Body is too large

- **WHEN** a posted body exceeds `max_body_size`
- **THEN** the API returns 413

#### Scenario: Content type is not allowed

- **WHEN** a posted body carries a content type outside `content_types`
- **THEN** the API returns 415

#### Scenario: Every enabled guard runs

- **WHEN** a client posts a body to `/v1/scan`
- **THEN** every enabled guard is called with the units its surface admits

### Requirement: Custom PII labels surface in the results

An operator-defined label from `[[builtin_guards.pii.custom]]` SHALL appear in the
`kinds` array of `/v1/scan`.

#### Scenario: A custom definition matches

- **WHEN** a custom definition matches the posted body
- **THEN** `/v1/scan` lists the configured label in `kinds`
