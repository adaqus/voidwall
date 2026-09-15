## MODIFIED Requirements

### Requirement: Body scanning respects the content type and the target flags

The proxy SHALL scan a body only when at least one guard selected for the route admits
the body in its surface, the body is non-empty, and the content type appears in the
top-level `content_types` list.

#### Scenario: Content type is outside the allowlist

- **WHEN** a request body carries a content type outside `content_types`
- **THEN** the proxy does not scan the body

#### Scenario: Body is empty

- **WHEN** a request carries no body bytes
- **THEN** the proxy does not scan the body

#### Scenario: No selected guard admits the body

- **WHEN** every guard selected for the route sets `surface.body` to false
- **THEN** the proxy does not scan the body

### Requirement: The URL path, the query, and listed headers are scannable

The proxy SHALL scan the URL path and the query string for a guard whose surface admits
them, and SHALL scan the value of every header the route names. A unit no selected guard
admits SHALL NOT be built, and a header the route does not name SHALL NOT be built.

#### Scenario: PII sits in the query string

- **WHEN** a selected guard sets `surface.query_params` to true and the query holds an
  email address
- **THEN** the proxy detects it and blocks the request

#### Scenario: PII sits in a header the route names

- **WHEN** a route names a header and a request carries an email address in it
- **THEN** the proxy detects it and blocks the request

#### Scenario: Two guards admit different surfaces

- **WHEN** one selected guard admits the body only and another admits the query only
- **THEN** each guard is called with its own units and neither sees the other's

## REMOVED Requirements

### Requirement: A route may override the scan settings

**Reason**: The `scan` table no longer exists, so a route has nothing to override. Route
behaviour is now guard selection, stated once under `guard-configuration` in
"A route selects guards by name" rather than restated here.

**Migration**: Replace a route's `scan` table with `guards`, a list of guard names. A
route that switched detection off for one path uses `guards = []`. A route that narrowed
the inspected surface declares a guard carrying that surface and names it in `guards`.
