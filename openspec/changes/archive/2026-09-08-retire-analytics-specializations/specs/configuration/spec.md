## ADDED Requirements

### Requirement: An unknown configuration key is rejected

Every table in the configuration file SHALL accept only the keys its schema defines. A key
the schema does not define SHALL fail validation at startup, naming the key. The proxy SHALL
NOT start on such a file.

#### Scenario: A misspelled key

- **WHEN** a configuration file carries a key no table defines
- **THEN** validation fails naming the key and the proxy does not start

#### Scenario: A retired key

- **WHEN** a reverse-proxy route carries `specialization`
- **THEN** validation fails naming the key and the proxy does not start

#### Scenario: Every defined key is accepted

- **WHEN** a configuration file carries only keys the schema defines
- **THEN** validation passes and the proxy starts

### Requirement: Reverse proxy route identity and upstream are validated

A `path_prefix` SHALL be unique across the routes. An `upstream` SHALL parse as a URI
carrying an `http` or `https` scheme and an authority.

#### Scenario: Duplicate path prefix

- **WHEN** two routes carry the same `path_prefix`
- **THEN** validation fails naming the prefix

#### Scenario: Upstream lacks a scheme or an authority

- **WHEN** a route names an upstream with no `http` or `https` scheme, or no authority
- **THEN** validation fails naming the upstream

## REMOVED Requirements

### Requirement: Reverse proxy routes are validated

**Reason**: The requirement bound route identity, upstream validity, and specialization
resolution into one block. The analytics specializations are retired, so its third clause
and the scenario that covered it describe behaviour that no longer exists.

**Migration**: The surviving clauses continue unchanged under "Reverse proxy route identity
and upstream are validated". A route that still names a specialization is now caught by the
unknown-key requirement instead, which fails at startup naming the key.

A `path_prefix` SHALL be unique across the routes. An `upstream` SHALL parse as a URI
carrying an `http` or `https` scheme and an authority. A named `specialization` SHALL
match a built-in specialization.

#### Scenario: Duplicate path prefix

- **WHEN** two routes carry the same `path_prefix`
- **THEN** validation fails naming the prefix

#### Scenario: Upstream lacks a scheme or an authority

- **WHEN** a route names an upstream with no `http` or `https` scheme, or no authority
- **THEN** validation fails naming the upstream

#### Scenario: Unknown specialization

- **WHEN** a route names a specialization that does not exist
- **THEN** validation fails naming the route and the specialization
