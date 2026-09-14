## ADDED Requirements

### Requirement: The API serves one route

The HTTP API listener SHALL serve `POST /v1/scan` and nothing else. It SHALL NOT serve a
health probe, a readiness probe, a config endpoint, a detection-surface endpoint, or a
specification endpoint. Those live on the admin listener, in the repository, or nowhere.

#### Scenario: Client calls the served route

- **WHEN** a client sends `POST /v1/scan`
- **THEN** the listener answers it

#### Scenario: Client asks for the scanner configuration

- **WHEN** a client requests a config endpoint on the API listener
- **THEN** no such route exists

#### Scenario: Client calls the retired redaction route

- **WHEN** a client posts to `/v1/redact`
- **THEN** the listener returns 404, because no such route exists

#### Scenario: Client calls the retired detection-surface route

- **WHEN** a client sends `GET /v1/info`
- **THEN** the listener returns 404, because no such route exists

#### Scenario: Client calls the retired specification route

- **WHEN** a client sends `GET /openapi.json`
- **THEN** the listener returns 404, because no such route exists

### Requirement: The OpenAPI document is published as a repository file

The repository SHALL hold an OpenAPI 3.x document at `docs/openapi.json` describing
`POST /v1/scan`. It SHALL be generated from the route handler and the request and
response types, so it cannot drift from the implementation. A test SHALL fail when the
generated document and the checked-in file differ.

#### Scenario: A consumer reads the contract

- **WHEN** a consumer opens `docs/openapi.json`
- **THEN** the document describes `POST /v1/scan`, its accepted content types, its
  response shape, and its status codes

#### Scenario: The handler changes without regenerating the document

- **WHEN** a change alters the route, the request type, or a response type and leaves
  `docs/openapi.json` untouched
- **THEN** the freshness test fails

## REMOVED Requirements

### Requirement: The API serves three routes

**Reason**: `GET /v1/info` and `GET /openapi.json` are deleted. The rule survives as
*The API serves one route*, which keeps the same prohibition on health, readiness, and
config endpoints and extends it to the two deleted routes.
**Migration**: Stop calling `/v1/info` and `/openapi.json`. `POST /v1/scan` is unchanged.

### Requirement: GET /v1/info lists the detection surface

**Reason**: The route described the deployment rather than inspecting a message. It cost
a public endpoint on an unauthenticated listener and returned nothing a caller needs to
scan a body.
**Migration**: The built-in kind labels are listed in the `kinds` property description of
`docs/openapi.json`. A caller that needs the kinds a body carries reads the `kinds` array
of a `POST /v1/scan` response.

### Requirement: GET /openapi.json serves a generated specification

**Reason**: The document is still generated from the handlers, but it no longer needs a
runtime route. Serving it required a permissive cross-origin layer on the public
listener and a spec-generation step on every start.
**Migration**: Read `docs/openapi.json` from the repository instead of fetching
`http://<api>/openapi.json`.
