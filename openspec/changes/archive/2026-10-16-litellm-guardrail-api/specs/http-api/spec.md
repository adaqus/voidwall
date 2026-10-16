## RENAMED Requirements

- FROM: `### Requirement: The API serves one route`
- TO: `### Requirement: The API serves the scan route and the LiteLLM route`

## MODIFIED Requirements

### Requirement: The API serves the scan route and the LiteLLM route

The HTTP API listener SHALL serve `POST /v1/scan` when `http_api.scan.enabled` is true.
It SHALL serve `POST /beta/litellm_basic_guardrail_api` when `http_api.litellm.enabled`
is true, as the `litellm-guardrail-api` capability states. A route whose switch is false
SHALL NOT exist. The listener SHALL serve nothing else. It SHALL NOT serve a health
probe, a readiness probe, a config endpoint, a detection-surface endpoint, or a
specification endpoint. Those live on the admin listener, in the repository, or nowhere.

#### Scenario: Client calls the served route

- **WHEN** `http_api.scan.enabled` is not set and a client sends `POST /v1/scan`
- **THEN** the listener answers it

#### Scenario: Client calls the LiteLLM route

- **WHEN** `http_api.litellm.enabled` is true and a client sends
  `POST /beta/litellm_basic_guardrail_api`
- **THEN** the listener answers it

#### Scenario: The scan route is off

- **WHEN** `http_api.scan.enabled` is false and a client sends `POST /v1/scan`
- **THEN** the listener returns 404, because no such route exists
- **AND** `POST /beta/litellm_basic_guardrail_api` is still served

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

### Requirement: The request body is the content to scan

On `/v1/scan`, the API SHALL treat the raw request body as the content. There SHALL be
no JSON envelope and no `text` field. The `Content-Type` header SHALL drive the parsing,
using the same routing as the proxy modes.

#### Scenario: Plain text body

- **WHEN** a client posts `text/plain` to `/v1/scan`
- **THEN** the API scans the raw bytes as flat text

#### Scenario: JSON body

- **WHEN** a client posts `application/json` to `/v1/scan`
- **THEN** the API flattens it by key path and scans the fragments

#### Scenario: CSV body with no header row

- **WHEN** a client posts a CSV body with no detectable header row to `/v1/scan`
- **THEN** the API falls back to flat text scanning, matching proxy behaviour

### Requirement: Scan and body limits match the proxy

The top-level `max_body_size` SHALL apply to every API route exactly as it applies to a
proxy mode. The top-level `content_types` allowlist SHALL apply to `/v1/scan` exactly as
it applies to a proxy mode. It SHALL NOT apply to the LiteLLM route, which accepts JSON
only.

The API SHALL run every enabled guard. It SHALL NOT carry a guard selection of its own,
because it has no route to attach one to.

#### Scenario: Body is too large

- **WHEN** a posted body exceeds `max_body_size`
- **THEN** the API returns 413

#### Scenario: Content type is not allowed

- **WHEN** a body posted to `/v1/scan` carries a content type outside `content_types`
- **THEN** the API returns 415

#### Scenario: Every enabled guard runs

- **WHEN** a client posts a body to `/v1/scan`
- **THEN** every enabled guard is called with the units its surface admits

### Requirement: The OpenAPI document is published as a repository file

The repository SHALL hold an OpenAPI 3.x document at `docs/openapi.json` describing
`POST /v1/scan` and `POST /beta/litellm_basic_guardrail_api`. It SHALL be generated from
the route handlers and the request and response types, so it cannot drift from the
implementation. A test SHALL fail when the generated document and the checked-in file
differ.

#### Scenario: A consumer reads the contract

- **WHEN** a consumer opens `docs/openapi.json`
- **THEN** the document describes `POST /v1/scan`, its accepted content types, its
  response shape, and its status codes

#### Scenario: A consumer reads the LiteLLM contract

- **WHEN** a consumer opens `docs/openapi.json`
- **THEN** the document describes `POST /beta/litellm_basic_guardrail_api`, its request
  shape, its `NONE` and `BLOCKED` response shapes, and its status codes

#### Scenario: The handler changes without regenerating the document

- **WHEN** a change alters a route, a request type, or a response type and leaves
  `docs/openapi.json` untouched
- **THEN** the freshness test fails
