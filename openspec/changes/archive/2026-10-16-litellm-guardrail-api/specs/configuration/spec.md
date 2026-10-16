## ADDED Requirements

### Requirement: Each HTTP API route has its own switch

`http_api.scan.enabled` SHALL turn the `POST /v1/scan` route on or off.
`http_api.litellm.enabled` SHALL turn the LiteLLM Generic Guardrail API route on or off.
Each SHALL be a boolean and SHALL default to true. A value that is not a boolean SHALL
fail config loading with the `schema` category. A key under `http_api.scan` or
`http_api.litellm` other than `enabled` SHALL fail it as an unknown key.

`http_api.enabled` SHALL start the listener. While it is false, the route switches SHALL
have no effect and SHALL be valid whatever they say. While it is true, validation SHALL
fail with the `semantic` category when every route switch is false.

#### Scenario: Both tables are absent

- **WHEN** the config enables `http_api` and has no `http_api.scan` or `http_api.litellm`
  table
- **THEN** validation passes and both routes are on

#### Scenario: Only the LiteLLM route

- **WHEN** the config enables `http_api` and sets `http_api.scan.enabled = false`
- **THEN** validation passes, the LiteLLM route is on, and `/v1/scan` is off

#### Scenario: Only the scan route

- **WHEN** the config enables `http_api` and sets `http_api.litellm.enabled = false`
- **THEN** validation passes, `/v1/scan` is on, and the LiteLLM route is off

#### Scenario: Every route is off

- **WHEN** the config enables `http_api` and sets both `http_api.scan.enabled` and
  `http_api.litellm.enabled` to false
- **THEN** validation fails with the `semantic` category and names both switches

#### Scenario: The value is not a boolean

- **WHEN** the config sets `http_api.litellm.enabled = "yes"`
- **THEN** loading fails with the `schema` category and the proxy does not start

#### Scenario: An unknown key in a route table

- **WHEN** the config sets `http_api.litellm.path = "/x"`
- **THEN** loading fails naming the unknown key

#### Scenario: The HTTP API is disabled

- **WHEN** the config sets `http_api.enabled = false`, sets both route switches to false,
  and enables the reverse proxy
- **THEN** validation passes and no HTTP API route is served
