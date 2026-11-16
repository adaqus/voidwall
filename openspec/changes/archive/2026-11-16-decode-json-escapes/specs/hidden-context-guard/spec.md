## MODIFIED Requirements

### Requirement: The guard scans the response body only

The guard SHALL be passed the body unit of a response and no other unit. It SHALL NOT
be passed a request unit, a URL path, a query string, or a header value. A request that
holds a marker SHALL NOT be reported by this guard.

For a structured body, the guard SHALL match each parsed value on its own, in its decoded
form. A marker split across two values SHALL NOT match.

#### Scenario: The marker is in the system message of a request

- **WHEN** a request to an `openai-chat` route carries a marker in its system message
- **THEN** the `hidden_context` guard reports nothing and the request is forwarded

#### Scenario: The marker is in a response header

- **WHEN** a route names the header `x-debug` for scanning and an upstream response
  carries a marker in it, with a clean body
- **THEN** the `hidden_context` guard reports nothing

#### Scenario: The marker is in a JSON response value

- **WHEN** a generic route's upstream answers a JSON body whose value holds a marker
- **THEN** the guard reports a finding

#### Scenario: The marker is written with an escape in a JSON response value

- **WHEN** a marker holds a non-ASCII letter, and a generic route's upstream answers a JSON
  body whose value holds the marker with that letter written as a `\uXXXX` escape
- **THEN** the guard reports a finding

#### Scenario: The LiteLLM request side

- **WHEN** a LiteLLM guardrail call with `input_type` `request` holds a marker
- **THEN** the `hidden_context` guard reports nothing

#### Scenario: The LiteLLM response side

- **WHEN** a LiteLLM guardrail call with `input_type` `response` holds a marker in `texts`
- **THEN** the guard reports a finding and the route answers `BLOCKED`
