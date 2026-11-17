## RENAMED Requirements

- FROM: `### Requirement: The guard scans every request unit and the raw text only`
- TO: `### Requirement: The guard scans every request unit through the decoded view`

## MODIFIED Requirements

### Requirement: The guard scans every request unit through the decoded view

The guard SHALL be passed every unit of a request-direction message: the body, the URL
path, the query string and every scanned header value. It SHALL NOT be passed a unit of
a response. It SHALL read the decoded view of a unit that the `encoded-content-decoding`
capability builds, never the scan view of the `hidden-unicode-normalization` capability.
In a structured body it SHALL read each fragment value after its JSON escapes are
decoded.

#### Scenario: Tag characters in a query string

- **WHEN** a request's query string holds the word `ignore` written as tag characters
- **THEN** the guard reports a finding

#### Scenario: Tag characters in a URL path

- **WHEN** a request's path holds the word `ignore` written as tag characters
- **THEN** the guard reports a finding

#### Scenario: Tag characters in a CSV cell

- **WHEN** a CSV request body holds a cell with the word `ignore` written as tag
  characters
- **THEN** the guard reports a finding

#### Scenario: Tag characters written as JSON escapes

- **WHEN** a JSON request value holds tag characters written as `\uXXXX` surrogate-pair
  escapes
- **THEN** the guard reports a finding

#### Scenario: Tag characters inside base64

- **WHEN** a request body holds a base64 run whose decoded text is the words `ignore all
  rules` written as tag characters
- **THEN** the guard reports a finding

#### Scenario: Tag characters inside base64 in a query string

- **WHEN** a request's query string holds a base64url run whose decoded text is the words
  `ignore all rules` written as tag characters
- **THEN** the run is not decoded, and the guard reports no finding for it

#### Scenario: Tag characters in a response

- **WHEN** a response body holds the word `ignore` written as tag characters
- **THEN** the guard is not called

#### Scenario: The LiteLLM request side

- **WHEN** a LiteLLM guardrail call with `input_type` `request` holds the word `ignore`
  written as tag characters in `texts`
- **THEN** the route answers `BLOCKED`, and `blocked_reason` names `INVISIBLE_TEXT`

#### Scenario: A route that does not select the guard

- **WHEN** a route sets `guards = ["prompt_injection"]` and a request body holds the word
  `ignore` written as tag characters
- **THEN** the `invisible_text` guard is not called for that route, and the tag run is
  not reported as `INVISIBLE_TEXT`
