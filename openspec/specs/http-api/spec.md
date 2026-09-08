## Purpose

The HTTP API exposes PII scanning and redaction to other services. A caller posts the
content directly as the request body and gets back either a detection report or the
redacted body.

## Requirements

### Requirement: The API serves four routes

The HTTP API listener SHALL serve `POST /v1/scan`, `POST /v1/redact`, `GET /v1/info`,
and `GET /openapi.json`. It SHALL NOT serve a health probe, a readiness probe, or a
config endpoint. Those live on the admin listener, or nowhere.

#### Scenario: Client calls a served route

- **WHEN** a client sends a request to one of the four routes
- **THEN** the listener answers it

#### Scenario: Client asks for the scanner configuration

- **WHEN** a client requests a config endpoint on the API listener
- **THEN** no such route exists

### Requirement: The request body is the content to scan

The API SHALL treat the raw request body as the content. There SHALL be no JSON
envelope and no `text` field. The `Content-Type` header SHALL drive the parsing, using
the same routing as the proxy modes.

#### Scenario: Plain text body

- **WHEN** a client posts `text/plain`
- **THEN** the API scans the raw bytes as flat text

#### Scenario: JSON body

- **WHEN** a client posts `application/json`
- **THEN** the API flattens it by key path and scans the fragments

#### Scenario: CSV body with no header row

- **WHEN** a client posts a CSV body with no detectable header row
- **THEN** the API falls back to flat text scanning, matching proxy behaviour

### Requirement: Scan and body limits match the proxy

The `scan.content_types` allowlist and `scan.max_body_size` SHALL apply to the API
exactly as they apply to a proxy mode.

#### Scenario: Body is too large

- **WHEN** a posted body exceeds `max_body_size`
- **THEN** the API returns 413

#### Scenario: Content type is not allowed

- **WHEN** a posted body carries a content type outside `scan.content_types`
- **THEN** the API returns 415

### Requirement: A malformed structured body is always a client error

A body that does not parse as its declared content type SHALL return 400, whatever
`on_error` says. The caller declared the type, so a silent fallback would hide their
bug.

#### Scenario: Body claims JSON but does not parse

- **WHEN** a client posts a malformed body with `Content-Type: application/json`
- **THEN** the API returns 400, under `fail_open` and under `fail_close` alike

### Requirement: A scanner error follows the on_error policy

A scanner failure SHALL return 500 under `fail_close`. Under `fail_open` the API SHALL
answer normally, and `/v1/redact` SHALL return the body unredacted with
`X-PII-Redacted-Count: 0`.

#### Scenario: Scanner fails under fail_close

- **WHEN** the scanner errors and `on_error` is `fail_close`
- **THEN** the API returns 500

#### Scenario: Scanner fails under fail_open

- **WHEN** the scanner errors on `/v1/redact` and `on_error` is `fail_open`
- **THEN** the API returns the original body with `X-PII-Redacted-Count: 0`

### Requirement: POST /v1/scan reports the detection

`/v1/scan` SHALL return JSON holding `detected`, `matches_count`, and `kinds`. It SHALL
NOT echo the body. `matches_count` SHALL be the size of the resolved match set. `kinds`
SHALL hold kind names only, never a matched value.

#### Scenario: Body carries PII

- **WHEN** a client posts a body holding an email address and a national number
- **THEN** the response reports `detected` true, the resolved match count, and both kind
  names

#### Scenario: Body is clean

- **WHEN** a client posts a body with no PII
- **THEN** the response reports `detected` false and an empty `kinds` array

### Requirement: POST /v1/redact returns the redacted body

`/v1/redact` SHALL return the body with the PII replaced in place. The response content
type SHALL mirror the request. A JSON body SHALL stay valid JSON, and a CSV body SHALL
stay valid CSV. The match metadata SHALL travel in response headers, so the body keeps
its format.

#### Scenario: JSON body is redacted

- **WHEN** a client posts JSON holding PII to `/v1/redact`
- **THEN** the response body is still valid JSON with the values replaced

### Requirement: Redaction metadata travels in headers

`/v1/redact` SHALL set `X-PII-Detected` to the comma-separated kind names, and SHALL
omit that header when nothing is detected. It SHALL set `X-PII-Redacted-Count` to the
number of redactions, and SHALL set it to `0` when there are none.

#### Scenario: PII was redacted

- **WHEN** the API redacts two matches
- **THEN** `X-PII-Detected` names the kinds and `X-PII-Redacted-Count` is 2

#### Scenario: Nothing was detected

- **WHEN** the API detects nothing
- **THEN** `X-PII-Detected` is absent and `X-PII-Redacted-Count` is 0

### Requirement: Custom PII labels surface in the results

An operator-defined label from `[[pii.custom]]` SHALL appear in the `kinds` array of
`/v1/scan`, and SHALL be used as the `type_label` replacement by `/v1/redact`.

#### Scenario: A custom definition matches

- **WHEN** a custom definition matches the posted body
- **THEN** `/v1/scan` lists the configured label in `kinds`

### Requirement: GET /v1/info lists the detection surface

`/v1/info` SHALL return JSON holding the build version, the supported keyword
languages, and every built-in PII kind label. It SHALL exclude the `Custom` kind, whose
labels are per-deployment.

#### Scenario: Client asks what the deployment detects

- **WHEN** a client sends `GET /v1/info`
- **THEN** the response holds the version, the language codes, and the built-in kind
  labels
- **AND** the generic `Custom` label is absent

### Requirement: GET /openapi.json serves a generated specification

The API SHALL serve an OpenAPI 3.x document at `/openapi.json`. It SHALL be generated
from the route handlers and the request and response types, so it cannot drift from the
implementation.

#### Scenario: Client fetches the specification

- **WHEN** a client sends `GET /openapi.json`
- **THEN** the API returns the OpenAPI document describing the four routes

### Requirement: The API provides no authentication

The HTTP API SHALL NOT authenticate a caller. Access control is the deployment's job:
an authenticating gateway in front, plus network-level isolation.

#### Scenario: Unauthenticated client calls the API

- **WHEN** any client reaches the API listener
- **THEN** the API serves the request, because it holds no credential check
