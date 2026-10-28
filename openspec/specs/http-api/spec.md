## Purpose

The HTTP API exposes PII scanning and redaction to other services. A caller posts the
content directly as the request body and gets back either a detection report or the
redacted body.

## Requirements

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

### Requirement: A malformed structured body is always a client error

A body that does not parse as its declared content type SHALL return 400, whatever
`on_error` says. The caller declared the type, so a silent fallback would hide their
bug.

#### Scenario: Body claims JSON but does not parse

- **WHEN** a client posts a malformed body with `Content-Type: application/json`
- **THEN** the API returns 400, under `fail_open` and under `fail_close` alike

### Requirement: A scanner error follows the on_error policy

A scanner failure SHALL return 500 under `fail_close`, even when another guard reported a
finding. Under `fail_open` the API SHALL answer 200 with a report built from the findings
of the guards that succeeded.

The 500 body SHALL be exactly `{"error":"internal error"}`. It SHALL carry no detail of
the failure.

#### Scenario: Scanner fails under fail_close

- **WHEN** the scanner errors and `on_error` is `fail_close`
- **THEN** the API returns 500
- **AND** the body is exactly `{"error":"internal error"}`

#### Scenario: Scanner fails under fail_open

- **WHEN** the scanner errors on `/v1/scan` and `on_error` is `fail_open`
- **THEN** the API answers 200 with a report that detects nothing

#### Scenario: A guard fails and another guard detects under fail_open

- **WHEN** one guard fails on `/v1/scan`, another guard reports a finding, and `on_error`
  is `fail_open`
- **THEN** the API answers 200 with a report holding the finding of the guard that
  succeeded

#### Scenario: A guard fails and another guard detects under fail_close

- **WHEN** one guard fails on `/v1/scan`, another guard reports a finding, and `on_error`
  is `fail_close`
- **THEN** the API returns 500
- **AND** the body is exactly `{"error":"internal error"}`

### Requirement: POST /v1/scan reports the detection

`/v1/scan` SHALL return JSON holding `detected`, `matches_count`, `kinds`, and `guards`. It
SHALL NOT echo the body. `matches_count` SHALL be the size of the resolved match set, plus
one for each finding a model guard reported. `kinds` SHALL hold kind names only, never a
matched value. `kinds` SHALL be sorted and SHALL hold each kind once, so two scans of the
same body return the same array.

`guards` SHALL be an array holding one object for each guard that reported at least one
finding, sorted by guard name. A guard that reported no finding SHALL NOT appear, so a
scan with no findings returns an empty array. Each object SHALL hold `name`,
`matches_count`, and `kinds`:

- `name` SHALL be the name configuration gave the guard.
- `matches_count` SHALL be the number of findings that guard reported. The `matches_count`
  values of all objects SHALL add up to the top-level `matches_count`.
- `kinds` SHALL hold the kind names that guard reported, sorted, each kind once, never a
  matched value.

#### Scenario: Body carries PII

- **WHEN** a client posts a body holding an email address and a national number
- **THEN** the response reports `detected` true, the resolved match count, and both kind
  names

#### Scenario: Body is clean

- **WHEN** a client posts a body with no PII
- **THEN** the response reports `detected` false, an empty `kinds` array, and an empty
  `guards` array

#### Scenario: The same body is posted twice

- **WHEN** a client posts the same body holding two kinds twice
- **THEN** both responses carry the same `kinds` array in the same sorted order

#### Scenario: A model guard reports a finding

- **WHEN** a model guard with `labels = ["PROMPT_INJECTION"]` scores the posted body at or
  above its threshold, and the body holds no PII
- **THEN** the response reports `detected` true, `matches_count` 1, and `kinds`
  `["PROMPT_INJECTION"]`

#### Scenario: Two guards report the same kind for one value

- **WHEN** the `pii` guard, through a custom definition labelled `SECRET`, and a model
  guard named `pii_ml` each report one `SECRET` finding for the same word in the posted
  body
- **THEN** the response reports `matches_count` 2 and `kinds` `["SECRET"]`
- **AND** `guards` is `[{"name":"pii","matches_count":1,"kinds":["SECRET"]},
  {"name":"pii_ml","matches_count":1,"kinds":["SECRET"]}]`

#### Scenario: Only guards with findings are listed

- **WHEN** two guards are configured and only one of them reports a finding for the posted
  body
- **THEN** `guards` holds one object, naming the guard that reported the finding

### Requirement: Custom PII labels surface in the results

An operator-defined label from `[[builtin_guards.pii.custom]]` SHALL appear in the
`kinds` array of `/v1/scan`.

#### Scenario: A custom definition matches

- **WHEN** a custom definition matches the posted body
- **THEN** `/v1/scan` lists the configured label in `kinds`

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

### Requirement: The API provides no authentication

The HTTP API SHALL NOT authenticate a caller. Access control is the deployment's job:
an authenticating gateway in front, plus network-level isolation.

#### Scenario: Unauthenticated client calls the API

- **WHEN** any client reaches the API listener
- **THEN** the API serves the request, because it holds no credential check

### Requirement: A window-limit error follows the on_error policy

When a model guard needs more windows for a unit than its window limit, `/v1/scan` SHALL
follow `on_error`. Under `fail_close` it SHALL answer 413 with the body exactly
`{"error":"tokenized content too long to scan"}`, even when another guard reported a
finding. Under `fail_open` it SHALL answer 200 with a report built from the findings of
the guards that succeeded.

#### Scenario: Window limit under fail_close

- **WHEN** a model guard hits its window limit on `/v1/scan` and `on_error` is
  `fail_close`
- **THEN** the API answers 413 with the body
  `{"error":"tokenized content too long to scan"}`

#### Scenario: Window limit under fail_open

- **WHEN** a model guard hits its window limit on `/v1/scan`, another guard reports a
  finding, and `on_error` is `fail_open`
- **THEN** the API answers 200 with a report holding the finding of the guard that
  succeeded

### Requirement: A model guard inference failure is a scanner error

A model guard's inference failure SHALL follow the requirement "A scanner error follows the
on_error policy": 500 with the fixed body under `fail_close`, 200 with the findings of
the guards that succeeded under `fail_open`.

#### Scenario: Inference fails under fail_close

- **WHEN** a model guard's inference fails on `/v1/scan` and `on_error` is `fail_close`
- **THEN** the API answers 500 with the body `{"error":"internal error"}`
