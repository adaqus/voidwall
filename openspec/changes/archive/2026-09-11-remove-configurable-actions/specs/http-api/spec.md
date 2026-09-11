## ADDED Requirements

### Requirement: The API serves three routes

The HTTP API listener SHALL serve `POST /v1/scan`, `GET /v1/info`, and
`GET /openapi.json`. It SHALL NOT serve a health probe, a readiness probe, or a config
endpoint. Those live on the admin listener, or nowhere.

#### Scenario: Client calls a served route

- **WHEN** a client sends a request to one of the three routes
- **THEN** the listener answers it

#### Scenario: Client asks for the scanner configuration

- **WHEN** a client requests a config endpoint on the API listener
- **THEN** no such route exists

#### Scenario: Client calls the retired redaction route

- **WHEN** a client posts to `/v1/redact`
- **THEN** the listener returns 404, because no such route exists

## MODIFIED Requirements

### Requirement: A scanner error follows the on_error policy

A scanner failure SHALL return 500 under `fail_close`. Under `fail_open` the API SHALL
answer normally.

#### Scenario: Scanner fails under fail_close

- **WHEN** the scanner errors and `on_error` is `fail_close`
- **THEN** the API returns 500

#### Scenario: Scanner fails under fail_open

- **WHEN** the scanner errors on `/v1/scan` and `on_error` is `fail_open`
- **THEN** the API answers 200 with a report that detects nothing

### Requirement: Custom PII labels surface in the results

An operator-defined label from `[[pii.custom]]` SHALL appear in the `kinds` array of
`/v1/scan`.

#### Scenario: A custom definition matches

- **WHEN** a custom definition matches the posted body
- **THEN** `/v1/scan` lists the configured label in `kinds`

## REMOVED Requirements

### Requirement: The API serves four routes

**Reason**: `POST /v1/redact` is deleted. The rule survives as *The API serves three
routes*, which keeps the same prohibition on health, readiness, and config endpoints.
**Migration**: Stop calling `/v1/redact`. The other three routes are unchanged.

### Requirement: POST /v1/redact returns the redacted body

**Reason**: Redaction is deleted from the product. The endpoint has no behaviour left to
describe.
**Migration**: Call `POST /v1/scan` to learn what a body carries. There is no supported
way to obtain a redacted body from Voidwall.

### Requirement: Redaction metadata travels in headers

**Reason**: Both headers belonged to `/v1/redact`. `X-PII-Detected` is deleted across the
product, and `X-PII-Redacted-Count` counted replacements that no longer happen.
**Migration**: Read the `kinds` array and `matches_count` of a `/v1/scan` response
instead.
