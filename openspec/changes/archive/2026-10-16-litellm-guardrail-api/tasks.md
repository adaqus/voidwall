## 1. Configuration

- [x] 1.1 Add `RouteSwitch { enabled }` as `HttpApiConfig.scan` and `HttpApiConfig.litellm`, with `deny_unknown_fields` and a `Default` of `enabled: true` (design D6). Verify: unit tests for absent tables, each switch off alone, a non-boolean value (`schema` category), and an unknown key, each matching a scenario of `specs/configuration/spec.md`.
- [x] 1.2 Add the semantic rule that fails an enabled HTTP API with every route switch off, and keep it valid while `http_api.enabled` is false. Verify: unit tests for both scenarios, the failure carrying the `semantic` category and naming both keys; `--validate` reports it in `validate_cli_integration.rs`.

## 2. Error and metric

- [x] 2.1 Add the unscannable-content `Error` variant: status 422, body `{"error":"unscannable content"}`, reason `unscannable_content` (design D4). Verify: a unit test asserts the status, the exact body, and the reason.
- [x] 2.2 Register `voidwall_unscanned_total` with labels `mode`, `route`, `direction`, `reason` and an increment helper whose `reason` is a fixed enum (`encoded_data`). Verify: a unit test increments it and reads the sample back with the four labels.

## 3. Decoder

- [x] 3.1 Extract the key-path builder of `structured/json.rs` into one shared function and use it in `flatten_json` (design D1). Verify: the existing `json.rs` and `structured_scanning_integration` tests pass unchanged.
- [x] 3.2 Add the typed envelope with `input_type` as a two-variant enum and no `request_data` or `request_headers` field (design D3). Verify: unit tests for a missing `input_type`, an unknown `input_type`, and an unknown top-level field.
- [x] 3.3 Add the classifier for messages, content parts, tools, and tool calls: the request-side field list, the skip list, the generic rule for unknown fields and roles, the unknown-part count, and the encoded-data count (design D1, D5). Verify: one `#[test_case]` per field in the spec's request-side list, plus cases for each skipped field, an unknown field, an unknown role, an unknown part type, a tool with only `type`, each encoded-data field, and an `https://` image URL.
- [x] 3.4 Add the response-side rule (`texts` and tool calls only) and the `texts` fallback on the request side. Verify: unit tests for `texts` ignored when `structured_messages` exists, `texts` used when it is missing, and `structured_messages` ignored on a response payload.
- [x] 3.5 Build one `Body` unit per top-level entry from the selected `flatten_json` fragments (design D2). Verify: a unit test asserts the unit count and that each unit's fragments carry their key paths and document-absolute offsets.

## 4. Handler and route

- [x] 4.1 Make the detection-metric loop take the direction as a parameter, and keep `/v1/scan` on `"request"` (design D7). Verify: the existing `http_api.rs` metric tests pass unchanged.
- [x] 4.2 Add the handler: JSON-only content-type check (415), decode (400), unknown-part handling under both `on_error` values (422 or skip), encoded-data counting, `Engine::guard` with `BlockPolicy::Never`, error mapping shared with `/v1/scan`, and the typed `NONE`/`BLOCKED` response (design D4, D8). Verify: handler unit tests for `NONE`, `BLOCKED` with the exact `blocked_reason` text, 415, 400, 422 under `fail_close`, skip under `fail_open`, and a guard failure under both `on_error` values.
- [x] 4.3 Add each route to `router` only when its switch is on (design D7). Verify: unit tests get 404 from the LiteLLM route when it is off while `/v1/scan` answers, and 404 from `/v1/scan` when it is off while the LiteLLM route answers.

## 5. OpenAPI document

- [x] 5.1 Annotate the route, envelope, and both response shapes with `utoipa` and regenerate `docs/openapi.json`. Verify: `openapi_document_file_is_fresh` passes, and a test asserts that the document describes the route, `NONE`, `BLOCKED`, and the 400/413/415/422/500 statuses.

## 6. Integration tests

- [x] 6.1 Add LiteLLM payload fixtures copied from one named LiteLLM version, with PII placeholders only: a request with system, user, assistant tool call, and tool messages plus tools; a response with texts and tool calls; a request with an inline image. Verify: each fixture parses with the envelope type.
- [x] 6.2 Add `crates/voidwall/tests/litellm_guardrail_integration.rs`, which starts a real server and posts the fixtures. Verify: one test per scenario of `specs/litellm-guardrail-api/spec.md`, including the metric scenarios read from the admin `/metrics` endpoint.
- [x] 6.3 Add the scenarios of the `specs/http-api/spec.md` delta that are not already covered (LiteLLM route served; `content_types` not applied to it). Verify: the tests pass in `http_api_integration.rs`.

## 7. Documentation and checks

- [x] 7.1 Update `README.md` (feature list and a LiteLLM `config.yaml` example), `docs/TODO.md` ("LiteLLM integration"), and `ARCHITECTURE.md` (the HTTP API routes). Verify: each file names the route and both switches, `http_api.scan.enabled` and `http_api.litellm.enabled`.
- [x] 7.1a Add 422 to the "Errors" section of `CLAUDE.md`: a blocking error answers 422 for content that parses but that Voidwall cannot inspect. Verify: the status list in `CLAUDE.md` names 413, 400, 422, and 500.
- [x] 7.2 Run `cargo test --workspace`, `cargo clippy --workspace --all-targets`, and `openspec validate litellm-guardrail-api --strict`. Verify: all three pass with no warning.
- [x] 7.3 Review the diff against the spec deltas with the `code-review` skill. Verify: no finding is left open.
