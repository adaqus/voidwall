## 1. Direction in the engine

- [x] 1.1 Add a `Direction` type and a direction set to `Interest`; give the `pii` guard
  and model guards both directions. Check: unit tests in `engine/guard.rs` show an
  interest wants a (direction, kind) pair only when it holds both.
- [x] 1.2 Make `Engine::guard` take a `Direction` and skip a guard whose interest lacks
  it; make `GuardSelection::wants` take the direction. Check: an `engine/mod.rs` unit
  test shows a response-only guard is not called for a request and is called for a
  response.
- [x] 1.3 Pass the direction from the reverse proxy request path, response path, and
  stream driver, and from the LiteLLM route. Check: `cargo test --workspace` passes with
  no change to an existing test's expected result.

## 2. Configuration

- [x] 2.1 Add `HiddenContextConfig` (`enabled`, `markers`, no `surface`) under
  `BuiltinGuards`, with a hand-written `Debug` that prints the marker count only, and add
  `hidden_context` to `enabled_names`. Check: `config.rs` unit tests parse a valid section,
  reject a `surface` key, and show `{:?}` holds no marker.
- [x] 2.2 Validate: enabled with no marker, an empty marker, more than 64 markers, a
  case-folded duplicate, and a longest possible match over `stream_holdback_bytes`
  (`regex-syntax` `maximum_len`). Messages name `markers[<index>]` and never the value.
  Check: one `#[test_case]` per spec scenario under "Markers are validated at startup",
  each asserting the message holds no marker.

## 3. The guard

- [x] 3.1 Add `engine/hidden_context.rs`: build one `(?i)` regex from the escaped
  markers; `detect` matches each selected body unit inline (plain text whole, structured
  values one by one) and returns at most one spanned `HIDDEN_CONTEXT` finding per unit.
  Check: unit tests for each scenario under "A marker matches without regard to case" and
  "The guard reports one HIDDEN_CONTEXT finding per unit", including a marker split across
  two JSON values.
- [x] 3.2 Build the guard in the engine when its section is enabled. Check: an
  `engine/mod.rs` test shows the guard is built with the name `hidden_context`, and is not
  built when the section is absent or disabled.

## 4. `/v1/scan` direction

- [x] 4.1 Read the `direction` query parameter into `Direction`; default to request;
  answer 400 `{"error":"invalid direction"}` for any other value without scanning; pass
  the direction to `Engine::guard` and `record_detections`. Check: `http_api.rs` tests for
  each scenario under "POST /v1/scan takes the direction of the posted content".
- [x] 4.2 Document the parameter and the 400 in the OpenAPI annotations and regenerate
  `docs/openapi.json` with `UPDATE_OPENAPI=1 cargo test -p voidwall --lib openapi`. Check:
  `openapi_document_file_is_fresh` passes.

## 5. Integration tests

- [x] 5.1 Reverse proxy, generic and `openai-chat` routes: a marker in a request is
  forwarded; a marker in a response answers 403 / 400 `content_filter` with
  `["HIDDEN_CONTEXT"]`; a request with PII and a marker on a route selecting both guards
  is blocked with `["EMAIL"]` only. Check: new tests under `crates/voidwall/tests/` pass.
- [x] 5.2 Stream in hold-back mode with a marker split across two events: the stream
  stops, and no received event holds a byte of the marker. Check: new integration test
  passes.
- [x] 5.3 LiteLLM route: a marker with `input_type` `request` answers `NONE`; with
  `response` answers `BLOCKED`. Check: new integration test passes.
- [x] 5.4 `/v1/scan?direction=response` with a marker twice: `matches_count` 1 and the
  `guards` entry; `voidwall_detections_total` carries `guard="hidden_context"` and
  `direction="response"`. Check: new integration test passes.
- [x] 5.5 Detection safety: after a blocked response, captured logs, the `/metrics`
  output, and the response body hold no marker; startup logs hold no marker. Check: new
  integration test passes.

## 6. Documentation

- [x] 6.1 Reword CLAUDE.md "Threading" and ARCHITECTURE.md §4.1 to allow a `detect` that
  is a single linear literal scan to run inline, and add the guard to ARCHITECTURE.md's
  guard list. Check: re-read both sections against design decision 6.
- [x] 6.2 Document `[builtin_guards.hidden_context]` and `/v1/scan?direction=` under
  `docs/` (config reference and API docs): the case-insensitive substring match, the
  word-for-word limit, and advice to use a long random canary. Check: every key and
  validation rule in the spec appears in the docs.
- [x] 6.3 Confirm no Grafana change is needed: no metric family, label, or reason value
  is added. Check: grep `docker/grafana/dashboards/voidwall.json` for `guard` and
  `direction` panels and confirm their queries accept the new values unchanged.

## 7. Verification

- [x] 7.1 Run `cargo test --workspace`, `cargo clippy --workspace --all-targets` (no
  warnings), and `cargo deny check licenses`. Check: all three pass.
- [x] 7.2 Review the diff against the spec deltas with the `code-review` skill. Check: no
  finding left open.
