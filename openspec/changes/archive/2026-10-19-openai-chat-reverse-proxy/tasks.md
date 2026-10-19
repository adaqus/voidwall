## 1. Configuration

- [x] 1.1 Add `RouteFormat { Generic, OpenAiChat }` as `Route.format` with `#[serde(default)]`, kebab-case value `openai-chat`, and carry it in `ResolvedRoute` (design D1). Verify: unit tests for format absent, `openai-chat`, an unknown string, and a non-string, each matching a scenario of `specs/configuration/spec.md`. The two failing cases report the `schema` category.

## 2. Errors and metrics

- [x] 2.1 Add `Error::UnscannableStream`: status 422, the same body as `UnscannableContent`, and reason `unscannable_stream` (design D6). Verify: a unit test asserts the status, the exact body, and the reason.
- [x] 2.2 Add `Error::into_openai_response()` with the status, `message`, `type`, and `code` table from `specs/openai-chat-proxy/spec.md`. It reads the same message constants as `into_response` (design D5). Verify: one `#[test_case]` per table row asserts the status and the `error` object with exactly four keys and `param` null.
- [x] 2.3 Add the OpenAI block body: 400, `message` `content blocked. Kinds: …`, `type` `invalid_request_error`, `param` null, `code` `content_filter`, and `kinds` (design D5). Verify: unit tests for two kinds sorted, a byte-identical body for the same kinds, and no matched value in the body.

## 3. Decoder

- [x] 3.1 Pair fragments with entries by leaf order (design D2). The classifier records one decision per string leaf in document order, `into_unit_fragments` zips the decisions with the `flatten_json` fragments, and a top-level key can root an entry. Delete `entry_root` and `is_at_or_under`. The LiteLLM decoder classifies the top-level keys of the raw `Value` in order. A leaf-count mismatch returns `Error::Scanner` in every build, and both routes apply `on_error` to it as a scanner failure. Verify: a unit test cuts `metadata` and `messages[0]` into two units; a unit test scans the values under top-level keys `a.b` and `x[0].y`; a unit test passes mismatched counts and gets `Error::Scanner`. The existing `chat_completions.rs` and `litellm.rs` tests pass unchanged, except the `is_at_or_under` test, which is deleted with the function.
- [x] 3.2 Add the `REQUEST` table and `Selection::request` (design D3). Verify: one `#[test_case]` per scanned field in "The request is read from messages, tools, and the free-text fields", one per skipped field, and cases for an unknown top-level key, `functions[]`, `prediction.content` as a string and as parts, and an unknown part in `prediction`.
- [x] 3.3 Add the `RESPONSE`, `CHOICE`, and `RESPONSE_MESSAGE` tables and `Selection::response` (design D3). Verify: unit tests for `message.content`, `tool_calls`, `function_call`, `refusal`, `annotations`, and `audio.transcript` scanned; for `audio.data` counted as encoded; for `logprobs` and the metadata fields skipped; and for an unknown top-level `error` object scanned.
- [x] 3.4 Add `structured/openai_chat.rs` with `decode_request` and `decode_response`, and share `Decoded` with `litellm.rs` (design D4). Verify: unit tests for a request that is not an object, one with no `messages`, `stream` true and `"true"` (only the boolean counts), a JSON array response scanned whole, and an unparseable response returning `BodyParse`.

## 4. Reverse proxy

- [x] 4.1 Route every answer of a matched route through `answer(shape, Error)` and `block(shape, kinds)`. That covers `buffer_body`, `upstream_timeout`, `classify_scan_body`, `handle_scan_error`, the 502 paths, and `run_engine` (design D5). Verify: the existing `reverse_proxy.rs` tests pass unchanged for `Generic`, and new tests assert the OpenAI body for 413, 500, 502, and 504 on an `OpenAiChat` route.
- [x] 4.2 Decode the request on an `OpenAiChat` route in the D6 order: 400 under both policies, the `stream` 422, unknown parts, encoded-data count, then units and the engine. Skip the `content_types` check. Verify: handler tests for each step, including `stream` under `fail_open` with no request-side count, and `stream` with response scan off and no check.
- [x] 4.3 Check the response content type before the body read on an `OpenAiChat` route, per the D6 table. Decode a JSON body with `decode_response`. Verify: handler tests for `text/event-stream` and `text/html` under both policies, for an empty `text/html` 204 that is forwarded, and for a JSON response with PII answering 400 with `direction="response"`.
- [x] 4.4 Count `voidwall_unscanned_total` with `mode="reverse_proxy"`, the route prefix, and the direction, only for a message that goes on to be scanned. Verify: a unit test for one inline image in a request and one `audio.data` in a response.

## 5. Integration tests

- [x] 5.1 Add the fixtures of design D9 under `crates/voidwall/tests/fixtures/openai-chat/`. Write `openai-python-<ver>-request-full.json` by hand, with every request field the spec scans or skips and one inline image. Copy the five `lmstudio-0.4.26-*` files from `openspec/changes/openai-chat-reverse-proxy/recordings/lmstudio-0.4.26/` as its `README.md` maps them, and keep the recorded status and content type of each for the stub upstream. Re-record only if a recording is missing. Verify: no fixture holds PII; each JSON fixture decodes with `openai_chat`; the stream file's recorded content type is `text/event-stream`.
- [x] 5.2 Add `crates/voidwall/tests/openai_chat_proxy_integration.rs`. It starts a real server in front of a stub upstream that answers JSON, `text/event-stream`, or `text/html` on demand. Verify: one test per scenario of `specs/openai-chat-proxy/spec.md`, with the metric scenarios read from the admin `/metrics` endpoint.
- [x] 5.3 Add the scenarios of the `reverse-proxy` and `metrics` deltas that 5.2 does not cover, such as "An openai-chat route ignores the allowlist", "A stream under fail_close", and the block counters on an `openai-chat` route. Verify: the tests pass.

## 6. Documentation and checks

- [x] 6.1 Amend `CLAUDE.md`. "Outcomes": the fixed-403 rule gains "unless explicitly stated otherwise" and names the `openai-chat` 400. "Errors": the response-side 400 exception to the party-at-fault rule. Make the same two notes in the `openspec/config.yaml` context (design D8). Verify: both files state both points.
- [x] 6.2 Update `README.md`, `ARCHITECTURE.md`, and the proxy docs under `docs/`. Add the two-route example, the HTTP-only note, the streaming behavior, and the SDK retry note. Add a `docs/backlog.md` item for upstream TLS if none exists. Verify: each file names `format = "openai-chat"`, and the docs say that `https://` upstreams are not supported yet.
- [x] 6.3 Run `cargo test --workspace`, `cargo clippy --workspace --all-targets`, and `openspec validate openai-chat-reverse-proxy --strict`. Verify: all three pass with no warning.
- [x] 6.4 Review the diff against the spec deltas with the `code-review` skill. Verify: no finding is left open.
