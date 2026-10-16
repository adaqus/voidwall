## Why

LiteLLM is the most widely deployed AI gateway and Voidwall's first integration target.
Its Generic Guardrail API lets LiteLLM call an outside guardrail service on every request
and response. Voidwall has no endpoint that speaks this API, so LiteLLM cannot use it.

LiteLLM converts every call it proxies into the OpenAI Chat Completions message format
before it calls the guardrail. The decoder this change adds is therefore also the base for
the later OpenAI-compatible proxy routes (`voidwall-internal/research/openai-endpoint-tiers.md`).

## What Changes

- The REST API serves a second route, `POST /beta/litellm_basic_guardrail_api`, next to
  `POST /v1/scan`.
- Each REST API route gets its own switch: `http_api.scan.enabled` and
  `http_api.litellm.enabled`, both true by default. An operator can serve the LiteLLM
  route without `/v1/scan`. `http_api.enabled` still starts the listener, and enabling it
  with every route switched off fails validation.
- A decoder turns the LiteLLM payload into units, one per text field, each with its key
  path. It follows `voidwall-internal/research/chat-completions-field-map.md`.
  - On a request (`input_type = "request"`) it reads `structured_messages`, `tools`, and
    `tool_calls`. It reads `texts[]` only when `structured_messages` is missing.
  - On a response (`input_type = "response"`) it reads `texts[]` and `tool_calls`.
  - It does not read `request_data` or `request_headers`.
  - It produces no trust class.
- Base64 data is not scanned: `image_url` data URLs, `input_audio.data`,
  `file.file_data`, and the `data:` URLs in LiteLLM `images[]`. A new counter records
  each skipped value. LiteLLM copies every `image_url.url` of the messages into
  `images[]`, so on the request side `images[]` is ignored when `structured_messages`
  exists, as `texts[]` is.
- A content part whose `type` the decoder does not know is unscannable and follows
  `on_error`: under `fail_close` the route answers 422 with a fixed body, under
  `fail_open` it skips the part.
- An unknown field inside a message, tool, or tool call, and a message with an unknown
  `role`, are scanned generically: every string under them. An unknown top-level
  envelope field is ignored.
- The route accepts JSON only. `max_body_size` applies; the `content_types` allowlist
  does not.
- Metrics follow `/v1/scan`: `mode="http_api"`, `route="global"`, detection counters
  increment, and the blocked counters never do. The `direction` label comes from
  `input_type`.
- Outcomes:
  - No detection: 200 with `action` `NONE`.
  - A detection: 200 with `action` `BLOCKED` and a `blocked_reason` that holds a fixed text
    and the sorted kinds. It never holds a detected value.
  - Voidwall never answers `GUARDRAIL_INTERVENED`, because it never rewrites a message.
- Errors keep today's REST API behavior. Under `fail_close` an oversize body answers 413,
  a body that does not parse answers 400, and a scanner failure answers 500. LiteLLM's own
  `fail_on_error` then decides. Under `fail_open` the route answers 200 with `action`
  `NONE`.
- The OpenAPI document describes the new route.

## Capabilities

### New Capabilities

- `litellm-guardrail-api`: the LiteLLM Generic Guardrail API route. It covers the payload
  fields read and skipped, the `texts[]` fallback, the unknown-part rule, the response
  shape, and error handling.

### Modified Capabilities

- `http-api`: "The API serves one route" becomes "The API serves the scan route and the
  LiteLLM route", each behind its own switch. "The request body is the content to scan" is scoped to `/v1/scan`.
  "Scan and body limits match the proxy" keeps `content_types` off the LiteLLM route.
  "The OpenAPI document is published as a repository file" also covers the new route.
- `configuration`: `http_api.scan.enabled` and `http_api.litellm.enabled` turn each route
  on or off, and an enabled HTTP API with every route off fails validation.
- `metrics`: an eighth family, `voidwall_unscanned_total`, counts values skipped without
  a scan, by `reason`.

## Impact

- `crates/voidwall/src/http_api.rs`: the new route and its handler.
- `crates/voidwall/src/structured/`: a new decoder for the LiteLLM payload and the
  Chat Completions message shapes.
- `crates/voidwall/src/error.rs`: a new error for unscannable content (422,
  `reason="unscannable_content"`).
- `crates/voidwall/src/config.rs`: the two route switches and the all-routes-off rule.
- `CLAUDE.md`: the "Errors" status list gains 422.
- `crates/voidwall/src/metrics.rs`: the new counter.
- `crates/voidwall/tests/`: integration tests that post LiteLLM payloads to a running
  server.
- The OpenAPI document file.
- Docs: `README.md` feature list, `docs/TODO.md` "LiteLLM integration", `ARCHITECTURE.md`.
- No new dependency is expected.
