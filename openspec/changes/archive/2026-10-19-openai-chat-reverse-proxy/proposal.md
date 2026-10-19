## Why

Every OpenAI-compatible server speaks `POST /v1/chat/completions`. The reverse proxy
scans that traffic today only through the generic JSON flattener. The flattener reads
base64 images as text, cuts no unit per message, lets a `stream: true` call through
unscanned, and answers a block with a body that OpenAI SDKs do not understand.

The LiteLLM change built a Chat Completions decoder. This change puts that decoder in
front of the reverse proxy. It is tier 2 in
`voidwall-internal/research/openai-endpoint-tiers.md`.

## What Changes

- A reverse proxy route gets an optional `format` key. `format = "openai-chat"` decodes
  the route's request and response bodies as Chat Completions. A route without `format`
  keeps the generic scan.
- Scope is non-streaming Chat Completions to plain-HTTP upstreams, such as vLLM and
  Ollama. The proxy does not originate upstream TLS yet, so OpenAI, Azure OpenAI, and
  OpenRouter are not reachable. The docs say so.
- Request decoding follows `voidwall-internal/research/chat-completions-field-map.md` § 2.
  - It reads `messages[]`, `tools[]`, and the deprecated `functions[]` with the tier-1
    rules.
  - It also reads `response_format.json_schema`, `prediction.content`, `metadata`,
    `safety_identifier`, `user`, `prompt_cache_key`, and
    `web_search_options.user_location`.
  - It skips the sampling and control fields, such as `model`, `temperature`, `stop`,
    and `tool_choice`.
  - A top-level key the decoder does not know is scanned generically.
- Response decoding follows the field map § 3.
  - It reads `choices[].message` with the tier-1 message rules, and also
    `annotations[]` and `audio.transcript`.
  - It skips `logprobs` and the metadata fields.
  - A top-level key the decoder does not know is scanned generically, so an upstream
    `error` object is scanned.
- One unit per message, tool, choice, and top-level field. No trust class.
- Base64 data is skipped and counted, as on the LiteLLM route, now with
  `mode="reverse_proxy"`.
- A request body that is not JSON, or has no `messages` array, answers 400 under both
  `on_error` settings. The `content_types` allowlist does not apply to the route.
  `max_body_size` applies.
- Streaming is unscannable until tier 3, and follows `on_error`.
  - A `stream: true` request on a route with response scan on is stopped under
    `fail_close` with 422, before the upstream call.
  - A `text/event-stream` response is stopped under `fail_close` with 422.
  - Under `fail_open`, the stream passes unscanned.
  - Either way, the new reason `unscannable_stream` is counted.
- Another non-JSON response, such as an HTML error page, is unscannable content. It
  follows `on_error` with the reason `unscannable_content`.
- An unknown content part type follows `on_error`, as on the LiteLLM route: 422 under
  `fail_close`.
- **BREAKING (for the route only)** A detection on an `openai-chat` route answers **400**
  in the OpenAI error shape, in both directions, with `code` `content_filter`, `type`
  `invalid_request_error`, and a `kinds` list. OpenAI clients need no change. Routes
  without `format` keep the fixed 403.
- Every other answer Voidwall makes on the route uses the OpenAI error shape. The status
  stays the same: 400, 413, 422, 500, 502, and 504.
- `CLAUDE.md` changes:
  - The fixed-403 rule gains "unless explicitly stated otherwise".
  - The party-at-fault rule gains one exception: a response-side block on an
    `openai-chat` route answers 400.

## Capabilities

### New Capabilities

- `openai-chat-proxy`: the `openai-chat` route format. It covers the request and
  response fields read and skipped, unknown keys, encoded data, unknown parts, streaming,
  the 400 block, and the OpenAI error shape.

### Modified Capabilities

- `reverse-proxy`:
  - "A detection blocks with a fixed 403" is scoped to routes without `format`.
  - "Body scanning respects the content type and the target flags" exempts an
    `openai-chat` route from `content_types`.
  - "A blocked error names the party at fault", "The upstream exchange has a time limit",
    and "The buffered upstream response body has a size limit" point to the OpenAI
    bodies on an `openai-chat` route.
- `configuration`: a route's `format` key is validated.
- `metrics`:
  - The blocked counter counts the 400 block and a 422 stop.
  - `voidwall_errors_total` gains the reasons `unscannable_content` and
    `unscannable_stream` in the metrics spec.

## Impact

- `crates/voidwall/src/structured/`: a new `openai_chat` decoder. `chat_completions::Selection`
  gains entries rooted at a top-level key, not only at an array index.
- `crates/voidwall/src/reverse_proxy.rs`: per-route decoding, the stream checks, the
  unscannable paths, and the OpenAI-shaped answers.
- `crates/voidwall/src/config.rs`: `Route.format` as an enum, with validation tests.
- `crates/voidwall/src/error.rs`: OpenAI-shaped bodies next to the existing ones.
- `crates/voidwall/src/metrics.rs`: the `unscannable_stream` reason.
- `crates/voidwall/tests/`: integration tests against a stub upstream that speaks Chat
  Completions.
- Docs: `CLAUDE.md` (Outcomes, Errors), `openspec/config.yaml` context, `ARCHITECTURE.md`,
  `README.md`, and the proxy docs under `docs/` (HTTP-only note, route example).
- No new dependency is expected.
