## Why

Most chat clients send `stream: true`. On a route with `format = "openai-chat"` and
response scan on, such a request answers 422 under `fail_close`, and under `fail_open`
the stream reaches the client unscanned. This is tier 3 of the OpenAI endpoint tiers
(`voidwall-internal/research/apis/openai-endpoint-tiers.md`): `/v1/chat/completions`
streaming (SSE).

## What Changes

- A `text/event-stream` response on an `openai-chat` route with response scan on is
  scanned. The proxy finds a stream by its content type, whatever the request said.
- A new route field `stream` selects how: `"holdback"` (the default) or `"buffer"`. It is
  valid only on a route with `format = "openai-chat"`.
- **Hold-back mode.** The proxy joins the text of each choice and field, scans it every
  `stream_scan_bytes` of new text, and forwards whole upstream events unchanged once a
  scan shows that no match can overlap them. It keeps `stream_holdback_bytes` of text
  back, and scans with `stream_context_bytes` of already-sent text before it. A finding
  near the end of the received text waits for more text, so a value that is not complete
  yet cannot cause a false block. A finding without a span waits for the next scan and
  blocks only if it comes back. A text of a choice closes when the choice moves to
  another text or sends `finish_reason`; it gets a final scan and is released whole.
- **Buffer mode.** The proxy reads the whole stream, scans it once, and then sends the
  exact upstream bytes, or answers the normal 400.
- A stream with a `Content-Encoding` other than `identity` is unscannable content and
  follows `on_error`.
- **Block after the first byte.** The proxy sends one `data:` event that holds the
  same OpenAI error body as the 400, and closes the stream. It does not send `[DONE]`.
  Before the first byte, every answer stays as it is today.
- A clean end of the upstream body without `data: [DONE]` ends the stream as `[DONE]` does.
- New top-level keys: `stream_idle_timeout_secs` (default 60), `stream_holdback_bytes`
  (default 512), `stream_context_bytes` (default 512), `stream_scan_bytes` (default 256).
- The idle timeout limits each gap between two stream events. For a stream,
  `upstream_timeout_secs` covers only the wait for the response headers. The size limit
  counts the stream's bytes against `max_body_size`. Both limits block whatever
  `on_error` says, as they do today.
- Chunk fields follow the existing response rules: `choices[].delta.X` follows the rule
  for `choices[].message.X`, so `reasoning_content` deltas are scanned.
- New metric `voidwall_streams_cut_total{mode,route,reason}` counts streams cut after the
  first byte.
- Startup logs one warning when an `openai-chat` route in hold-back mode selects the `pii`
  guard and a custom definition has no keywords, because such a pattern has no bound on
  its match length.
- **BREAKING**: a request with `stream: true` no longer answers 422 under `fail_close`.
  The `unscannable_stream` reason of `voidwall_errors_total` is removed.
- **BREAKING**: for a stream, `upstream_timeout_secs` no longer limits the body read.

## Capabilities

### New Capabilities

- `openai-chat-streaming`: how an `openai-chat` route scans and forwards a
  `text/event-stream` response in hold-back and buffer mode, and how it ends a stream
  that it stops.

### Modified Capabilities

- `openai-chat-proxy`: a stream is no longer unscannable; the 422 row of the error table
  covers unscannable content only.
- `reverse-proxy`: the upstream time limit and the response size limit state their
  exception for a stream on an `openai-chat` route.
- `configuration`: the four new top-level stream keys and the route field `stream`, with
  their validation.
- `metrics`: the new `voidwall_streams_cut_total` family, the blocked counter for a
  stream, and the removal of the `unscannable_stream` reason.

## Impact

- Code: `crates/voidwall/src/reverse_proxy.rs` (the stream path), `structured/` (an SSE
  framer and a chunk decoder next to `openai_chat.rs`), `config.rs` and `validate.rs`
  (keys, field, warning), `metrics.rs`, `error.rs` (`UnscannableStream` goes).
- The engine, the `Guard` trait, and `voidwall-pii` do not change. Each scan is one more
  `Engine::guard` call.
- Tests: unit tests in each touched file; integration tests in
  `crates/voidwall/tests/openai_chat_proxy_integration.rs` use the recorded LM Studio
  stream fixture.
- Docs: `ARCHITECTURE.md` § 2 (route formats), proxy docs under `docs/`, the default
  config.
- Operators: dashboards that read `reason="unscannable_stream"` lose that series.
