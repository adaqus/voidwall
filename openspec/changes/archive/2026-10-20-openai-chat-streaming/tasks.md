## 1. Configuration

- [x] 1.1 Add the route field `stream` (`holdback` | `buffer`) and resolve it into `RouteFormat::OpenAiChat { stream }`; reject `stream` on a route without `format = "openai-chat"` with `semantic`. Verify: `#[test_case]` unit tests in `config.rs` for each scenario of "A reverse proxy route's stream mode is validated".
- [x] 1.2 Add the top-level keys `stream_idle_timeout_secs`, `stream_holdback_bytes`, `stream_context_bytes`, `stream_scan_bytes` as range-checked newtypes with their defaults, and the cross-key rules in validation. Verify: unit tests for each scenario of "The stream keys are top-level keys", valid and invalid.
- [x] 1.3 Log the startup warning for a custom definition without keywords when an `openai-chat` hold-back route selects the `pii` guard. Verify: a unit test of the check that returns the labels and prefixes, for hold-back (warns) and buffer (does not).

## 2. Stream decoding

- [x] 2.1 Add `structured::sse`, an incremental framer that keeps each event's raw bytes. Verify: unit tests for a frame split across reads, multi-line `data:`, CRLF, comments, `event:`/`id:`/`retry:`, and `[DONE]`; the joined raw bytes equal the input.
- [x] 2.2 Add `structured::openai_chat_stream`, the chunk decoder and per-choice, per-field joiner, taking its field rules from `chat_completions.rs` and the key paths of the matching `choices[].message` field. Verify: `#[test_case]` tests for `content`, `refusal`, tool call `arguments` and `name` by index, `reasoning_content`, an unknown top-level key, the skipped keys, and two interleaved choices; the LM Studio stream fixture joins to its expected reasoning text.
- [x] 2.3 Apply the parse-failure rule to a `data:` payload that is not JSON. Verify: unit tests under `fail_close` (stop with `malformed_body`) and `fail_open` (plain-text scan, go on).

## 3. Hold-back window

- [x] 3.1 Measure R, the longest right-side extension that turns a shipped or custom-keyword match into a non-match; set it as a constant and replace `<R>` in `specs/openai-chat-streaming/spec.md`. Verify: a unit test per measured case shows the match waits inside the tail and resolves after it; `grep '<R>'` over the change finds nothing.
- [x] 3.2 Implement the release gate as a pure state machine: scan on K new bytes and at the end, scan window `[p − C, e]`, release to `min(e − L, earliest waiting finding)` rounded down to an event boundary, events in arrival order. Verify: unit tests with scripted findings for "A short reply", "A value inside the hold-back", and "A keyword before the value".
- [x] 3.3 Add the tail rule and the wait-one-scan rule for a finding without a span. Verify: unit tests for "A value that is not complete yet", "A value at the end of the stream", "The finding comes back", and "The finding does not come back".

## 4. Reverse proxy

- [x] 4.1 Remove `Error::UnscannableStream`, the 422 for `stream: true`, and the `unscannable_stream` reason. Verify: the old 422 tests are rewritten to the new scenarios; `grep -rn unscannable_stream crates/` finds nothing.
- [x] 4.2 Add the stream stop function that writes the route's error body as one `data:` event and closes, beside `answer` and `block`. Verify: a unit test that the event body is byte-identical to the 400 body for the same kinds and to each error body in the table.
- [x] 4.3 Add the hold-back driver: hold status and headers until the first release, scan the named response headers first, read under the idle timeout with any byte resetting it, count bytes against `max_body_size`, write released events through a bounded channel, and close the upstream on a stop. Verify: unit tests in `reverse_proxy.rs` with a stub upstream for a stop before and after the first byte, an idle stop, an oversize stop, an upstream connection failure, and a clean end without `[DONE]`.
- [x] 4.4 Apply `on_error` to a guard error during a stream. Verify: unit tests for `fail_close` (error event `internal_error`) and `fail_open` (rest forwarded unscanned, `outcome="passed"`).
- [x] 4.5 Add buffer mode: read the whole stream under both limits, scan once, answer 400 or replay the exact bytes. Verify: unit tests for "A clean stream in buffer mode" and "A detection in buffer mode".
- [x] 4.6 Limit `upstream_timeout_secs` to the headers for a stream. Verify: a unit test for "A stream outlives the upstream timeout".

## 5. Metrics

- [x] 5.1 Register `voidwall_streams_cut_total{mode,route,reason}` with its fixed reason set and increment it only after the first byte. Verify: unit tests for each reason and for a stop before the first byte.
- [x] 5.2 Count a stream stop in `voidwall_blocked_total` for a detection or a `fail_close` error, and not for idle, size, or upstream stops. Verify: unit tests for "A stream under fail_close" and "An idle stream".

## 6. Integration tests

- [x] 6.1 Add one test per scenario of `specs/openai-chat-streaming/spec.md` to `crates/voidwall/tests/openai_chat_proxy_integration.rs`, serving the LM Studio stream fixture with placeholders inserted. Verify: `cargo test -p voidwall --test openai_chat_proxy_integration` passes.
- [x] 6.2 Add the scenarios of the `reverse-proxy`, `configuration`, `metrics`, and `openai-chat-proxy` deltas that 6.1 does not cover. Verify: the same command passes, and each delta scenario maps to a named test.

## 7. Docs and checks

- [x] 7.1 Update `ARCHITECTURE.md` § 2 "Reverse proxy route formats" and § 3, `docs/config-validation.md` (the new `schema` and `semantic` cases), the commented keys in `docker/voidwall.toml`, and mark "Streaming support (SSE)" done in `docs/TODO.md`. Verify: `grep -rn -i "event-stream" ARCHITECTURE.md docs/` shows no claim that a stream is unscannable.
- [x] 7.2 Run the workspace checks. Verify: `cargo test --workspace`, `cargo clippy --workspace --all-targets` with no warnings, and `openspec validate openai-chat-streaming --strict` all pass.

## 8. Review follow-ups

- [x] 8.1 Give each piece its choice index and report each choice that sends `finish_reason` from the chunk decoder; close the other texts of a choice in `Holdback` on a switch or `finish_reason`, with the end-of-stream scan, and open a closed text again when it gets text. Verify: unit tests in `holdback.rs` and `openai_chat_stream.rs` for each scenario of "A text of a choice closes when the choice moves on".
- [x] 8.2 Add `CutReason::UnscannableContent` and use it for an unknown content part under `fail_close`. Verify: a unit test for "An unknown content part after the first byte".
- [x] 8.3 Treat a stream with a `Content-Encoding` other than `identity` as unscannable content in both modes. Verify: integration tests for "A compressed stream under fail_close" and "A compressed stream under fail_open".
- [x] 8.4 Add integration tests for the scenarios of 8.1 to `crates/voidwall/tests/openai_chat_proxy_integration.rs`, and run the workspace checks. Verify: `cargo test --workspace`, `cargo clippy --workspace --all-targets`, and `openspec validate openai-chat-streaming --strict` pass.

## 9. End of stream and client loss

- [x] 9.1 End the stream at `[DONE]` on every path: buffer mode stops reading at the `[DONE]` event and sends the bytes up to it; the `fail_open` path after `[DONE]` sends the held events and stops. Verify: tests for "Bytes after DONE" in hold-back and in buffer mode, and a unit test for a guard error under `fail_open` in the final scan after `[DONE]`.
- [x] 9.2 Drop the upstream `content-length` in both modes; buffer mode sends the length of the body it sends. Verify: tests for "The upstream length is not forwarded" and for a buffer-mode stream whose body ends after `[DONE]`.
- [x] 9.3 Stop the hold-back driver when the client is gone, before or after the first byte, while it waits on the upstream. Verify: a unit test where the client drops the response before the first byte and the upstream body is dropped within 1 s.

## 10. Review follow-ups (2)

- [x] 10.1 Drop a waiting finding without a span when the scan at its text's close does not report it again, so the closed text is released and not scanned again. Verify: a unit test in `holdback.rs` and an integration test for "A finding without a span that does not come back at the close".
- [x] 10.2 Test the tail in the JSON-escaped form the stream scans. Verify: a unit test in `holdback.rs` that no escaped two-character suffix settles a match that the whole suffix turns.
- [x] 10.3 Count every upstream failure in `voidwall_errors_total` with `outcome="blocked"` and `reason="upstream_error"`: a failed connection, a failed buffered body read, and a stream whose connection fails before the body ends. Verify: unit tests in `reverse_proxy.rs` for "The upstream cannot be reached", "The upstream response body fails", and "The upstream stream fails".
- [x] 10.4 Apply the close rule also when the stream ends before the scan at the close, so the result does not depend on how the upstream bytes are split into reads. Verify: a unit test in `holdback.rs` and an integration test for "A finding without a span that does not come back at a close with the end", both failing before the change.
- [x] 10.5 Scope the `upstream_error` stream rule in the metrics delta to the streams the proxy reads: an `openai-chat` route under response scan, in hold-back or buffer mode. Verify: `openspec validate openai-chat-streaming --strict`.
