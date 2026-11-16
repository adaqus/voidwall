## 1. Failing tests first

- [x] 1.1 Add the scenarios of "Every JSON path scans decoded values" for buffered bodies
  as integration tests: generic request and response, the newline and tab case,
  `openai-chat` request and buffered response, `/v1/scan`, and both sides of the LiteLLM
  route (`reverse_proxy_integration.rs`, `openai_chat_proxy_integration.rs`,
  `http_api_integration.rs`, `litellm_guardrail_integration.rs`). An "escaped" placeholder
  has every character written as `\uXXXX`. Check: each test fails on `main` because the
  message passes.
- [x] 1.2 Add the four stream scenarios to `openai_chat_proxy_integration.rs`. Check: the
  newline-in-a-delta test fails on `main`. The three `\uXXXX` tests (delta, string scanned
  per event, buffer mode) are expected to pass on `main` already, because the stream
  decoder rewrites each chunk; record what they do.
- [x] 1.3 Add "An escaped attack prompt in a JSON body" and "A span in a JSON value with
  escaped non-ASCII" to `model_guard_integration.rs`, and the escaped-marker scenario of
  `hidden-context-guard` to its integration tests. Check: they fail on `main`.
- [x] 1.4 Add the duplicate-key scenarios as integration tests on the five paths (generic
  route, `openai-chat` request, `/v1/scan`, LiteLLM, stream chunk). Check: each fails on
  `main` because the body is accepted.

## 2. Duplicate keys

- [x] 2.1 Add the helper that parses a JSON document and fails on a duplicate key (design
  D5). Check: unit tests for a duplicate at the top level, in a nested object inside an
  array, with non-string values (`{"a":1,"a":2}`), written with an escape (`"a"` and
  `"a"`), and for bodies without a duplicate, which parse as before.
- [x] 2.2 Use the helper in `flatten_json` and on the `data` payload in `decode_chunk`.
  Check: the tests of 1.4 pass, and each path answers as it does for invalid JSON.

## 3. Decoded values and the escape map

- [x] 3.1 Add the escape map to `OwnedContextFragment` (design D2). The map is empty by
  default, and its `Debug` prints positions only. Check: unit tests for an empty map, one
  escape, a surrogate pair, and adjacent escapes.
- [x] 3.2 Make `flatten_json` take the value from `Value::String` and build the map from
  the raw bytes (D1). Replace `string_with_escapes_keeps_raw_bytes` with tests of the
  decoded value, and change `check_offsets` to compare the raw bytes through the map.
  Check: the scenarios "A Unicode escape", "The two-character escapes", "An escaped
  backslash before the text of an escape", "A surrogate pair" and "An escaped key" pass as
  unit tests.
- [x] 3.3 Confirm that a lone surrogate still fails to parse. Check: a unit test in
  `json.rs`.

## 4. Engine span mapping

- [x] 4.1 Map every spanned finding of a structured unit through its fragment's map once,
  after the guards return and before the canonical sort (D3). Keep a span unchanged when
  no fragment holds it, with a debug assertion. Check: unit tests in `engine/mod.rs` for
  the three span scenarios of `pii-scanning` (after an escape, over an escape, a value that
  starts and ends with an escape) and for a plain-text unit left unchanged.
- [x] 4.2 Check that overlap resolution and `matches_count` do not change: a JSON body with
  two escaped values that each hold one match counts two. Check: a unit test.
- [x] 4.3 Check the dictionary detector on a JSON value after an escape. Check: a test
  through the engine in which the finding's span is the raw byte range of the name.

## 5. Streams

- [x] 5.1 Check that the hold-back needs no change (D4). Check: the tests of 1.2 pass and
  the existing hold-back tests pass unchanged.

## 6. Verify and document

- [x] 6.1 Run `cargo test --workspace` and `cargo clippy --workspace --all-targets`.
  Check: no failures, no warnings, and the tests of group 1 pass.
- [x] 6.2 Rerun both JSON-escape probes (`voidwall-internal/research/encoded-content/json-escape-probe/`) against the
  built binary. Check: every escaped form is blocked with the same kinds as its raw form, a
  value after `\n` or `\t` is found, and every body with a duplicate key answers 400. The
  tool call `arguments` case with an inner escape still passes; that is the recorded limit.
- [x] 6.3 Remove item 1.5 from `docs/dev/backlog.md`. Check: the file has no entry for
  duplicate JSON keys, and the item for JSON nested in a string value is still there.
- [x] 6.4 Run `docs-sync`. Check: the docs say that JSON values are scanned decoded and
  that a body with a duplicate key is rejected as a body that does not parse.
