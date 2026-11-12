## 1. Accept-Encoding on the forwarded request

- [x] 1.1 When `reverse_proxy.response.scan` is on, remove every `Accept-Encoding` value
  from the forwarded request headers and insert one `Accept-Encoding: identity`, on every
  route and both formats; with response scan off, leave the header as the client sent
  it. Check: `#[test_case]` unit tests in `reverse_proxy.rs` over (scan on, scan off) ×
  (`gzip, deflate, br`, two `Accept-Encoding` headers, none).
- [x] 1.2 Integration tests in `crates/voidwall/tests/content_encoding_integration.rs`
  (a binary of its own, so the metric deltas of group 2 are exact) against an upstream that reports the `Accept-Encoding` it received: scan on with
  `gzip` → `identity`; scan on with none → `identity`; an `openai-chat` route →
  `identity`; a route with `guards = []` → `identity`; scan off with `gzip` → `gzip`;
  scan off with none → no header. Check: the tests pass.

## 2. A compressed response body is unscannable content

- [x] 2.1 Before the response body is read, when the route scans the response body (a
  selected guard reads body units and, on a generic route, the content type is in
  `content_types`), treat a non-empty body with a `Content-Encoding` other than
  `identity` as `Error::UnscannableContent` under `on_error`, on both formats. Reuse
  `is_encoded` and `has_no_body`. Check: the existing compressed-stream tests still pass.
- [x] 2.2 Integration tests in `content_encoding_integration.rs` for each scenario of "A
  compressed response body is unscannable content", and for the added scenario of "A
  compressed stream is unscannable content" (a compressed stream on an `openai-chat`
  route with `guards = []` passes): generic gzip JSON under `fail_close` (422, exact body, metric
  `outcome="blocked"`) and `fail_open` (upstream bytes unchanged, metric
  `outcome="passed"`); `openai-chat` br JSON under both; `Content-Encoding: identity`
  scanned and passed; `guards = []` passes with no `unscannable_content` sample;
  `image/png` gzip on a generic route passes; a 204 with `Content-Encoding: gzip`
  passes. Check: the tests pass, and no test still expects 400 `body_parse_failed` for a
  compressed body.

## 3. Rule text

- [x] 3.1 In `ARCHITECTURE.md`, name the `Accept-Encoding` exception next to the two
  "Nothing … rewrites a message" sentences (lines 186 and 298). Check: both sentences
  name it, and `CLAUDE.md` is not changed.

## 4. Docs and backlog

- [x] 4.1 Run the `docs-sync` workflow: state in the user docs that, with response scan
  on, Voidwall asks the upstream for an uncompressed answer and answers 422 to a
  compressed body it would scan. Check: the docs link check prints nothing, and
  `cargo test --workspace` passes the docs key test.
- [x] 4.2 Confirm backlog item 1.10 "Scan compressed response bodies" in
  `docs/dev/backlog.md` matches the built behavior. Check: it names `Accept-Encoding:
  identity` and the 422, and nothing in it is built.

## 5. Verification

- [x] 5.1 Run `cargo test --workspace`, `cargo clippy --workspace --all-targets`, and
  `cargo fmt --check`. Check: all pass with no warning.
- [x] 5.2 Rebuild the image and repeat the AnythingLLM → Voidwall → OpenAI run of
  `add-upstream-tls` task 6.3. Check: AnythingLLM's `GET /v1/models` passes (no
  `body_parse_failed` sample), and the prompt injection still answers
  `400 content blocked. Kinds: PROMPT_INJECTION`.
- [x] 5.3 Review the diff against this change's spec delta with the `code-review` skill.
  Check: no open finding.
