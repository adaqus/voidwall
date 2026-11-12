## Why

A hosted provider compresses its JSON answers when the client asks for it, and the
reverse proxy forwards the client's `Accept-Encoding` unchanged. The proxy does not
decompress, so it cannot read such a body: in the end-to-end run of AnythingLLM →
Voidwall → OpenAI (change `add-upstream-tls`), `GET /v1/models` answered 400 with
`reason="body_parse_failed"`, because OpenAI sent compressed JSON. Local servers such as
LM Studio did not compress, so the earlier recipe tests did not show it.

## What Changes

- When `reverse_proxy.response.scan` is on, the reverse proxy sets `Accept-Encoding:
  identity` on every request it forwards, on both route formats. It replaces the
  client's value, or adds the header when the client sent none.
- When `reverse_proxy.response.scan` is off, the client's `Accept-Encoding` is forwarded
  unchanged, as today.
- An upstream response body with a `Content-Encoding` other than `identity` is
  unscannable content on both route formats, JSON and stream alike: 422
  `unscannable content` under `fail_close`, forwarded unscanned under `fail_open`, with
  `voidwall_errors_total{reason="unscannable_content"}`. Today a compressed JSON body
  answers 400 `body_parse_failed`, and only a compressed `openai-chat` stream answers 422.
- The rule "the proxy never rewrites a header value" gets one stated exception:
  `Accept-Encoding`. The reverse-proxy spec and `ARCHITECTURE.md` name it.
- Scanning a compressed body (decompression) is not part of this change. It is backlog
  item 1.10.

## Capabilities

### New Capabilities

None.

### Modified Capabilities

- `reverse-proxy`: "A clean message is forwarded unchanged" names the `Accept-Encoding`
  exception; a new requirement sets `Accept-Encoding: identity` when response scan is on;
  a new requirement makes a compressed response body unscannable content on every route.
- `openai-chat-streaming`: "A compressed stream is unscannable content" applies only
  when the route scans the response body; a route with `guards = []` forwards a
  compressed stream.

## Impact

- Code: `crates/voidwall/src/reverse_proxy.rs` (the forwarded request headers, the
  response-side check that uses `is_encoded`).
- Tests: unit tests in `reverse_proxy.rs`; integration tests in
  `crates/voidwall/tests/reverse_proxy_integration.rs` that read the header the upstream
  receives, and the answer to a compressed response.
- Docs: `ARCHITECTURE.md` (the two "nothing rewrites a message" sentences),
  `docs/configuration.md` or `docs/recipes/README.md` where response scan is described,
  `docs/dev/backlog.md` item 1.10.
- No new configuration key, metric family, label, or dependency.
- Behavior change for an operator: a compressed JSON response answers 422, not 400, under
  `fail_close`, and passes unscanned under `fail_open`, where today it is scanned as
  plain text.
