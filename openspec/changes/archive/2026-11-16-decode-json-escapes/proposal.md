## Why

The JSON flattener keeps escape sequences in a string value as literal text, but the
upstream's JSON parser decodes them. So the guards do not read what the LLM reads.
Measured on `main` (2026-11-16):

- **Attack:** an e-mail, a `US_SSN`, an IBAN and a prompt injection with every character
  written as `\uXXXX` pass every guard. One escaped `@` is enough for an e-mail.
- **Normal traffic:** a `US_SSN` directly after `\n` or `\t` is missed by the regex guard,
  because the literal `n` joins the value. A client that uses Python's default
  `json.dumps` escapes all non-ASCII, and then `pii_ml` misses a name it finds in raw
  UTF-8.
- **Duplicate keys:** one duplicate key shifts every later fragment to the wrong text, and
  no guard reports anything (backlog item 1.5). The fix for escapes takes the value from
  the parsed tree and the offset from the raw bytes, so it needs this fixed too.

Measurements: `voidwall-internal/research/encoded-content/json-escape-bypass.md`.

This change comes before Phase 1 of the encoded-content plan
(`voidwall-internal/research/encoded-content/encoded-content-detection-plan.md`: normalize invisible and
confusable Unicode). Phase 1 cannot work on a JSON route while values hold literal escapes,
and it reuses the offset map this change adds.

## What Changes

- The value of every JSON string fragment is the decoded string: every JSON escape is
  resolved once, `\uXXXX` with surrogate pairs included. This applies to every path that
  reads a JSON body into fragments, in both directions:
  - JSON bodies on a generic reverse proxy route (request and response)
  - `openai-chat` routes: request, buffered response, and streams in both modes
  - `/v1/scan` with a JSON body
  - the LiteLLM guardrail route (request side and response side)
- Every guard scans the decoded values, never the escaped text.
- Each fragment carries a map from positions in its decoded value to bytes of the raw
  document. The engine maps every finding span once, before the canonical sort, so a span
  still names the raw bytes the value came from. The guards do not change.
- **BREAKING**: a JSON body in which one object holds the same key twice is a body that
  does not parse. Each path applies its existing rule for that: 400 on an `openai-chat`
  request, on `/v1/scan` and on the LiteLLM route, the `on_error` policy on a generic
  route, and the parse-failure rule in a stream.
- No new configuration, metric, or error code. The forwarded message does not change.

Limits that stay:

- JSON that is nested inside a string value, such as a tool call's `arguments`, is decoded
  one layer only. An escape of the inner document stays literal. This is recorded in the
  backlog.
- A JSON document sent under a content type that is not JSON, to a generic route or to
  `/v1/scan`, is scanned as flat text, and its escapes stay literal.

## Capabilities

### New Capabilities

None.

### Modified Capabilities

- `pii-scanning`: a JSON fragment's value is the decoded string, a span inside it maps to
  the raw bytes of the document, and a body with a duplicate key fails to parse.
- `guard-configuration`: a model guard scores the decoded values of a JSON unit.
- `hidden-context-guard`: the guard matches a marker in the decoded value.
- `dictionary-detection`: the span of a match in a JSON value follows the span rule of
  `pii-scanning`.

## Impact

- Code: `crates/voidwall/src/structured/json.rs` (flattener, duplicate-key check),
  `crates/voidwall/src/structured/mod.rs` (`OwnedContextFragment` gets its map),
  `crates/voidwall/src/structured/openai_chat_stream.rs` (duplicate-key check on each
  chunk), `crates/voidwall/src/engine/` (span mapping before the canonical sort). The
  regex guard, the model guards, `hidden_context` and `voidwall-pii` do not change.
- Every JSON route detects more: a value that was escaped can now block. Benign escaped
  content that a guard flags also blocks now.
- A client or an upstream that sends a duplicate key is now rejected.
- `docs/dev/backlog.md`: item 1.5 is closed by this change, and one item is added for JSON
  nested in a string value.
- No dependency change. CSV bodies do not change.
