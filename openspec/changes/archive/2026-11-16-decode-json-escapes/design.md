## Context

`flatten_json` (`crates/voidwall/src/structured/json.rs`) parses the body into a
`serde_json::Value`, lists the position of every quoted string in the raw bytes, and then
walks the tree and takes one position per key and per string value. For a string value it
copies the raw bytes between the quotes into the fragment and throws away the decoded
string that the `Value` already holds. Keys are taken from the `Value`, so the key path is
already decoded.

Who calls it:

- Generic JSON bodies, `openai-chat` requests and buffered responses, `/v1/scan` and the
  LiteLLM route pass the bytes of the body as received.
- The stream decoder (`structured/openai_chat_stream.rs::decode_chunk`) parses each chunk
  into a `Value` first, writes parts of it back to JSON with `serde_json::to_vec`, and
  passes those bytes. That step already turns `@` into `@` in a stream. It writes a
  quote, a backslash and the control characters (`\n`, `\t`) back as escapes, so those
  stay literal in a stream today.

A duplicate key keeps its first position in the `Value` and takes the last value, so the
raw bytes hold more strings than the walk takes. Every fragment after it reads the wrong
bytes (`docs/dev/backlog.md`, item 1.5). In a stream the duplicate is dropped when the
chunk is parsed, before `flatten_json` sees it.

serde_json parses into `String` with validation on, so a lone surrogate (`\ud800` with no
pair) already fails to parse. That stays.

Every span consumer computes `fragment.offset + index in the value`: the regex scanner and
its overlap resolution (`voidwall-pii`), `UnitText::source` for the model guards, and
`hidden_context`. No API returns spans. They are used by overlap resolution, the
canonical finding order and the stream hold-back.

## Goals / Non-Goals

**Goals:**

- Every guard reads the decoded value of a JSON string (see proposal).
- A finding span in a buffered body still names the raw bytes the characters came from.
- A body with a duplicate key is never scanned at the wrong positions.
- The guards and `voidwall-pii` stay unchanged.

**Non-Goals:**

- JSON nested inside a string value, such as a tool call's `arguments`. It is decoded one
  layer only, and an escape of the inner document stays literal. In a stream the inner
  escape can also be split across deltas. This is a second decoding layer, like the nested
  encodings of Phase 2 of the encoded-content plan
  (`voidwall-internal/research/encoded-content/encoded-content-detection-plan.md`); it goes to the backlog.
- A JSON document sent under a content type that is not JSON, to a generic route or to
  `/v1/scan`. It is flat text, as today.
- Unicode normalization (Phase 1 of the encoded-content plan) and base64 or hex decoding
  (Phase 2).
- CSV bodies: their only escape is a doubled quote.
- Changing how a lone surrogate is treated.

## Decisions

### D1. The value comes from the parsed `Value`

`walk` uses the decoded string that `Value::String` already holds and keeps `offset` at
the first content byte. No second JSON decoder is written. The raw bytes between the
quotes are read only to build the map (D2).

*Alternative:* write a decoder over the raw bytes. Rejected because it repeats what
serde_json already does and could disagree with it.

### D2. Each fragment carries an escape map

The map lists one entry per escape sequence: the position in the decoded value, the
decoded length, and the raw length. A value with no backslash has an empty map and
allocates nothing. A fragment built by hand (the stream window in
`reverse_proxy.rs::text_unit`, tests) gets the empty map, which is the identity.

To map a span, the engine turns a decoded position into a raw position. A position inside
one escape's decoded character goes to the start of the sequence for a span start, and to
its end for a span end. So a character from an escape maps to the whole sequence (spec
`pii-scanning`).

*Alternative:* one raw offset per decoded byte. Rejected because it costs memory for every
value.

### D3. The engine maps spans once, before the canonical sort (agreed 2026-11-16)

Guards keep reporting `offset + decoded index`. After the guards return, the engine finds
the fragment of each spanned finding in a structured unit, maps the span through that
fragment's map, and then sorts. A plain-text unit is not touched.

Why this stays correct before the mapping:

- Decoding never grows a value. `\n` is 2 raw bytes to 1, `@` is 6 to 1, `ó` is
  6 to 2, `一` is 6 to 3, and a surrogate pair is 12 to 4. So `offset + decoded index`
  stays inside the fragment's raw range, and spans of two fragments never overlap.
  Overlap resolution in the regex guard and the per-guard counts are therefore the same as
  over raw spans.
- The map is monotonic, so a resolved, non-overlapping set stays non-overlapping after it
  is mapped.

The span scenarios of the specs are true for a finding that leaves the engine. A guard
tested alone reports `offset + decoded index`, so the tests for a span over an escape run
through the engine.

*Alternatives:* each guard maps its own spans, or no exact map. Both were rejected when the
user chose this option (2026-11-16): the first repeats the logic in three guards, and the
second changes the model-guard span rule.

### D4. Streams need no map

After D1, `flatten_json` decodes the escapes that the stream decoder wrote back (`\n`,
`\t`, a quote, a backslash), so the joined pieces and the strings scanned per event hold
decoded text. The hold-back counts positions in the joined text, never in event bytes, and
a window unit is built by hand with the empty map. The hold-back, `TAIL_BYTES` and the
window sizes do not change.

A fragment of a string scanned per event carries offsets into the bytes that the stream
decoder wrote, not into the event. Its spans are used only for the order of findings, so
the span rule of `pii-scanning` leaves streams out.

### D5. A duplicate key is a parse failure (agreed 2026-11-16)

One helper parses a JSON document and fails when an object holds a key twice. It compares
two counts: the quoted strings in the raw bytes, and the keys plus string values of the
parsed tree. serde_json keeps one entry for a repeated key, with keys compared after their
escapes are decoded, so the counts differ exactly when a key repeats, at any depth. The
check runs before any fragment is built.

The helper is used at the two places that parse a body as received:

- `flatten_json`, for generic bodies, `openai-chat` requests and buffered responses,
  `/v1/scan` and the LiteLLM route;
- `decode_chunk`, on the chunk's `data` payload, before it is written back to JSON.

It returns the error that invalid JSON returns today at that place, so each path applies
its existing rule and no new error code is added.

*Alternative:* a parser that sees every key and scans every duplicate value. Rejected by
the user (2026-11-16): the flattener and the tree-based field rules of the `openai-chat`
and LiteLLM decoders all read a tree without duplicates and would need a new walker.

## Risks / Trade-offs

- [Benign escaped content now blocks where it passed before] → This is the intended effect:
  the guards now see what the upstream sees. The measured cases are in
  `voidwall-internal/research/encoded-content/json-escape-bypass.md`. Integration tests cover each path.
- [A client or an upstream that sends a duplicate key is rejected] → SDKs build JSON from
  maps, which cannot hold a key twice, so this is expected to be rare. Which upstreams
  accept duplicate keys was not checked. The docs name the new rejection.
- [Under `fail_open`, a stream chunk with a duplicate key is scanned as plain text and a
  generic body follows `on_error`] → This is the existing rule for a body that does not
  parse. An operator who needs a block uses `fail_close`, which is the default.
- [A span in a structured unit with no matching fragment] → A model-guard span always lies
  inside one fragment value (`UnitText` refuses others). If the engine finds no fragment
  for a span, it keeps the span unchanged, and a debug assertion catches it in tests.
- [A decoded value holds detected values in a new buffer] → It replaces the raw copy, so
  there are no more buffers than today. The escape map holds positions only.
- [Cost] → serde_json already decoded every string. The new work is one pass over the raw
  bytes of values that contain a backslash, and one count of the tree.
