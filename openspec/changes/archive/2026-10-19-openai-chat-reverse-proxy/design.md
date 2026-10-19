## Context

See proposal.md for the motivation and `specs/openai-chat-proxy/spec.md` for the
behavior.

The LiteLLM change left these parts in place:

- `structured/chat_completions.rs`: `Selection` classifies a message, a tool, and a tool
  call by field tables, and picks the kept fragments out of `flatten_json`. It groups
  fragments into units by `entry_root`, which cuts a key path at the first `]`. So it
  knows only array entries such as `structured_messages[2]`.
- `structured/litellm.rs`: a typed envelope plus `decode`, which returns unit fragments,
  `unknown_parts`, and `encoded_values`.
- `error.rs`: `Error::UnscannableContent` (422, `unscannable_content`).

The reverse proxy (`reverse_proxy.rs`) builds one `Body` unit from `classify_scan_body`,
admits a body by the `content_types` allowlist, and answers every block and error with
the flat `{"error": ...}` body. Some answers come from `Error::into_response`, some from
`block_response`, and some from inline helpers (`buffer_body`, `upstream_timeout`). The
response body is read in full before its content type is checked.

The upstream client is `build_http()`, so an `https://` upstream fails at run time. This
change keeps that, as agreed.

Field reasoning: `voidwall-internal/research/chat-completions-field-map.md`. Tiers and
decisions: `voidwall-internal/research/apis/openai-endpoint-tiers.md`.

## Goals / Non-Goals

**Goals:**

- One place holds every field rule: the request and response tables sit next to the
  tier-1 message tables.
- The route's answer shape is decided once per route, so no code path can answer an
  `openai-chat` route with the flat body.
- The LiteLLM route's behavior does not change.

**Non-Goals:**

- No upstream TLS.
- No SSE parsing and no per-chunk scan (tier 3).
- No path detection. The route's `format` is the only switch.
- No change to the engine, the guards, or overlap resolution.

## Decisions

### D1 — `format` is an enum on `Route`

`Route` gains `format: RouteFormat` with `#[serde(default)]`. `RouteFormat` has two
variants, `Generic` (the default) and `OpenAiChat` (`"openai-chat"`). An unknown string
is a serde error, which the loader already reports with the `schema` category. No
semantic rule is needed.

`ResolvedRoute` carries the format. Every later branch matches on it, so a third format
is a compile error at each branch until it is handled.

Alternative: `Option<String>` checked in `validate`. Rejected: a typo could reach the
handler as a string.

### D2 — Fragments are paired with entries by leaf order

A top-level object field such as `metadata` or `response_format` is one unit, as an
array item such as `messages[2]` is.

The classifier walks the parsed `Value` in document order and records one decision per
string leaf: the entry it belongs to, or skip. It visits every string, also under a
skipped field, an encoded value, or an unknown part, so no leaf is missing from the
sequence. `flatten_json` walks the same bytes and returns one fragment per string leaf,
in the same order. `into_unit_fragments` zips the two sequences. No key path is
matched, so a key that holds `.` or `[` cannot be taken for another key. `entry_root`
and `is_at_or_under` are deleted.

Both walks parse the same bytes with the same `serde_json` settings (`preserve_order`),
so they see the same leaves in the same order. `into_unit_fragments` checks that the two
counts are equal, in every build. A mismatch is `Error::Scanner`, which follows
`on_error` as a scanner failure on both routes. A unit test covers top-level keys that
hold `.` and `[`.

The LiteLLM decoder classifies the top-level keys of the raw `Value` in document order.
The typed `GuardrailRequest` still validates the envelope. Every key it ignores, such
as `request_data`, is recorded as skip. Its units do not change, and its tests must
pass unchanged.

Alternatives:

- Two candidate roots per fragment, looked up by path. Rejected: a path does not escape
  `.` or `[` in a key, so a top-level key such as `a.b` matches no entry and its value
  is never scanned.
- A lookup at every segment boundary of the path. Rejected: it finds the dropped key,
  but it still matches paths that are ambiguous.
- A linear scan for the longest matching root. Rejected: a long conversation has
  hundreds of entries and thousands of fragments.
- A debug assertion on the two counts. Rejected: a release build would skip it, and a
  mismatch would pair decisions with the wrong leaves.

### D3 — The request and response tables live in `chat_completions.rs`

`chat_completions.rs` gains two top-level tables. They use the existing `Rule` enum. A
top-level key the tables do not list falls to `Rule::Scan`, the same as an unknown field
inside a message.

- `REQUEST`: `messages`, `tools`, `functions`, `response_format`, `prediction`,
  `metadata`, `safety_identifier`, `user`, `prompt_cache_key`, `web_search_options`, and
  the skip list from the spec.
- `RESPONSE`: `choices`, the skip list from the spec, and `CHOICE` for one choice.

`messages`, `tools`, and `functions` cut one entry per array item. `choices` cuts one
entry per choice. Every other kept key is one field entry (D2).

Two `Selection` methods take a parsed top-level object: `request(&Map)` and
`response(&Map)`. `Rule` stays private.

The response message gets its own table, `RESPONSE_MESSAGE`. It extends `MESSAGE` with:

- `annotations`: Scan.
- `audio`: `id` and `expires_at` Skip, `data` Encoded, and `transcript` Scan.

`MESSAGE` is not changed, because a change there would change what the LiteLLM route
counts as encoded data.

`prediction.content` uses the existing `Rule::Content`, so an unknown part type there is
unscannable like any other.

### D4 — `structured/openai_chat.rs` decodes, as `litellm.rs` does

```
decode_request(raw)  -> Result<Request, Error::BodyParse>
decode_response(raw) -> Result<Decoded, Error::BodyParse>

Request  { decoded: Decoded, stream: bool }
Decoded  { units: Vec<Vec<OwnedContextFragment>>, unknown_parts, encoded_values }
```

The body is parsed twice over the same bytes: once as a `serde_json::Value` for
classification, and once by `flatten_json` for fragments, as tier-1 D1 does.

- A request that is not an object, or has no `messages` array, is `BodyParse`.
- `stream` is true only for the JSON value `true`.
- A response that is valid JSON but not an object is scanned whole.
- A response that does not parse returns `BodyParse`, and the handler applies today's
  parse-failure rule.

`Decoded` is shared with `litellm.rs`, which drops its own copy of the struct.
`Debug` is not derived, because the fragments hold scanned text.

### D5 — The answer shape is part of the route

The `openai-chat` route needs two answer shapes, so every answer in `reverse_proxy.rs`
goes through one function:

```
enum AnswerShape { Plain, OpenAi }      // from RouteFormat
fn answer(shape, Error) -> Response
fn block(shape, &[String]) -> Response
```

- The 404 for "no route" is outside every route and stays `Plain`.
- `buffer_body`, `upstream_timeout`, `classify_scan_body`, `handle_scan_error`, and the
  502 paths take the shape instead of calling `into_response` themselves.

`error.rs` gains `Error::into_openai_response()`. It holds the status, type, and code
table from the spec next to the existing status table. Both functions read the same
fixed message constants, so the message text cannot drift between shapes.

`block` for `OpenAi` builds 400 with `code` `content_filter` and the `kinds` array. The
kinds come from `ScanResult::kinds()`, as the 403 does.

Alternative: rewrite the body at the end of the handler, keyed on the status. Rejected:
it would parse Voidwall's own answers back, and a forwarded upstream 400 could not be
told apart from a block.

### D6 — Stream and non-JSON checks, in order

Request side, on an `openai-chat` route with request scan on and a body a guard wants:

```
decode_request ──err──▶ 400 (both policies; errors{blocked, body_parse_failed}; blocked_total)
     │
stream && response_scan && fail_close ──▶ 422 (errors{blocked, unscannable_stream}); no guard
     │
unknown_parts > 0 ──▶ on_error with UnscannableContent (as LiteLLM)
     │
encoded_values ──▶ voidwall_unscanned_total
     │
units + path/query/header units ──▶ run_engine
```

Under `fail_open`, `stream: true` does nothing on the request side. The response side
counts it, so a message counts once.

Response side, with response scan on. The content type is read from the response
headers **before** the body is read:

| Upstream content type | `fail_close` | `fail_open` |
|---|---|---|
| `text/event-stream` | 422, drop the upstream body | count `passed`, stream through unbuffered |
| JSON | buffer, `decode_response`, scan | same |
| Other or missing, with a body | 422 | count `passed`, stream through unbuffered |
| Other or missing, no body | forward | forward |

"No body" is read from the headers: status 204 or 304, a `HEAD` request, or
`Content-Length: 0`. A pass-through behaves as with response scan off: no
`max_body_size` limit and no time limit on the body read.

`error.rs` gains `Error::UnscannableStream`. It answers the same 422 body as
`UnscannableContent`, and its reason is `unscannable_stream`. The status and reason
mapping stays in one file.

Alternative: buffer first, then check, as the generic path does. Rejected: a stream would
then wait for the whole completion, or hit `max_body_size`, before anything reaches the
client under `fail_open`.

### D7 — Units

There is one `Body` unit with `UnitContent::Structured` per kept entry, as tier-1 D2
does. The URL path, query, and header units are built as today. Overlap resolution runs
per unit inside the regex guard. Entries never share a byte range, so per-unit resolution
equals resolution over the whole body.

### D8 — Rules and docs

- `CLAUDE.md` "Outcomes": "A detection blocks with a fixed 403…" gains "unless explicitly
  stated otherwise". The section names the `openai-chat` route's 400.
- `CLAUDE.md` "Errors": the party-at-fault rule gains the exception that a
  response-side block on an `openai-chat` route answers 400.
- `openspec/config.yaml` context: the same two notes.
- Proxy docs and `README.md` get:
  - the two-route example (`/v1/chat/completions` with `openai-chat`, and `/v1` generic);
  - the HTTP-only note;
  - the streaming behavior.

## Risks / Trade-offs

- [`format` on a broad prefix such as `/v1` answers 400 to `/v1/embeddings`] → The docs
  show the two-route setup. Longest-prefix matching already supports it.
- [A response-side 400 tells the client that its request was wrong] → Accepted, so that
  OpenAI clients handle a block without a change. `code` `content_filter` names the
  real cause.
- [OpenAI SDKs retry 500, 502, and 504 by default] → A scanner failure under
  `fail_close` can reach Voidwall up to three times. A 400 or 422 is not retried. The
  docs state this.
- [Generic scan of unknown top-level keys can cause false positives on vendor
  extensions] → A block names the kind, so the cause is visible. A known key can get a
  rule later.
- [`stream: true` under `fail_open` sends model output unscanned] → It is counted as
  `unscannable_stream`, so operators can measure it before tier 3.
- [An upstream with a non-JSON body and no length header counts as having a body] →
  Under `fail_close` it answers 422. Real Chat Completions servers send JSON or
  `text/event-stream`.
- [An `https://` upstream passes validation and fails with 502] → Unchanged by this
  change. Documented. A backlog item covers upstream TLS.

## Migration Plan

None. `format` is opt-in. A config without it behaves as before. Rollback is to remove
`format` from the route, or to run the previous build.

### D9 — Fixtures: hand-written requests, recorded responses

The integration tests use two sources of fixtures. The file name of each fixture names
its source and version.

- **Requests are hand-written from the `openai-python` types.** One file holds every
  request field the spec scans or skips. No real server sends all of them.
- **Responses, error bodies, and the stream are recorded once from LM Studio 0.4.26**
  (`google/gemma-4-26b-a4b-qat`, on `:1234`). The recordings carry the vendor fields a
  hand-written file would miss:
  - `message.reasoning_content` on the response;
  - a top-level `stats` key;
  - an error as a flat string, `{"error": "…"}`, that echoes request input;
  - an error as an object whose `type` is `invalid_request`;
  - the exact stream content type, `text/event-stream`.

| File | Source |
|---|---|
| `openai-python-<ver>-request-full.json` | Hand-written |
| `lmstudio-0.4.26-response.json` | Recorded: plain answer |
| `lmstudio-0.4.26-response-tool-call.json` | Recorded: tool call |
| `lmstudio-0.4.26-error-flat.json` | Recorded: 400 for an unknown role |
| `lmstudio-0.4.26-error-object.json` | Recorded: 400 for a body that is not JSON |
| `lmstudio-0.4.26-stream.txt` | Recorded: used only for the content-type check |

The raw recordings, with their requests and response headers, are in
`recordings/lmstudio-0.4.26/` in this change folder. Its `README.md` maps each recording
to its fixture.

The recordings hold no PII. As in tier 1, a test inserts a placeholder by editing the
loaded fixture. The stub upstream serves a fixture with its recorded status and content
type.

Alternatives:

- **vLLM.** Current GPU wheels do not support the local GPU.
- **Ollama.** It is installed too, but LM Studio already serves a loaded model. One
  recorded server is enough to show real vendor fields.
- **Only hand-written files.** They would miss the vendor fields above, which are the
  real test of the rule that an unknown key is scanned.
