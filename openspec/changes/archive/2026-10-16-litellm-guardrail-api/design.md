## Context

See proposal.md for the motivation and `specs/litellm-guardrail-api/spec.md` for the
behavior.

Today the HTTP API has one handler, `process` in `crates/voidwall/src/http_api.rs`. It
checks the content type, parses the body with `classify_body`, pushes one `Body` unit, runs
`Engine::guard` with `BlockPolicy::Never`, records metrics, and maps an engine error
through `handle_scanner_failure`. `DefaultBodyLimit` enforces `max_body_size` on the
router.

`structured/json.rs` (`flatten_json`) already turns a JSON document into fragments with a
key path (`structured_messages[0].content[1].text`) and a document-absolute offset. The
regex PII guard uses the key path for keyword context.

Field-level reasoning: `voidwall-internal/research/chat-completions-field-map.md`.
Endpoint order and the decisions behind this change:
`voidwall-internal/research/openai-endpoint-tiers.md`.

## Goals / Non-Goals

**Goals:**

- A decoder whose field rules can be read in one place and tested field by field.
- Reuse of the existing JSON flattener, so offsets and key paths match `/v1/scan`.
- The LiteLLM handler shares the `/v1/scan` metric and error helpers, so the two routes
  cannot drift apart.

**Non-Goals:**

- No trust class on units.
- No `/v1/chat/completions` reverse-proxy route. The decoder for Chat Completions message
  shapes is written so that route can reuse it later, but this change adds no caller
  besides the LiteLLM handler.
- No decoding of base64 data (images, audio, files).
- No change to the engine, the guards, or overlap resolution.

## Decisions

### D1 — Select fragments from `flatten_json` by key path

The decoder parses the body twice over the same bytes: `flatten_json` for fragments with
offsets, and `serde_json::Value` for classification. The classifier walks the `Value` and
builds a selection: exact key paths to keep, and path prefixes whose whole subtree is
kept (the generic rule for an unknown field or role). The handler keeps a fragment when
its key path is selected.

Alternatives:

- **A walker of its own that records offsets.** It would repeat the position-recovery
  logic of `json.rs`, which is the subtle part of that file. Rejected.
- **Typed serde structs for messages.** They would make an unknown field or role a parse
  error or a silent drop, and the spec wants both scanned. The envelope is typed (D3);
  the messages stay a `Value`.

The key-path string is built by one shared function, so the classifier and the flattener
cannot format a path differently.

### D2 — One `Body` unit per top-level entry

Each entry of `structured_messages`, `tools`, `tool_calls`, and `texts` becomes one
`Body` unit with `UnitContent::Structured`. An entry with no kept fragment produces no
unit.

Alternative: one unit for the whole payload. It gives the same findings, because spans
in two entries never overlap, so `resolve_overlaps` per unit and over the whole payload
agree. Per-entry units were chosen because the planned verdict cache and gate work per
part (`voidwall-internal/research/detection-architecture.md` D9), and recutting units
later costs more than cutting them right now. The cost is a few more `Unit` values per
call.

### D3 — A typed envelope; `input_type` is an enum

The envelope deserializes into a struct that ignores unknown fields (no
`deny_unknown_fields`, because LiteLLM's Beta API adds fields). `input_type` is an enum
with two variants, `Request` and `Response`, so a third value cannot reach the handler.
It maps one to one onto the `direction` label. A missing `input_type`, or one with another
value, is a deserialization error, answered with 400 by the existing malformed-body path.

`structured_messages`, `tools`, `tool_calls`, and `texts` are `Option`s of `Value`
arrays. On the response side the decoder never reads `structured_messages` or `tools`.
`request_data` and `request_headers` are not fields of the struct at all, so no code path
can scan them.

### D4 — An unknown part type is a decode result, not a unit

The decoder returns the count of unknown content parts next to the selection. The handler
acts before the engine runs:

- `fail_close`, count > 0: answer 422 with `{"error":"unscannable content"}`, increment
  `voidwall_errors_total{outcome="blocked",reason="unscannable_content"}`, run no guard.
- `fail_open`, count > 0: skip the parts, increment the error counter with
  `outcome="passed"` once per message, and scan the rest.

A new `Error` variant carries the 422 status and the `unscannable_content` reason. This
keeps the status and reason mapping in `error.rs` with the other errors.

Alternative: an `Unscannable` unit that the engine resolves, as the research proposed.
Nothing in the engine reads it, and every guard would have to ignore it. Rejected for
now. It can move into the engine when a second producer appears, such as the reverse
proxy's non-UTF-8 body.

### D5 — Encoded data is classified by field, not by sniffing

A value is base64 data by its position: `input_audio.data`, `file.file_data`, and an
`image_url.url` or a string in `images` that starts with `data:` (compared ASCII
case-insensitively). The decoder counts them and does not select them.

LiteLLM (v1.105.1) fills `images` with every `image_url.url` of the messages, `https://`
URLs included. On the request side the decoder therefore ignores `images` when
`structured_messages` exists, as it ignores `texts`, so one inline image counts once and
an `https://` image counts nothing. The handler adds
the count to `voidwall_unscanned_total` only when it goes on to scan, so a 422 or a 400
counts nothing as skipped.

Alternative: detect base64 in any string by its look. Rejected: it guesses, and a long
token or key would be skipped as data.

A base64 value inside an unknown field is scanned by the generic rule. That is accepted:
the generic rule exists so that nothing unknown passes unseen.

### D6 — Config: one switch table per route, on one listener

`HttpApiConfig` gains `scan: RouteSwitch` and `litellm: RouteSwitch`, each with
`#[serde(default)]`. `RouteSwitch { enabled: bool }` has `deny_unknown_fields` and a
hand-written `Default` that returns `enabled: true`. `HttpApiConfig` derives `Default`,
so the derived default for each table must come from that impl, not from
`bool::default()`. One type serves both routes, because the two tables have the same
shape and rule.

A semantic rule in `AppConfig::validate` fails when `http_api.enabled` is true and every
route switch is false. It sits next to the at-least-one-mode check and names both keys.

Alternatives considered: LiteLLM as its own mode with
its own listener, rejected because it adds a port, a port-conflict rule, and a `mode`
label value for no need seen so far; and a LiteLLM switch that starts the listener on its
own, rejected because two switches would then start one listener.

### D7 — The router adds a route only when its switch is on

`router` adds `/v1/scan` when `config.http_api.scan.enabled` is true and
`/beta/litellm_basic_guardrail_api` when `config.http_api.litellm.enabled` is true. A
route that is off is answered by axum's fallback with 404, the same as any route that
does not exist. Both routes sit under the same `DefaultBodyLimit` layer.

The handler shares `record_request`, `handle_scanner_failure`, and the detection-metric
loop with `/v1/scan`. The detection-metric loop takes the direction as a parameter
instead of the fixed `"request"`.

### D8 — The response is two typed shapes

The response is an enum serialized with `action` as the tag: `None` → `{"action":"NONE"}`
and `Blocked { blocked_reason }` → `{"action":"BLOCKED","blocked_reason":…}`. There is no
variant for `GUARDRAIL_INTERVENED`, so the route cannot send it. The reason text is built
from `ScanResult::kinds()`, which is already sorted and holds each kind once, and that is
the set the reverse proxy's 403 lists.

Both shapes and the request envelope carry `ToSchema` for the OpenAPI document.

## Risks / Trade-offs

- [LiteLLM's API is Beta and can change shape] → Integration tests post payloads copied
  from one named LiteLLM version, recorded in the fixture's file name. A LiteLLM upgrade
  is checked by refreshing the fixtures.
- [A key path that holds `.` or `[` in a key could select the wrong fragment] → The
  classifier and the flattener share one path builder, so equal input gives an equal
  string. LiteLLM's known keys hold neither character, and a collision only adds or drops
  scanning of an unknown field.
- [Generic scanning of an unknown field can scan base64 and cause a false positive] →
  Accepted (D5). It is visible as a `BLOCKED` with a kind, and the field can get a rule
  when it becomes known.
- [The route is on by default, which widens the REST API] → The REST API has no
  authentication by spec. The route reads and reports like `/v1/scan`, and an operator
  can turn it off.
- [Two parses of one body cost CPU] → The `Value` parse is a fraction of the scan cost,
  and the body buffer is dropped once both are done.

## Migration Plan

None. The route is new and `/v1/scan` stays on by default. A config without the new
tables gets both routes, and a config that sets `http_api.litellm.enabled = false` gets
today's behavior. Rollback is that setting or the previous build.
