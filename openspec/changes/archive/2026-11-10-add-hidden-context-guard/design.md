## Context

See proposal.md for why. The facts that shape the approach:

- `Interest` (`engine/guard.rs`) has one axis, the unit kind. Its doc comment says a
  second axis "is added when a producer exists". This guard is that producer.
- The direction is known at every call site, but the engine is not told it. The reverse
  proxy scans the request (`reverse_proxy.rs`, request path) and the response (response
  path and the stream driver) separately. The LiteLLM route reads `input_type`.
  `/v1/scan` records every scan as `request`.
- The reverse proxy builds a unit only when the selection wants its kind
  (`selection.wants(UnitKind::Body)`), so a unit no selected guard wants is never decoded.
- The stream hold-back (`reverse_proxy/holdback.rs`) releases text up to `p = e − L`
  after a clean scan, where `L` is `stream_holdback_bytes`, and covers `[p − C, e]` in the
  next scan.
- CLAUDE.md "Threading" and ARCHITECTURE.md §4.1 say a guard's `detect` hands its units
  to its own threads. This guard breaks that rule on purpose (decision 6).

## Goals / Non-Goals

**Goals:**

- A direction axis that the engine applies, as it applies the unit-kind axis.
- No change in what the `pii` guard and model guards see.
- No byte of a marker reaches a streaming client.

**Non-Goals:**

- Detecting a paraphrased, translated, or encoded leak.
- Learning the hidden context from the request (the system message or tools) and
  comparing the response to it.
- A per-route or per-config choice of direction.

## Decisions

### 1. Direction is a second axis of `Interest`, passed once per scan

`Interest` gains the set of directions a guard inspects. `Engine::guard` takes the
`Direction` of the message, and a guard whose interest does not hold it is not called,
as a guard whose kinds match no unit is not called today. `GuardSelection::wants` takes
the direction too, so the request side of a route that selects only `hidden_context`
builds no body unit.

The `pii` guard and model guards build their interest with both directions. The
`hidden_context` guard builds it with the response direction and the body kind, from
code, not from configuration.

Alternatives:

- A `direction` field in the guard's config. Rejected by the agreed design: the
  direction is fixed in the guard.
- A per-direction guard list on a route. Rejected: CLAUDE.md warns against per-direction
  lists, and the route's guard selection stays one list.
- A direction on each `Unit`. Rejected: a message is one direction, so every unit would
  carry the same value.

### 2. One case-insensitive regex over the escaped markers

At startup the guard builds one `regex::Regex` from the markers, each passed through
`regex::escape`, joined with `|`, under the `(?i)` flag. The `regex` crate folds case by
Unicode simple case folding, which is the agreed matching rule. It matches without
changing the text, so the span offsets stay offsets into the unit.

Alternatives:

- `aho-corasick` with `ascii_case_insensitive`. Rejected: ASCII only.
- Lower-casing the text and the markers. Rejected: lower-casing can change byte lengths,
  so the offsets no longer point into the unit, and it allocates a copy of every body.

### 3. One spanned finding per unit, at the leftmost match

`detect` calls `find` once per text and stops at the first match in the unit. The
finding carries that match's span.

A spanned finding fits the hold-back better than one without a span. A spanned finding
outside the tail stops the stream in the scan that finds it. A finding without a span
holds the whole text for one more scan and stops only when the next scan reports it
again (openai-chat-streaming, "A finding without a span waits for the next scan"). A
substring match never goes away when text is added, so the wait buys nothing.

Alternative: a finding without a span, like a model guard. Rejected for the delay above.

### 4. The hold-back bound uses the longest possible match

For each marker, validation parses `(?i)` + the escaped marker with `regex-syntax` and
reads `properties().maximum_len()`. This is the longest match in bytes, after case
folding. For example, `k` can match the 3-byte Kelvin sign. Validation rejects a marker
whose value is greater than `stream_holdback_bytes`.

Why this is enough: after a clean scan that ended at `e₀`, text up to `e₀ − L` is
released. A match not found in that scan ends after `e₀`, so it starts after
`e₀ − len`. With `len ≤ L`, it starts after the release point, and none of its bytes
were released.

Alternative: bound by 3 × the marker's byte length. Rejected: it rejects markers that
cannot grow at all, such as digits.

### 5. Duplicate markers are found with the regex

Marker B duplicates marker A when `(?i)^` + escape(A) + `$` matches B. Simple case
folding is an equivalence, so this is symmetric and needs no folding table of our own.
The check is O(n²) over at most 64 markers, once at startup.

### 6. The guard matches inline in `detect`

The regex runs in linear time over the text, with no backtracking. On a body near
`max_body_size` it costs about a millisecond. A worker thread would add a channel
round trip and a thread to save less than that. CLAUDE.md "Threading" and ARCHITECTURE.md
§4.1 are reworded to allow this one case: a `detect` that is a single linear literal
scan of its units may run inline. A detector that costs more stays on its own threads.

Alternative: `spawn_blocking`. Rejected: it adds a thread hop for the same short work.

### 7. Structured units are matched value by value

For a structured unit, the guard matches each fragment's `value` and adds the fragment's
offset to the span. It does not match the key path in `context`. A plain-text unit is
matched as one string.

### 8. The marker list stays out of every printed form

`HiddenContextConfig` implements `Debug` by hand and prints the marker count only.
Validation messages name a marker as `markers[<index>]`. The guard holds the markers only
inside the compiled regex.

### 9. `/v1/scan` reads `direction` with a typed query

The handler reads `direction` into a `Direction` enum that deserialises `request` and
`response` only. A missing parameter becomes `Request`. Any other value answers 400 with a
fixed `{"error":"invalid direction"}` and scans nothing. Like the 415 for an unsupported
content type, it is a client mistake rather than a scanner failure or a limit, so it does
not increment `voidwall_errors_total`. `record_detections` takes the parsed direction in
place of the fixed `"request"`.

## Risks / Trade-offs

- [A paraphrased or encoded leak passes] → Stated as a non-goal. The docs say the guard
  catches word-for-word leaks only, and point to the OWASP advice to keep secrets out of
  the context.
- [A short marker blocks normal answers] → Matching has no word boundary, so a short
  common marker matches inside ordinary words. The docs advise a long, random canary.
- [Inline matching on the runtime] → Bounded by `max_body_size` and linear time. If a
  later change makes `detect` cost more, it moves to its own threads.
- [Lowering `stream_holdback_bytes` fails a config that worked] → Validation names the
  key and the marker's position, so the operator sees which one to change.

## Migration Plan

None. The guard is off unless its section is declared. `/v1/scan` without `direction`
behaves as today.
