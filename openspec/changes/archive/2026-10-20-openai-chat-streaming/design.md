## Context

See proposal.md for the motivation. Today `reverse_proxy` reads the response content type
before the body. On an `openai-chat` route a `text/event-stream` response is
`Error::UnscannableStream`, and a `stream: true` request under `fail_close` answers 422
before the upstream call (`decode_openai_request`). Every other response is buffered
whole, under `upstream_timeout_secs` and `max_body_size`, and scanned once.

Constraints that shape the approach:

- A guard is called with units and returns findings; the engine and the `Guard` trait
  stay as they are. The scanner never runs on the async runtime.
- Nothing rewrites a message. The proxy may hold an event back or stop the stream, but
  it forwards each event as the upstream sent it.
- Once the status line is sent, the 400 is impossible.

## Goals / Non-Goals

**Goals:**

- No byte of a detected value reaches the client in hold-back mode, for every match
  inside one open text no longer than the hold-back minus the tail.
- A stop before the first byte answers exactly what a buffered response answers today.
- Memory per stream in hold-back mode stays bounded by the window, not by the stream
  length.

**Non-Goals:**

- Streams on a route without `format`. A `text/event-stream` there stays as today.
- The LiteLLM endpoint, `/v1/responses`, and Anthropic Messages streams.
- Any change to `voidwall-pii`, the `Guard` trait, or `Engine::guard`.

## Decisions

### 1. Hold-back window by default, buffer mode as an option

| Option | Leak on a detection | First token |
|---|---|---|
| Hold back L bytes, release after each scan (chosen default) | None for matches ≤ L − R | ~L bytes behind the model |
| Buffer all, scan once, replay (chosen option) | None | Only at the end |
| Pass through, scan in parallel, cut on a finding | The value is already sent | No delay |
| Scan each chunk alone | A split value is missed | No delay |

The last two break "a detection blocks", so they are rejected. Buffer mode suits agents
that do not read partial output; hold-back suits chat UIs.

### 2. The window: C, L, R and the release rule

```
   p − C                       p                         s     e
     │◀──────── C = 512 ──────▶│◀────────── L = 512 ───────────▶│
     │                         │                    │◀─── R ───▶│
 ────┼─────────────────────────┼────────────────────┼───────────┤
     │ released, kept as       │ held back          │ tail      │
     │ left context            │                    │           │
     └──────────── one scan covers [p − C, e] ──────────────────┘

 p  release point     e  end of the received text     s = e − R
```

- A scan runs per joined string when `stream_scan_bytes` (K) of new text arrived, and at
  the end. No timer is needed: text newer than L is held back anyway, so K ≤ L is the
  only rule.
- After a scan, `p` moves to `min(e − L, start of the earliest waiting finding)`, then
  down to an event boundary. Events are released in arrival order.
- Why L ≥ max match + R is enough: a match that overlaps the new `p` ends at most
  `max match` after it, so before `s`. It is settled in this scan and stops the stream
  before `p` is released.
- Why C = 512 is enough: an unsettled match starts after the old `p` (by the same
  argument), and the keyword-context detectors look back at most `MATCH_LOOKBACK = 512`
  bytes from a match end (`keyword_context_detector.rs:1608`, `user_detector.rs:24`).
- Default L = 512, not the measured ~160 (keyword + separator + value): the user chose
  the regex detector's own 3× margin over a lower delay. The default model guard's
  64-token overlap (~256 bytes) is also inside it.

Memory per joined string is at most C + L + K bytes of text, plus the events not yet
released.

**Closing a text.** Events go out in arrival order, so a text that stops growing would
hold its last L bytes, and every event after them, until the stream ends: reasoning then
content, a tool call's name then its arguments, tool call 0 then 1, a choice that
finishes before the others. So a text of a choice closes when another text of the same
choice gets text, or when the choice sends `finish_reason`. A closed text gets the
end-of-stream scan — no tail wait, and a finding without a span does not wait — and is
released whole or stops the stream. A closed text that gets more text opens again and
goes on as the same joined text. The next scan keeps C bytes of released context, so a
value split across the close is still found, but its first part may already be out.
Known servers (vLLM, LM Studio, OpenAI) do not go back to a field.

### 3. The tail rule (R)

A pattern boundary matches at the end of the input, so the first digits of a longer
number can match a shorter kind. A spanned finding that ends inside the last R bytes
waits for more text, or for the end. R is a constant, not a key. Its value is the
longest right-side extension that can turn a match into a non-match, measured over
the shipped patterns (tasks.md 3.1), and it replaces `<R>` in the spec delta.

### 4. A finding without a span waits one scan

A whole-unit finding (`Finding::whole_unit`, model guards) has no end to place against
the tail. The user chose to wait: the scan that first reports it does not stop the
stream and does not move `p` for that string; the next scan of the same string stops
the stream if the same guard reports the same kind without a span again. At the end of
the stream a waiting finding in an open text stops it. The scan at a text's close is the
next scan, also when the stream ends before it: a waiting finding it does not report
again is dropped, and the text is released.

### 5. The stop event after the first byte

The proxy sends `data: <the route's JSON error body>\n\n`, without an event name, and
closes. Both official SDKs raise on it (read 2026-10-19):

- `openai-python` `src/openai/_streaming.py` 93–106: a mapping with an `error` key raises
  `APIError(message=error.message, body=error)`.
- `openai-node` `src/core/streaming.ts` 149–155: `data.error` throws `APIError`.

No `[DONE]` before or after it: Python stops reading at `[DONE]`, and Node ignores
errors after it.

### 6. Units for a stream scan

Each scan builds one body unit per joined string with new text, as a structured fragment
with the key path the non-streaming field has (`choices[0].message.content`,
`choices[0].message.tool_calls[1].function.arguments`). The structured scan then gives a
key path the same keyword context as on a buffered response. Fragment offsets start at
the window start; the driver adds it back to place a finding against `p` and `s`. Each
other chunk key that the response rules scan becomes a unit of its event, scanned once.
The route's response headers are scanned once, before the first release.

The regex PII guard still resolves overlaps once per unit per call, and it is still the
only producer of its vocabulary, so the resolution rule does not change. A stop takes
its kinds from the settled findings of the scan that stops it.

### 7. Where the code goes

- `structured::sse`: an incremental SSE framer — `data:` lines, multi-line data,
  comments, `event:`/`id:`/`retry:`, `[DONE]`, and a frame split across reads. It keeps
  each event's raw bytes so the release forwards them unchanged.
- `structured::openai_chat_stream`: the chunk decoder and the per-choice, per-field
  joiner. It takes its field rules from `chat_completions.rs`, so the stream and the
  buffered response cannot drift.
- `reverse_proxy`: a stream driver that reads the upstream body frame by frame, feeds the
  framer, calls `Engine::guard` on the scan schedule, and writes released events to the
  client body through a bounded channel. Every answer still goes through `answer` and
  `block`; a stream stop gets one more function that turns the same body into the event.
- `error.rs`: `UnscannableStream` goes.

### 8. Config shape

TOML stays flat: `stream = "holdback" | "buffer"` on the route, and the four top-level
keys beside `upstream_timeout_secs`. In the resolved route the mode lives inside the
format (`RouteFormat::OpenAiChat { stream }`), so a generic route cannot hold a mode once
validation passes. Each key is a range-checked newtype like `UpstreamTimeout`; the
cross-key rules run in validation (`semantic`). The startup warning sits beside the
existing warnings in `config.rs`.

### 9. Limits

- `upstream_timeout_secs` bounds the wait for the headers. For a stream, each read of
  the upstream body runs under `stream_idle_timeout_secs`; any byte resets it.
- One counter adds the raw body bytes against `max_body_size`.
- Both stop the stream whatever `on_error` says, matching today's 502 and 504.

### 10. Compressed streams

The proxy does not decompress. A stream with a `Content-Encoding` other than `identity`
has no readable `data:` line, so the framer would find no text and release every byte
unscanned, under either `on_error`. Such a stream is unscannable content, decided from
the headers before the body: under `fail_close` it answers 422 before any byte, under
`fail_open` it passes as any unscannable response does. Buffer mode takes the same rule.

## Risks / Trade-offs

- [A custom pattern without keywords has no length bound, so a match longer than L can
  leak its first part] → Startup warning; buffer mode has no such gap.
- [A model guard can need more right context than L to detect a value] → L defaults to
  512 bytes, above the default model's overlap; operators can raise it.
- [Scan cost: each byte is scanned about (C + L + K) / K ≈ 5 times with the defaults,
  which matters for a model guard] → `stream_scan_bytes` trades delay for cost; buffer
  mode scans once.
- [A whole-unit classifier sees a window of about 1 KB, not the whole message] → The
  model guard already classifies long text window by window; the wait-one-scan rule
  cuts false stops from a partial sentence.
- [The client sees part of a reply and then an error] → Inherent once the first byte is
  sent; `voidwall_streams_cut_total` makes it visible; buffer mode avoids it.
- [First-token delay of about 128 tokens] → `stream_holdback_bytes` is tunable, at the
  cost of the leak bound.
- [A server that switches back and forth between the fields of one choice closes a text
  at each switch, so a value split across a close can send its first part] → Known
  servers do not do this; the stop still comes; buffer mode has no such gap.
- [Buffer mode holds up to `max_body_size` per stream] → Same bound as a buffered
  response today.

## Migration Plan

No migration path: Voidwall is not deployed anywhere and is not versioned, so a breaking
change needs none. Every new key has a default, and an `openai-chat` route without
`stream` gets hold-back. One config that loaded before now fails validation: a
`max_body_size` below 512 without `stream_holdback_bytes` and `stream_context_bytes` set
at or below it. Behaviour changes at deploy: `stream: true` requests that
answered 422 under `fail_close` now stream, and `reason="unscannable_stream"` stops
appearing. Rollback is the previous image; no state is kept.
