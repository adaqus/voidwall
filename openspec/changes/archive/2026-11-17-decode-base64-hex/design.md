## Context

See `proposal.md` for the motivation. The user agreed every decision below unless it is
marked **proposed**.

Current state after `normalize-hidden-unicode` (Phase 1a, commit 439ff86):

- `Engine::guard` builds the guard plans, then `view_units` builds a scan-view unit set
  beside the raw set when a planned guard has `reads_scan_view() == true` and a rule
  changes one of its units. Every other guard reads the raw set.
- `UnitContent::PlainText { bytes, edits }` carries an `EditMap`: a sparse list of edits
  `(view, view_len, raw, raw_len)`, identity between edits. Inside an edit with
  `view_len > 0`, a span start maps to the raw start and a span end to the raw end.
- A structured fragment carries `escapes` (JSON escapes) and `normalized` (the scan-view
  edits). `map_spans` maps a span through `normalized`, then `escapes`, then adds
  `offset`.
- `reads_scan_view()` is `false` for `text_classifier` guards by default, for
  `hidden_context` (responses only) and for `invisible_text`.
- `regex-syntax` 0.8.11 is a direct dependency with its default features, which include
  `unicode-script`. So `\p{Latin}` is available. Phase 1a's D9 said that no current
  dependency gives the script of a character; that statement was wrong.
- The JWT validator in `voidwall-pii` (`jwt_check`) needs three dot-separated base64url
  segments, a header of 19+ characters and a payload of 10+, both starting with `ey`.
- Metrics are written by the handlers (`reverse_proxy.rs`, `http_api.rs`), never by the
  engine or a guard. `ScanResult` holds findings and the first error.

### Phase 2 split (agreed 2026-11-17)

Phase 2 as one change was estimated at about 3,900 lines of Rust (source and tests). It
is split into five parts. This change is 2b, and it comes first.

| Part | Scope | Estimate |
|---|---|---|
| 2a | `%xx` and HTML-entity decoding moved into the engine view (backlog 1.14) | ~650 |
| **2b** | base64, base64url, hex, one layer, request bodies (this change) | ~900 |
| 2c | Nested encodings, depth limit, byte budget, lenient decoding of glued runs, adjacent short runs | ~450 |
| 2d | Views and decoding for non-stream responses (backlog 1.12) | ~550 |
| 2e | Runs that cross stream scan windows | ~700 |

## Goals / Non-Goals

**Goals:**

- Every guard that reads a request body gets kept runs decoded, through the view it
  reads.
- Text with no candidate run costs one byte scan and no copy.
- Spans leave the engine in raw-message coordinates; `map_spans` does not change.

**Non-Goals:**

- Parts 2a, 2c, 2d and 2e.
- Changes to `voidwall-pii` (`decode_for_detection` stays; 2a moves it).
- A new finding kind for encoded content. Decoding never blocks on its own.

## Decisions

### D1. The `scan_view` bool now selects scan view or decoded view (proposed)

`Guard::reads_scan_view()` stays a `bool`. In the request direction, `true` gives the
scan view and `false` gives the decoded view. In the response direction both give the
raw text, as today. `invisible_text` and `hidden_context` already return `false`, so
`invisible_text` reads the decoded view (agreed) with no change to the guard, and
`hidden_context` is unchanged because it sees responses only.

After this change no request guard reads the plain raw set, so a third value has no user.

*Alternative:* an enum `TextSource { Raw, Decoded, ScanView }`. Rejected for now: the
`Raw` value would have no request-side user. 2d decides again when responses get views.

### D2. The engine builds up to two extra unit sets (agreed: second view)

`view_units` becomes two builders:

- **Decoded set**, for guards with `false`: each body unit that such a guard selected,
  with its kept runs decoded. Not built when no run is kept.
- **Scan set**, for guards with `true`: Phase 1a normalization of each selected unit,
  then, for body units, run decoding on the normalized text (D5).

A unit that nothing changes is shared, as in Phase 1a. Each guard gets the set it reads,
and `map_spans` maps each finding through that set, as today.

### D3. Run search: one pass with a byte table (proposed)

A 256-entry table marks the alphabet `A–Z a–z 0–9 + / - _`. One pass finds the maximal
runs. One or two `=` after a run join it only when they make its length a multiple of 4
and the next byte is neither in the table nor `=` (review fix, 2026-11-17: a form body
`field=<base64>` and two padded runs back to back were undefined before). For each run,
the pass records which alphabets it fits: hex (only hex digits, even length, 22+), base64
(no `-` or `_`), base64url (no `+` or `/`). A run shorter than 15 (without `=`) is
skipped at once. A run of decimal digits only fits hex alone (D4). The search runs on
bytes, so invalid UTF-8 ends a run like any other byte outside the table.

The JWT rule (agreed) is checked in the same pass: when a run that starts with `ey` is
followed by `.`, a second run that starts with `ey`, `.` and a non-empty third run, the
three runs are marked as not decoded. This is wider than `jwt_check` (no length
minimums), so every token that `JWT` reports stays undecoded. A token with an empty third
segment is not marked (proposed): `jwt_check` does not report it either, so decoding its
claims loses no `JWT` finding and lets the guards read them.

### D4. Decoding is strict, hex first (proposed)

- Hex is tried first when the run fits it (OpenAI Guardrails and the Phase 0 prototype
  also try hex first). If its result is kept, base64 is not tried.
- A run of decimal digits only is decoded only as hex, and its result is used only when
  it holds digits, the space and `+ ( ) . / -` (agreed 2026-11-17, the prototype's rule).
  The digits `0`–`9` are the bytes 0x30–0x39, so a number written in hex is all digits;
  without this rule a PESEL or a phone number in hex is never decoded. The rule also
  stops a random digit string from turning into letters (`4242…` → `BBBB…`); a random
  22-digit number decodes to printable ASCII 0.37% of the time (measured).
- base64 and base64url decode with or without padding. A run whose length without `=` is
  1 mod 4 cannot decode. Non-zero bits in the last character are accepted (lenient);
  everything else is strict.
- There is no start-offset search and no trimming of a glued prefix: both stay in 2c
  (agreed 2026-11-17). The plan's noise check and the prototype try start offsets 0–3.
  Without them, a run joined to a URL path by `/` (`/p/aWdub3Jl…`) is not decoded.

### D5. One keep test on the normalized decoded text (agreed)

The keep test runs once for each decoded run:

1. The decoded bytes must be valid UTF-8.
2. The decoded text must hold no C0 control other than tab, line feed and carriage
   return, and no U+007F. This test runs **before** normalization (review fix,
   2026-11-17): step 2 of the normalization removes C0 controls, so random bytes below
   0x80 would otherwise pass as ASCII.
3. The text is normalized with Phase 1a's `normalize_str`.
4. The normalized text must have more than 3 characters, and 95% or more of them must be
   ASCII, `\p{Latin}` or `\p{Common}` (one `Class` built from `regex-syntax`, as in
   Phase 1a). `Common` (agreed 2026-11-17) lets benign text with `’`, `–`, `€` or an
   emoji pass.

Measured on 400,000 random alphanumeric runs (2026-11-17, Python model of the rules):

| Run length | Normalize before control test, Latin only | Phase 0 prototype | This rule |
|---|---|---|---|
| 15 | 387 kept | 62 kept | 25 kept |
| 16 | 199 | 31 | 13 |
| 20 | 26 | 3 | 0 |

The decoded view gets the decoded text before step 3; the scan view gets the normalized
text from step 3. Because the decision depends only on the encoded characters, a run
that is in both views is kept in both or in neither.

This rule is the plan's noise-check rule plus the control test and `Common`. It is not
the prototype's `_good_text`, which keeps any one script (Cyrillic too) and which
produced the Phase 0 Tier A numbers together with start offsets, glued-prefix trims,
short-run chains, a depth of 3 and spaces around decoded text. Task 6.2 therefore
compares 2b with a prototype run limited to 2b's rules.

Order in the scan view (agreed): normalize the raw text, find runs in the result, decode
and keep-test each run, insert its normalized text. The Phase 1a pass is not run again on
the whole result. Because runs are found after normalization, base64 written in tag or
full-width characters is decoded in the scan view only. The spec states this in "Only one
layer is decoded", with the regex detectors' own percent and entity step.

A kept run replaces its encoded text with no space around it; the prototype adds a space
on each side. A run ends at a byte outside the alphabet, so decoded text touches only
punctuation or space, and the 1a requirement that the view is never longer stays simple.

### D6. One composed edit map per view (proposed)

A kept run is one edit `(view, decoded_len, raw, run_len)` with `decoded_len > 0`. The
existing edit semantics already map a span inside it to the whole run, so no new edit
kind is needed.

- **Decoded view:** the decode edits are the view's map, directly. For a fragment they go
  into the field that holds the view map (today `normalized`, renamed to `view` because
  it no longer holds normalization only).
- **Scan view:** the decode edits are in normalized-text coordinates. They are composed
  with the normalize edits into one `EditMap` (a new `EditMap::compose`, one linear merge
  of two sorted edit lists). A removed character inside a run falls inside the composed
  edit, so the span covers it (spec scenario "A finding in a base64 run with a hidden
  character").

`map_spans` stays as it is: view map, then escapes, then `offset`.

*Alternative:* a third map on each fragment, chained in `map_spans`. Rejected: it adds a
branch to a hot path that one merge at build time avoids.

### D7. The view is never longer than its input

Base64 decodes 4 characters to at most 3 bytes, hex 2 to 1, and normalization never
grows text (Phase 1a D5). So Phase 1a's order and binary-search arguments still hold. No
decoded-byte budget and no candidate cap are needed in 2b (agreed); work is one pass plus
at most two decodes for each run.

### D8. Counting decoded runs (agreed metric, proposed mechanism)

`ScanResult` gains a small count of kept runs by encoding. The engine fills it while it
builds the sets. When a run is kept in both sets, it counts once: the decoded set's
count is used, and the scan set adds only runs it kept that the decoded set did not (a
run that only the scan view finds, such as one split by a zero-width character). The key
is the unit, the fragment offset and the raw start of the run. The handlers then add the
counts to `voidwall_decoded_runs_total` with their `mode`, `route` and `direction`, as
they do for the other families. The engine still writes no metric.

### D9. Body units only (agreed)

Decoding runs only for units of `UnitKind::Body`. Path, query and header units are
normalized for the scan view as in Phase 1a, and not decoded.

### D10. The decoder runs on the async runtime

Same reasoning as Phase 1a D10: unit building already runs there, and the decoder is a
linear pass. The bench decides (5% limit, agreed). If the limit is not met, move large
bodies to `spawn_blocking`.

## Risks / Trade-offs

- [A benign request whose base64 or hex decodes to text that a guard reports now blocks]
  → Expected: this is the purpose of the change. The Phase 0 benign corpus is rerun; a
  new block must be decided as correct.
- [A long identifier (15+ alphabet characters) is decoded by chance and hides a value
  from the regex detectors] → The keep test drops random bytes. Phase 0 found 15 kept runs
  in 69,360 candidates of 55 MB of benign text, all real base64. Digit-only runs, which
  carry most numeric PII, are never decoded.
- [A non-Latin payload is not decoded] → Accepted limit of the keep rule (Cyrillic, CJK,
  Arabic, Hangul).
- [A payload that holds a backspace or another control character is not decoded, so the
  1a backspace trick inside base64 passes] → Accepted: the control test is what keeps
  random bytes out (D5 table).
- [`Common` also holds box-drawing and mathematical symbols, so more random bytes could
  pass] → Measured with the control test in place: fewer random runs are kept than in
  the prototype (D5 table).
- [A zero-width character inside a run hides it from the decoded view] → Accepted. The
  scan view still decodes it, and the `pii` guards read the scan view.
- [A run glued to a word, a run in a URL path joined by `/`, nested encodings] → Part 2c.
- [Line-broken base64 (MIME)] → Each line is its own run. MIME lines are a multiple of 4
  characters, so each line decodes alone. A UTF-8 character cut at a line end makes that
  line fail the UTF-8 test.
- [The run search adds cost on ASCII text with long words] → Measured with the bench and
  new payloads with base64 and hex runs (task 6).
- [`scan_view = false` changes meaning (raw → decoded view)] → Breaking in the
  proposal. The docs state it.

## Migration Plan

No configuration or data migration. Rollback is a revert of the change. The forwarded
message never changes. The dashboard gets a new panel; old panels are not touched.
