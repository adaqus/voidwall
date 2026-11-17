## Context

See `proposal.md` for the motivation. The user agreed every decision below unless it is
marked proposed. D5 is a property of the rules, and D11 records what stays unchanged.

Current state after `decode-json-escapes`:

- A handler builds `Units` and calls `Engine::guard(units, selection, direction, ...)`.
  The direction reaches the engine, so one step there can serve every request entry point.
- `UnitContent::PlainText(Bytes)` holds a body, a path, a query string or a header value.
  A body can hold invalid UTF-8; the guards read it with `from_utf8_lossy`.
- A path and a query string are the raw text of the request line. The HTTP layer accepts
  raw non-ASCII bytes there (checked on `main`, 2026-11-16), and nothing percent-decodes
  them before the engine.
- A header value becomes a unit only through `HeaderValue::to_str`, which accepts
  printable ASCII and tab only; any other header value is dropped. That is a bug against
  `guard-configuration` (backlog item 5.1). The normalizer needs nothing for headers: once
  the bug is fixed, a header unit is normalized like any other plain-text unit.
- `UnitContent::Structured` holds `OwnedContextFragment`s. Each fragment has a decoded
  `value`, a document-absolute `offset`, and an `EscapeMap`: one entry per escape
  sequence, with `u8` lengths.
- After the guards return, `map_spans` maps every span in a structured unit through its
  fragment's escape map, then the findings are sorted. Plain-text spans are not touched.
- `voidwall-pii` already has a normalizer of its own, `decode_for_detection`
  (`crates/voidwall-pii/src/normalize.rs`). The Vectorscan, keyword-context and custom
  detectors call it on their input: it removes U+200B, U+200C and U+200D, and decodes
  percent-encoding and HTML entities, with its own offset map back to its input. The
  model guards do not have it.
- The rules started from the Phase 0 prototype,
  `voidwall-internal/research/encoded-content/encoded-content-phase0/harness/proto_decode.py`,
  function `phase1` (without the homoglyph part). The review of this change found ways
  around the prototype's rules, so the spec now differs from the prototype in the points
  that the Risks section lists.

## Goals / Non-Goals

**Goals:**

- One normalizer that serves every request entry point, with no change to the handlers
  or the existing guards.
- Each guard reads the scan view or the raw text, by its `scan_view` setting.
- Tag and selector smuggling is found without decoding it, for the guards that read the
  raw text.
- ASCII traffic costs one byte scan and no copy. Other text costs one pass and no copy
  when no rule applies.
- Spans leave the engine in raw-message coordinates, as today.

**Non-Goals:**

- Response direction, streams, and the hold-back. The agreed stream rule (a tag or
  variation-selector run still open at the window end waits like the tail) belongs to the
  later response change.
- Homoglyph folding (Phase 1b). NFKC.
- Reporting other invisible characters (zero-width, bidi, soft hyphen, backspace) as
  `INVISIBLE_TEXT`: benign Persian, emoji and German text use them.
- Removing or changing `decode_for_detection` in `voidwall-pii` (D11).
- Percent-decoding or entity-decoding before the normalizer (Phase 2).

## Decisions

### D1. The engine builds the scan view for the request direction (agreed 2026-11-16, changed 2026-11-17)

`Engine::guard` builds the guard plans first. When `direction` is `Request` and at least
one planned guard reads the scan view (D14), it then normalizes the units that those
guards selected. It keeps the raw unit set as it is, and builds a view unit set beside
it only when at least one unit changed. Each guard gets the set it reads: a guard that
reads the view gets the view set, every other guard the raw set. A unit that no rule
changes is shared by both sets. `map_spans` maps each finding through the set its guard
read (D16).

*Alternative:* normalize in each handler while it builds units. Rejected: four entry
points, and a new one could forget it. The span mapping is already central (agreed for
`decode-json-escapes`).

### D2. One sparse edit map for escapes and normalization (agreed 2026-11-16, option A)

`EscapeMap` becomes a general edit map: a list of edits `(view, view_len, raw, raw_len)`
in order, identity between edits. `view_len` 0 means removed characters. Lengths become
wide enough for a long tag run (`u8` is too small). An empty map allocates nothing.

How a view position maps to a raw position:

- Inside an edit with `view_len > 0`: to the start of the raw range for a span start, and
  to its end for a span end, as `EscapeMap::raw` does today.
- At a removal edit (`view_len` 0) that sits exactly at the position: a span start maps
  to the end of the removed range, and a span end maps to its start. So removed
  characters at the edges of a finding are outside its span, and a finding that ends
  where the next one starts still does not overlap it. This case is new: an escape never
  has `view_len` 0.

*Rejected by the user:* dense `UnitText`-style pieces (copy, removed, atomic).

### D3. A plain-text unit carries its edit map (agreed 2026-11-16)

`UnitContent::PlainText` holds the scan-view bytes and an edit map; the map is empty for
raw text. Guards keep reading the bytes as today. `map_spans` maps a plain-text span
through the map.

*Rejected by the user:* a normalized plain unit as one `Structured` fragment, because the
regex guard would then scan it with keyword context and its output could change.

### D4. A fragment chains two maps (agreed 2026-11-16)

The normalizer runs on the decoded `value` of each fragment and replaces it with the scan
view. The fragment keeps its escape map and gains a normalize map. `map_spans` maps a span
through the normalize map, then through the escape map, then adds `offset`. The key path
(`context`) is not normalized (agreed 2026-11-16).

### D5. The view is never longer than its input, and the map keeps order

Every rule shrinks or keeps the length in bytes:

| Rule | Input bytes | View bytes |
|---|---|---|
| removed character | 1–4 | 0 |
| backspace | 1 + the deleted character | 0 |
| full-width or U+3000 | 3 | 1 |
| tag run of `k` tags | `4k` | at most `k + 2` |
| variation-selector run of `k ≥ 2` | at least `3k` | at most `k + 2` |

So `offset + view position` stays inside the fragment's raw range, spans of two
fragments still never overlap, and the binary search of `map_spans` still finds the right
fragment.

The map never reverses order: a finding that starts before another in the view does not
start after it in the raw text. Overlap resolution runs inside a guard, on view spans, so
its result does not depend on the map. One thing differs from `decode-json-escapes` D3:
two findings inside one decoded run map to the same raw range, so raw spans of a resolved
set can be equal. Nothing after the map resolves overlaps or removes duplicates, and both
findings count (spec, "Two findings inside one decoded run").

### D6. Ordered steps define the result; one pass may compute it (agreed 2026-11-16)

The spec defines the view as six steps, each applied to the result of the one before
(spec, "The rules apply in a fixed order"). This replaces the first form of this
decision, "one pass in the prototype's order", which let a removed character split a run
and let a ZWJ look at raw neighbours.

The implementation may be one left-to-right pass, when it gives the same result as the
six steps. It keeps a pending run: inside a tag run or a selector run, a step-1
character, a removed control, a ZWJ or a ZWNJ is skipped, and a backspace drops the last
pending character. A ZWJ or ZWNJ sequence waits until the next kept character is known.

The tests hold a plain reference: one function per step, applied in order. A table test
and a generated-input test compare the pass with the reference.

*Alternative:* six real passes. Rejected for the cost; kept as the test reference.

### D7. Fast path: no edit, no copy (agreed 2026-11-16)

The normalizer first scans the bytes for a byte that can start a rule: a C0 control other
than tab, line feed and carriage return, or a non-ASCII lead byte. ASCII text with no such
byte returns at once. Text with non-ASCII bytes takes the full pass; a unit in which no
rule fires keeps its original bytes, so it allocates nothing. The benchmark gets
non-ASCII payloads, because the ASCII ones measure only the byte scan.

### D8. Invalid UTF-8 is copied unchanged (agreed 2026-11-16)

A plain-text body can hold invalid UTF-8. The normalizer works on its valid UTF-8 parts
and copies invalid bytes to the view unchanged, so the guards' lossy decoding sees the
same invalid bytes as today. For the rules, one invalid byte is one character: a
backspace deletes it, it ends a run, and it is not an ASCII neighbour.

### D9. The Unicode tables come from `regex-syntax` (agreed 2026-11-16)

`regex-syntax` is already a direct dependency of `voidwall` and ships the current Unicode
general-category tables. The normalizer builds these classes once and looks a character
up with a binary search over the ranges: `Mn` (steps 5 and 6), `L` and `N` (step 6),
`Cc` without tab, line feed and carriage return, `Cf`, `Co`, `Cn`, `Zl`, `Zp` (the
text test of step 3), and `L`, `N`, `P`, `S`
(the base-character test of `invisible_text`, D15). No new dependency.

The text test has no script check (agreed 2026-11-16): no current dependency gives the
script of a character, and benign text has almost no selector runs.

*Alternative:* `unicode_categories`, already in `Cargo.lock` as a transitive dependency.
Rejected: its tables are from an old Unicode version and the crate is not maintained.

### D10. The normalizer runs on the async runtime (agreed 2026-11-16)

Unit building, including the JSON parse of up to 1 MB, already runs on the runtime, and the
normalizer is one linear pass of the same class. It is not a guard, so the threading rule
for guards does not apply to it directly. The bench decides: if the 5% limit is not met,
move units above a size limit to `spawn_blocking`.

### D11. The regex detectors keep their own decoding step

`decode_for_detection` stays as it is. The regex guard gets the scan view and then applies
that step to it, with its own offset map; the engine maps the result to raw bytes after
that. Two effects:

- For the regex detectors, a ZWJ or ZWNJ that step 5 keeps (Persian, emoji) is removed
  anyway, as before this change. Step 5's "keep" matters for the model guards.
- The order is normalize, then percent- and entity-decode. A hidden character that
  arrives as `%C2%AD` or as an entity is decoded after the normalizer ran, so it stays.
  Phase 2 of the plan moves that decoding in front.

*Alternative:* delete the zero-width part of `decode_for_detection`. Rejected: it touches a
second crate for no change in behavior, and `voidwall-eval` uses `voidwall-pii` without
the engine.

### D12. A flag is at most six tags for letters or digits (agreed 2026-11-16)

A tag run stays as it is when it follows U+1F3F4 directly, has one to six tags that each
stand for an ASCII letter or digit, and ends with the cancel tag U+E007F. That covers
every subdivision flag Unicode allows (a two-letter region code and up to four letters
or digits), so no real flag changes in the scan view.

*Declined for now (2026-11-17):* keep only the flags of England, Scotland and Wales, the
only ones Unicode recommends for general use. It would close the gap below, but another
subdivision flag would turn into letters in the scan view.

Known gap: a chain of flag-shaped runs can carry short words of letters and digits, six
at a time, that no guard reads. Punctuation and spaces in tags, and longer runs, are
decoded, so an e-mail address or a sentence with spaces cannot hide this way.

### D13. Selector text is normalized before the text test (agreed 2026-11-16)

Tab, line feed and carriage return count as text in the test (agreed 2026-11-17): a
smuggled instruction of several lines is decoded, as the Phase 0 prototype decoded it.
Two Phase 0 cases differed from the prototype until then.

The bytes of a selector run are decoded as UTF-8, the six steps run on the decoded text
once, and then the text test decides. A selector run inside the decoded text is not
decoded again; it stays, or step 6 removes it. One level is enough for the measured
attack, and it bounds the work to the length of the run.

### D14. `scan_view` is a field of each guard section (agreed 2026-11-17)

`[builtin_guards.pii]` and every `[guards.<name>]` section accept an optional boolean
`scan_view`. Its default depends on the guard: `true` for `pii`, `true` for
`adapter = "token_classifier"`, `false` for `adapter = "text_classifier"`. The engine
asks each guard whether it reads the view; the guard answers from its configuration.
`[builtin_guards.hidden_context]` and `[builtin_guards.invisible_text]` reject the key:
`hidden_context` reads responses only, where no view exists, and `invisible_text` must
see the raw characters.

The defaults keep a text classifier's input as it was before this change, and give the
PII guards the view, where Phase 0 measured the gain. An operator can change either.

*Alternative:* decide by guard type in code, with no field. Rejected by the user
(2026-11-17) in favour of a setting per guard.

### D15. `invisible_text` is a built-in guard that scans inline (agreed 2026-11-17)

The guard is a fixed-interest built-in guard, like `hidden_context`: request direction,
every unit kind (body, path, query string, header values), no `surface` (proposed: every
unit kind). Its `detect` is one linear scan over the bytes of each unit, so it runs
inline on the async runtime, as `CLAUDE.md` allows for a single linear-time literal scan.
The tag rule shares the emoji flag function with the normalizer, so the two cannot drift
apart. The selector rule (agreed 2026-11-17, after the second review) reports a selector
whose previous character is not a base character, that is, not of general category `L`,
`N`, `P` or `S`. It does not use the normalizer's run definition: a fixed list of
separators let an attacker split the selectors with any character outside the list, such
as U+034F, U+0301 or U+2028. A selector after a base character is a normal variation
sequence (emoji presentation, keycap, CJK ideographic variant) and passes.

Because the guard admits every request unit kind, a route that selects it builds the URL
path, query string and header units of every request (the `guard-configuration` surface
requirement). These units are small; the scan is one pass over each.

It reports one span-less `INVISIBLE_TEXT` finding per unit, as `hidden_context` reports
one `HIDDEN_CONTEXT` finding per unit (proposed: one per unit, no span). The guard name
`invisible_text` is proposed; the kind name `INVISIBLE_TEXT` comes from the plan.

The guard needs no class: its findings count in the guard-labelled detection metrics,
not in the PII families. No metric family changes.

*Alternatives:* report every invisible character, as LLM Guard's `InvisibleText` does
(rejected by the user: benign Persian, emoji and German text would block); report tag
runs only (rejected by the user: emoji smuggling would still reach the injection model).

### D16. Spans of a raw-text guard keep today's mapping

A guard that reads the raw set reports `offset` plus a position in the escape-decoded
value, as today, and `map_spans` maps it through the escape map only. A guard that reads
the view set maps through the normalize map and then the escape map (D4). `map_spans`
takes the unit set of each finding's guard. `invisible_text` findings have no span, so
the map does not touch them.

## Risks / Trade-offs

- [Benign text that uses these characters now blocks] → The agreed limit: no new block on
  the Phase 0 benign corpus except ones decided as correct. Phase 0 measured benign
  45% → 0% with the same obfuscation.
- [Reversed-text injections are detected less (38% → 3%)] → Accepted (2026-11-16).
  Reversed text is Tier B, plan Phase 4.
- [A decomposed accented name loses its accent, and the dictionary detector can miss it]
  → Accepted (2026-11-16). The spec has a scenario for the view; the proposal lists the
  limit.
- [A changed unit exists twice in memory during the scan: raw and view] → The view is never
  longer than the raw text (D5). Normal traffic makes no copy (D7).
- [The spec and the prototype differ] → Known differences: characters removed inside a
  run, the flag limit of six tags, two backspaces in a row (the prototype deletes one character),
  ZWJ neighbours, marks after ASCII punctuation, a single selector after ASCII, selector
  text normalized before the text test, no script check, U+061C and U+2061 to U+2064.
  The table test of the Phase 0 cases lists every case whose view differs, and each
  difference must be one of these.
- [The one-pass code and the six steps disagree] → The reference of D6 and its
  generated-input test.
- [Benign tag or selector runs now block] → Unicode keeps tag characters for emoji tag
  sequences, and deprecated their older use as language tags; a standard variation
  sequence has one selector directly after its base, so a selector after another
  selector, a mark or an invisible character does not occur in emoji. Phase 0's
  benign corpus has emoji flags, ZWJ emoji and presentation selectors, which pass; it is
  rerun in task 6.1.
- [An operator sets `scan_view = true` on a text classifier] → Allowed by design (D14).
  The docs state what the setting changes.
- [Two unit sets in memory during a request scan] → Only units that a rule changes are
  copied (D1, D7).

## Migration Plan

No configuration or data migration. Rollback is a revert of the change. The forwarded
message never changes, so an upstream sees no difference.
