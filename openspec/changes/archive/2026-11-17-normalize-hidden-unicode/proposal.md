## Why

An LLM reads text that hides behind invisible or decorative Unicode, but the guards read
the characters as they are sent. Today only one case is handled: the regex PII detectors
remove U+200B, U+200C and U+200D and decode percent-encoding and HTML entities
(`crates/voidwall-pii/src/normalize.rs`). The model guards get the raw text, and no guard
handles the other hidden forms.

Checked on `main` with the regex guard (2026-11-16): an IBAN with a soft hyphen, U+061C,
U+2060 or U+2062 between two digits passes; a `US_SSN` with a decoy letter and a
backspace, a NUL, one variation selector, an underline mark on each digit, or full-width
digits passes; an e-mail written full-width, in Unicode tag characters, or in variation
selectors ("emoji smuggling") passes.

Phase 0 of the encoded-content plan measured these forms with a prototype
(`voidwall-internal/research/encoded-content/encoded-content-phase0/README.md`,
2026-11-14):

| Hidden form | PII values found (of 6), today → normalized | Injections flagged today | Benign prompts flagged today |
|---|---|---|---|
| Unicode tags | 0 → 5 | 23% | 31% |
| Emoji smuggling | 0 → 6 | 98% | 96% |
| Zero-width characters | 5 → 6 | 84% | 29% |
| Soft hyphen | 1 → 6 | not in Phase 0 | not in Phase 0 |
| Full-width | 4 → 6 | 100% | 71% |
| Backspace characters | not in Phase 0 | 52% | 10% |
| Diacritics, underline marks | not in Phase 0 | 97–98% | 46–60% |

Two forms carry whole hidden texts, Unicode tags and emoji smuggling, and the injection
model misses most tag attacks. This change finds both forms without decoding them, and
normalizes all forms for the PII guards.

This is Phase 1a of `voidwall-internal/research/encoded-content/encoded-content-detection-plan.md`.
Phase 1b (homoglyphs) and the response direction are later changes. It reuses the offset
map that `decode-json-escapes` added.

## What Changes

- **Scan view for the guards that read it.** Before the guards run, the engine builds a
  scan view of each request-direction unit that a selected guard reads through the view.
  It applies at every request entry point: reverse proxy request, `openai-chat` request,
  `/v1/scan` with `direction=request`, and the request side of the LiteLLM route. In a
  structured unit, each fragment value gets its own view. The forwarded message does not
  change.
- **A new per-guard field, `scan_view`.** `[builtin_guards.pii]` and every
  `[guards.<name>]` section may set it. Defaults: `true` for the `pii` guard and for a
  `token_classifier` model guard, `false` for a `text_classifier` model guard. So by
  default the PII guards read the view, and the prompt-injection classifier reads the raw
  text as before.
- **A new built-in guard, `invisible_text`**, with the new kind `INVISIBLE_TEXT`. It reads
  the raw text of every request unit and reports a unit that holds a Unicode tag
  character outside an emoji flag, or a variation selector that does not directly follow a
  letter, number, punctuation mark or symbol: a run of selectors, or selectors split by
  invisible characters. It decodes nothing. A finding blocks like any detection: 403 on a generic route, 400 with
  `content_filter` on an `openai-chat` route. The shipped image configuration and
  `docker/voidwall.toml` turn it on.
- The view is the result of six ordered steps, each applied to the result of the step
  before, so a character that one step removes cannot split a run for a later step:
  1. Remove characters that carry no content: soft hyphen, combining grapheme joiner
     U+034F, U+061C, zero-width space, LRM,
     RLM, bidi embeddings, overrides and isolates, word joiner, U+2061 to U+2064, U+FEFF.
  2. Apply backspaces (each deletes the character before it) and remove the other C0
     controls except tab, line feed and carriage return.
  3. Decode runs: a run of Unicode tag characters becomes its ASCII text, except an emoji
     flag (one to six tags for letters or digits after U+1F3F4); a run of two or more
     variation selectors that decodes to text becomes that text, after the same steps are
     applied to it, and any other run is removed.
  4. Fold full-width ASCII to ASCII and the ideographic space to a space.
  5. Remove ZWJ and ZWNJ between two printable ASCII characters.
  6. Remove combining marks after a printable ASCII character, and decoration marks
     (overline, underline, strike-through) after any letter or number. A single variation
     selector is a combining mark; a keycap emoji stays.
- A finding's span in the view still names the raw bytes the view characters came from.
  The engine maps it centrally, as it does for JSON escapes.
- No new metric family and no new error code.

What the user agreed (2026-11-16 and 2026-11-17): the seven prototype rules; six fixes
from the review of this change (flag limit: at most six tags for letters or digits,
removed characters inside a run, selector text normalized before the text test, ZWJ
neighbours in the normalized text, marks after ASCII punctuation, a single selector after
ASCII); the two added character groups in step 1; the text test without the script
check; and then this shape: the view for the PII guards by default, a per-guard
`scan_view` field, and an `INVISIBLE_TEXT` guard for tag and selector runs, request only,
on in the image; then, after a second review, the stricter selector rule (any selector
that does not follow a base character) and U+034F in step 1. A stricter flag rule (only the flags of England, Scotland and Wales) was
declined for now.

Limits that stay:

- By default the prompt-injection classifier does not get the view, so zero-width,
  backspace, mark and full-width tricks reach it as raw text, as today. Phase 0 measured
  it flags most of these on its own (52% to 100%), and it also flags benign prompts that
  use them (10% to 71%). An operator can set `scan_view = true` on it.
- Response-direction units are not normalized and `invisible_text` does not read them (a
  later change).
- Homoglyphs are not folded (Phase 1b).
- Reversed-text injections: removing the bidi override drops their detection from 38% to
  3% (benign 23% → 4%) for a guard that reads the view. Reversed text is Tier B, plan
  Phase 4. With the default, the injection classifier reads the raw text and keeps its
  38%.
- JSON keys are not normalized: a key path is keyword context, not a scanned value.
- No guard reads JSON keys or CSV column names, so hidden characters there are neither
  normalized nor reported. Tool parameter names in a Chat Completions `tools` list do
  reach the model. This gap exists before this change.
- `invisible_text` runs only on a route that selects it. A route with its own `guards`
  list, such as the recipe in `docs/recipes/README.md` that selects only
  `prompt_injection`, must name `invisible_text` too, or tag and selector smuggling reaches
  the injection classifier as raw text.
- A hidden character that is percent-encoded or an HTML entity, such as `%C2%AD` in a
  query string, is not normalized: that decoding runs later, inside the regex detectors.
  Phase 2 moves it into the engine.
- A scanned header value with a non-ASCII byte is not built into a unit at all, so it is
  not scanned and not normalized. That is a bug against `guard-configuration`, tracked as
  backlog item 5.1; once it is fixed, this change covers header units like any other.
- A run that is split by a character the view keeps (visible text, a combining mark, a tag
  character between selectors) is decoded piece by piece. Split payloads are Tier C.
- These characters stay: U+180E, U+2028, U+2029, U+007F, the C1 controls and the Hangul
  fillers.
- Decomposed accented text loses its accents in the scan view. The dictionary detector
  matches a decomposed accented name today and can miss it after this change, when the
  name list holds only the accented spelling. Text with precomposed accents is not
  touched.
- Text can hide in flag-shaped runs: each U+1F3F4 followed by up to six tags for letters
  or digits and the cancel tag stays unchanged and is not reported, so a chain of them
  carries short words that no guard reads. Punctuation, spaces and longer runs are
  decoded and reported.

## Capabilities

### New Capabilities

- `hidden-unicode-normalization`: the request-direction scan view, the order of its
  steps, each step, and the span rule for a finding in the view.
- `invisible-text-guard`: the built-in `invisible_text` guard and its `INVISIBLE_TEXT`
  kind.

### Modified Capabilities

- `guard-configuration`: the `scan_view` field and its defaults; `invisible_text` joins
  the built-in guard names and inspects requests only; a model guard scores the view or
  the raw text according to `scan_view`.
- `distribution`: the image's default configuration declares the `invisible_text` guard.

`pii-scanning` keeps its JSON span rule; the new capability names the order (escapes
first, then normalization).

## Impact

- Code: `crates/voidwall/src/structured/mod.rs` (`EscapeMap` becomes a general sparse
  edit map), `crates/voidwall/src/engine/unit.rs` (`UnitContent::PlainText` carries an
  edit map), a new normalizer module and a new `invisible_text` guard under
  `crates/voidwall/src/engine/`, `crates/voidwall/src/engine/mod.rs` (`Engine::guard`
  passes each guard the view or the raw units; `map_spans` maps spans of view guards),
  and `crates/voidwall/src/config.rs` (`scan_view`, the new built-in section). The
  existing guards and `voidwall-pii` do not change.
- Configuration: `docker/voidwall-image.toml` and `docker/voidwall.toml` gain
  `[builtin_guards.invisible_text]`. The recipe in `docs/recipes/README.md` that lists
  `guards` adds `invisible_text`.
- A route that selects `invisible_text` builds the URL path, query string and header
  units of every request, because the guard admits them. They are small.
- `crates/voidwall/benches/`: every payload is ASCII today, so the benchmark gets
  payloads with non-ASCII text.
- `ARCHITECTURE.md`: the new engine step and the new guard.
- Every request path detects more. A request with a tag character outside an emoji flag,
  or with a variation-selector run, is now blocked, benign or not. Phase 0's benign
  corpus has emoji flags and ordinary emoji, which pass; the agreed limit is no new block
  on the benign corpus except ones decided as correct.
- Throughput: within 5% on `crates/voidwall/benches/` (agreed 2026-11-16).
- Side effects in the scan view only: decomposed accented text loses its marks;
  full-width Japanese punctuation becomes ASCII.
- No new dependency: the Unicode general-category tables come from `regex-syntax`,
  already a direct dependency (agreed 2026-11-16, design D9).
