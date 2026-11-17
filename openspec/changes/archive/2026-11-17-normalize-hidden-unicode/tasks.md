## 1. Baseline and failing tests

- [x] 1.1 Add benchmark payloads with non-ASCII text to `crates/voidwall/benches/`
  (precomposed Polish, Cyrillic, CJK and emoji, with no character that a rule changes),
  beside the ASCII ones. Check: `generate_payloads.py` writes them, and a k6 run uses
  them.
- [x] 1.2 Run `crates/voidwall/benches/` on the base commit with the ASCII and the
  non-ASCII payloads, and record the throughput (`docs/dev/load-testing.md`). Check: both
  sets of numbers are written in this change's notes for task 9.2.
- [x] 1.3 Add the scenarios of "Request units have a normalized scan view" as integration
  tests, each with an IBAN placeholder that holds a soft hyphen: plain body, JSON body, CSV
  body, query string, URL path (`reverse_proxy_integration.rs`), `openai-chat` request
  (`openai_chat_proxy_integration.rs`), `/v1/scan` in both directions
  (`http_api_integration.rs`), LiteLLM request side (`litellm_guardrail_integration.rs`).
  Check: each blocking test fails on the base commit because the message passes; the
  response-direction and forwarded-body tests pass there.
- [x] 1.4 Add the blocking scenarios of the step requirements as integration tests:
  U+061C and U+2062 in an IBAN; a letter and a backspace in a `US_SSN`, plain and as `\b`
  in JSON; an email in tags; text dressed as a flag; a flag-shaped run that is too long;
  an email in variation selectors, also with a zero-width space between the selectors and
  with one inside the smuggled text; a full-width email; an underlined `US_SSN`; one
  U+FE0F between two digits of a `US_SSN`. Each test selects only the `pii` guard. Check:
  each fails on the base commit because the message passes.
- [x] 1.5 Add the request scenarios of the `guard-configuration` delta to
  `model_guard_integration.rs`: a text classifier with no `scan_view` scores the raw
  text, a text classifier with `scan_view = true` scores the view, a token classifier
  with no `scan_view` scores the view, the response direction, and the span after removed
  characters. Check: the view tests fail on the base commit because the guard scores the
  raw text; the raw-text and response tests pass there.
- [x] 1.6 Add the scenarios of the `invisible-text-guard` capability as integration tests:
  generic route, `openai-chat` route, `/v1/scan` with its counts, LiteLLM request side, a
  query string, a URL path, a CSV cell, a JSON escape, a response, a route that does not
  select the guard, the detection metric, selectors split by U+200B, U+034F, U+0301 and
  U+2028, flags, presentation selectors, keycaps and ordinary emoji. Check: the blocking
  tests fail on the base commit because the config does not load (`invisible_text` is an
  unknown built-in name).

## 2. Configuration

- [x] 2.1 Add `scan_view` to `[builtin_guards.pii]` and to every `[guards.<name>]`
  section, with the defaults of design D14, and make `[builtin_guards.hidden_context]`
  reject it. Check: unit tests in `config.rs` for each default, for `true` and `false` on
  each section that accepts it, for a value that is not a boolean, and for the key on
  `hidden_context`.
- [x] 2.2 Add `[builtin_guards.invisible_text]` with only `enabled` (D15): present means
  enabled, `enabled = false` builds no guard, the name is reserved, any other key fails
  the schema. Check: unit tests for an empty section, `enabled = false`, a configured
  guard named `invisible_text`, and the keys `surface` and `scan_view`.

## 3. The edit map

- [x] 3.1 Generalize `EscapeMap` into the sparse edit map of design D2, with wide lengths
  and removal edits (`view_len` 0). Keep its `Debug` free of content. Check: the existing
  escape-map tests pass unchanged, and new unit tests cover a removal inside a span, a
  removal exactly at a span start and exactly at a span end, two spans that meet at a
  removal, a replacement with `view_len > 0`, a span start and end inside a replacement,
  and adjacent edits.
- [x] 3.2 Give `UnitContent::PlainText` its edit map (D3), empty for raw text, and keep the
  hand-written `Debug` free of content. Check: `cargo test --workspace` passes with no
  change of behavior, and the `Debug` test still prints sizes only.

## 4. The normalizer

- [x] 4.1 Write the test reference of D6: one function per step of "The rules apply in a
  fixed order", applied in order, with the tables of D9. Check: the scenarios of every
  step requirement that state the scan view pass against the reference.
- [x] 4.2 Add the normalizer module under `crates/voidwall/src/engine/` with the fast path
  (D7) and the invalid-UTF-8 rule (D8). Check: unit tests show that ASCII text and
  non-ASCII text where no rule fires return the input bytes with an empty map and no new
  buffer, and the scenarios "Ordinary non-ASCII text is unchanged" and "An invalid byte
  next to a hidden character" pass.
- [x] 4.3 Implement steps 1 and 2, U+034F included. Check: the scan-view scenarios of
  "Characters that carry no content are removed" and "Backspace and other control
  characters are applied" pass as unit tests.
- [x] 4.4 Implement step 3: tag runs with the flag rule, and variation-selector runs with
  the text test and the one-level normalization of D13. The flag rule is one shared
  function. Check: the scan-view scenarios of "Unicode tag runs become ASCII text" and
  "Variation-selector runs that hold text are decoded" pass as unit tests.
- [x] 4.5 Implement steps 4, 5 and 6. Check: the scan-view scenarios of "Full-width ASCII
  is folded", "ZWJ and ZWNJ are removed only between ASCII characters" and "Combining
  marks used as decoration are removed" pass as unit tests.
- [x] 4.6 Compare the normalizer with the reference of 4.1. Check: a table test over
  every scenario input of the spec and a generated-input test over the characters that
  the rules name give the same view from both, the scenarios of "The rules apply in a
  fixed order" pass, and a test checks the length table of D5 for each rule.
- [x] 4.7 Port the Phase 0 Tier A1 cases (`encoded-content-phase0/corpus`, without
  homoglyphs) into a table test that compares the normalizer's view with the prototype's
  view. Check: every case gives the same view, or its difference is one of the known
  differences that the design's Risks section lists.

## 5. The invisible text guard

- [x] 5.1 Add the `invisible_text` guard under `crates/voidwall/src/engine/` (D15): fixed
  interest (request direction, every unit kind), one linear scan per unit, one span-less
  `INVISIBLE_TEXT` finding per unit, using the shared flag rule of 4.4 and the
  base-character test of D15. Check: unit tests for every scenario of "The guard reports
  tag characters outside an emoji flag", "The guard reports a variation selector that
  follows no base character" and "The guard reports one INVISIBLE_TEXT finding per unit",
  and a test that its interest refuses
  response units.
- [x] 5.2 Build the guard from `[builtin_guards.invisible_text]` and add it to the
  enabled guard names. Check: the tests of 1.6 pass, and a unit test shows that no log
  line and no error body of a blocked request holds a tag character, a selector, or the
  text they stand for.

## 6. The engine step and span mapping

- [x] 6.1 Build the view unit set in `Engine::guard` for `Direction::Request` only, and
  only for the units that a planned guard reading the view selected (D1, D14), plain
  units and each fragment value (D4). Pass each guard the set it reads. Check: unit tests
  show that a response-direction call builds no view, that a request with no guard
  reading the view builds no view, that a request-direction call with units that no rule
  changes builds no new unit, and that a raw-text guard and a view guard on one request
  each get their own set.
- [x] 6.2 Make `map_spans` map each finding through the unit set its guard read (D16):
  through the normalize map and the escape map for a view guard, through the escape map
  only for a raw-text guard. Check: the scenarios of "A span in a normalized unit names
  the raw bytes it came from" pass through the engine, with the edge case and the two
  findings in one run, and the existing span tests still pass.
- [x] 6.3 Check "Normalization alone never blocks". Check: its scenario passes as an
  integration test.
- [x] 6.4 Run the tests of tasks 1.3, 1.4 and 1.5. Check: all pass.

## 7. Shipped configuration

- [x] 7.1 Add `[builtin_guards.invisible_text]` to `docker/voidwall.toml` and
  `docker/voidwall-image.toml`, with a comment on what it reports and that it decodes
  nothing. Check: `voidwall --validate` passes on both files, and the existing test that
  compares the two files' guards passes.
- [x] 7.2 Extend `docker/smoke-test.sh` (the image start test of the `distribution`
  delta, run by the release workflow): a `/v1/scan` request holding a tag run answers
  with an `INVISIBLE_TEXT` finding, and update its header comment. Check: the script
  passes on a local image build.

## 8. Workspace checks

- [x] 8.1 Run `cargo test --workspace`. Check: all tests pass.
- [x] 8.2 Run `cargo clippy --workspace --all-targets`. Check: no warnings.
- [x] 8.3 Run `cargo deny check licenses`. Check: it passes, and `Cargo.toml` has no new
  dependency.

## 9. Measurement

- [x] 9.1 Rerun the Phase 0 harness (`encoded-content-phase0/README.md`, "Reproduce")
  against the built binary with the image configuration, without the prototype. Check:
  each PII count of the proposal's table is at or above the prototype's normalized
  value; injections hidden in tags or variation selectors are blocked 100% (as
  `INVISIBLE_TEXT` or another kind); every other injection row is at or above today's
  rate; the benign corpus shows no new block except ones the user decides are correct.
  Benign prompts with tag or selector obfuscation are expected to block, and the report
  lists them apart.
- [x] 9.2 Rerun `crates/voidwall/benches/` with the same setup as task 1.2. Check:
  throughput is within 5% of the baseline for the ASCII payloads and for the non-ASCII
  payloads. If it is not, apply the fallback of D10 and measure again.

## 10. Docs and backlog

- [x] 10.1 Add backlog items to `docs/dev/backlog.md`: normalization of the response
  direction and the `invisible_text` guard for responses (with the agreed stream rule for
  a run open at the window end); Phase 1b homoglyphs; and a hidden character that is
  percent-encoded or an HTML entity, which Phase 2 handles by moving that decoding into
  the engine (design D11). The header bug is already item 5.1. Check: the three items
  exist and name this change.
- [x] 10.2 Update `ARCHITECTURE.md`: the request-direction scan view, which guards read
  it (`scan_view`), the `invisible_text` guard, and the regex detectors' own decoding step
  after the view. Check: the text agrees with the specs and with design D1, D11, D14 and
  D15, and the "Detection Engine" section of `CLAUDE.md` is still true or is corrected.
- [x] 10.3 Run the `docs-sync` workflow. Check: the user docs describe the scan view and
  its steps, the `scan_view` field and its defaults, the `invisible_text` guard and its
  kind, the limits and side effects, and that the forwarded message does not change; the
  recipe in `docs/recipes/README.md` that lists `guards` names `invisible_text`, and the
  docs say that a route with its own `guards` list must name it.
- [x] 10.4 Review the diff against the spec deltas with the `code-review` skill. Check:
  every finding is fixed or answered.
