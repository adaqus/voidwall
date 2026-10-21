## Context

See `proposal.md` for the motivation. The measurements behind every number here are in
`voidwall-internal/research/pii-model/README.md`, which holds:
- the latency, Gretel and Dolly results;
- the INT8 loader spike and its patch;
- `scripts/vw.py`, the Python port of the decoder that this change turns into Rust and
  into the parity reference.

Today:
- `voidwall-ml` has one built adapter, `text_classifier`. Its contract is a 2-D output
  `[1, 2]` (`checks.rs` `check_output`, `run.rs` `Worker::infer`).
- `Adapter` has `OUTPUT_WIDTH` and `window_score(&[f32]) -> f32`, and `Worker::score`
  returns one `f32` per unit.
- `ModelGuard` (`crates/voidwall/src/engine/model.rs`) reports whole-unit findings. It
  scores plain text decoded lossily, and JSON values joined with `\n`, with no map back to
  bytes.
- The regex guard's validators are `pub(crate)` per-pattern function pointers in
  `voidwall-pii`. `voidwall_pii_*` counts the `pii` guard only.

## Goals / Non-Goals

**Goals:**
- A `token_classifier` adapter that a new Hugging Face token classifier can use with no
  code change, when it meets the contract.
- Findings with exact byte spans in the unit, so findings from two guards are comparable.
- Each stage is a reviewable diff of about 1,300 lines or less, and lands as one commit
  with its tests.

**Non-Goals:**
- Making the decoder configurable.
- Validating spans in an engine stage above the guards.
- Batching windows, or GPU execution.
- Changing the regex guard's own validation.

## Decisions

### D1. One fixed decoder, owned by the adapter

The `token_classifier` adapter owns one word-level decoder, ported from bards.ai's
`pii_detector.py` steps 1–5. Configuration selects the adapter and sets no decoder option.
This keeps ARCHITECTURE §4.8: an adapter owns its output interpretation, and configuration
overrides none of it.

- *Alternative: several named adapters, one per decoding style.* Deferred. This is how a
  model that needs other decoding will be added, without breaking a config.
- *Alternative: decoder options in config.* Rejected. Operators could mis-tune it, every
  option needs validation, and §4.8 would have to change.
- *Steps 6 and 7 (format checks, email regex) are not ported.* `validate_as` and the regex
  guard cover them.

### D2. Two worker types, chosen at load

`load()` returns either classifier workers, which keep `score(text) -> f32`, or token
workers, whose run returns spans: type index, byte range, confidence. Calling the wrong
run method on a worker cannot compile, so the wrong pairing of a guard and a worker
cannot happen.

`Adapter` stays the classifier trait. The token side gets its own type, which holds the
`id2label` pooling matrix, built at load from `config.json`. Windowing, cancellation,
special tokens, and the input checks stay shared.

- *Alternative: one `Worker` with a runtime branch on the adapter.* Rejected. A guard could
  call `score` on a token model, which CLAUDE.md asks the type system to rule out.

### D3. Offsets are bytes in Rust; the parity reference converts

Rust `tokenizers` gives byte offsets; Python gives character offsets. Stage 2 must confirm
this. The Rust decoder works on byte positions on character boundaries, and implements
"first non-whitespace character" and the word rules over `char`s. The parity test turns the
reference's character offsets into byte offsets before it compares.

Whitespace, in every decoder rule, is the Unicode White_Space property, as Rust's
`char::is_whitespace` has it. The Python copy of the decoder uses the same set, not
Python's `str.isspace`, which also holds U+001C to U+001F (agreed 2026-10-21).

### D4. The guard builds the unit text with a source map and boundaries

`ModelGuard` builds three things for each unit: the text, a map from text bytes to unit
bytes, and the text positions that are hard boundaries.

- **Plain text:** decode lossily, and record each U+FFFD with the byte range it replaced.
  Outside those ranges, a text byte maps to the source byte plus the accumulated shift.
- **Fragments:** join the values with `\n`, record each value's text range and its
  document-absolute source offset, and make every join a hard boundary.

The decoder takes the boundaries and never merges words across one. The guard passes them
as a sorted `Boundaries` newtype from `voidwall-ml`, so an unsorted list cannot be built
(agreed 2026-10-21). Every span therefore
falls inside one fragment, and maps to one contiguous source range. The spec has a scenario
for this, `Two values of one type in neighbouring fragments`.

- *Alternative: run the model once per fragment.* Rejected. Each fragment would pay its own
  windows; a JSON body of many short values would multiply the inference cost.

### D5. The span trim lives in the decoder

The agreed trim is the decoder's last step in `voidwall-ml`, so every `token_classifier`
finding is trimmed, with or without `validate_as`. The `voidwall-pii` validation API then
takes the text exactly as given. This differs from the first sketch, which trimmed only
inside `validate_as`. The later decision was to trim every ML finding.

### D6. Validators made public by kind, built from the pattern tables

`voidwall-pii` builds, once, a map from kind to the check of each of that kind's patterns
(duplicates kept). It walks the same pattern tables the detectors compile. It exposes:
- a check that a text passes any validator of a list of kinds;
- a test that a kind has a validator other than one that accepts every value, which
  config validation needs.

A pattern added with the `add-pii` skill is then covered with no extra step.

- *Alternative: an engine stage that validates every guard's spans.* Rejected. Validators
  belong to patterns, not kinds; regex validation must run before `resolve_overlaps`; and
  the engine does not hold span text.
- *Alternative: name validators in config.* Rejected. About 50 internal function names
  would become stable config.

### D7. `config_path` is the source of `id2label`

The guard reads `config.json` at load, not from a label list in TOML. A model has dozens of
labels (bards v2 has 71), and listing them in order by hand is easy to get wrong. The file is
read only when the model loads; `--validate` stays offline and loads no model, as today.
`labels` keeps its meaning, and it is not checked against `id2label` (agreed).

### D8. A vocabulary belongs to one guard

Findings of the same kind name from two guards are merged and never resolved. The block
outcome does not depend on counts, so this changes match counts only. The wording is already
changed in `AGENTS.md`, `ARCHITECTURE.md` §4.2 and `engine/mod.rs`. The `pii-scanning`
delta makes the spec match. No code changes for this decision.

### D9. `class = "pii"` is declared, not derived

A guard's class is an explicit config field, a closed enum with one variant. It is not
derived from the adapter, because a token classifier may find secrets or toxic spans. Every
place that increments `voidwall_pii_*` asks one question: is this finding's guard a PII
guard? The built-in `pii` guard is one by definition. The answer is a set of guard names,
built at startup from configuration, so it cannot grow with traffic.

### D10. The default guard in the dev environment

`docker/fetch-models.sh` fetches bards v2 at revision `5e61416e…` into `models/bards-v2/`:
`onnx/model_quantized.onnx`, `tokenizer.json` and `config.json`, each verified against a
pinned SHA-256. The model repository carries no LICENSE file, so the script writes the
Apache-2.0 text from a copy vendored in the repository, with the source repository and
revision, as `models/bards-v2/LICENSE`. `docker-compose.yml` mounts the directory read-only.

`docker/voidwall.toml` declares the guard as `[guards.pii_ml]`; the image does not ship it:
- `adapter = "token_classifier"`, `class = "pii"`, `max_tokens = 512`,
  `overlap_tokens = 128`, surface: the body.
- Thresholds 0.4: `PERSON_NAME`, `POSTAL_ADDRESS`, `DATE_OF_BIRTH`.
- Thresholds 0.0: `PHONE_NUMBER`, `EMAIL_ADDRESS`, `BANK_ACCOUNT_IDENTIFIER`,
  `AUTH_SECRET`, `DOCUMENT_IDENTIFIER`, `IP_ADDRESS`, `PAYMENT_CARD`, `PERSON_IDENTIFIER`,
  `GEO_LOCATION`.
- `validate_as`: `PAYMENT_CARD = ["CREDIT_CARD"]` only. `IP_ADDRESS` gets none: its
  IPv4 pattern's `ip_check` accepts any text without a dot, and its IPv6 pattern has no
  check (`Check::Any`), so validating as `IP_ADDRESS` would drop almost no span.
- Not listed, so they report nothing: `PAYMENT_CARD_SECURITY`, `VEHICLE_IDENTIFIER`,
  `ACCOUNT_IDENTIFIER`, `CONTACT_HANDLE`, `DEVICE_IDENTIFIER`, and every type outside the
  agreed scope.

### D11. Parity: PyTorch fp32 plus a checked-in Python decoder

`crates/voidwall-ml/parity/` gains a token-classification reference. It runs the PyTorch
fp32 model per window, then a Python copy of the decoder taken from `vw.py`, which becomes
the decoder's executable specification. `docker/ctl parity` runs both models.

The pooled probabilities must be within 2e-4 of the reference, not the 1e-4 of
`text_classifier` (agreed 2026-10-21). Measured on fp32 bards v2 over the text set, at
the worst token: Rust against PyTorch 1.41e-4; the ONNX export in Python ORT 1.28.0
against PyTorch 9.77e-5; Rust against Python ORT 4.35e-5. The gap is the export's and the
runtime's, not the decoder's: token IDs and every span were equal.

The text set uses placeholder values only. It covers:
- every agreed label;
- multi-window texts;
- non-ASCII text;
- edge punctuation for the trim.

### D12. INT8 is checked against a plain session, not against Python

The spike measured a max logit difference of 0.74 for INT8 (Rust loader against Python
ORT), against 2e-5 for fp32. Stage 7 found the cause
(`voidwall-internal/research/pii-model/int8-gap.md`):
- It is not the loader. Every Rust session gives bit-identical logits: the original file
  with default options, with prepacked weights, with initializer overrides, and the staged
  graph the loader uses.
- It is not non-determinism. Each runtime gives bit-identical logits across optimization
  levels and thread counts.
- The pyke build that Voidwall links and the Python wheel, both ONNX Runtime 1.28.0, round
  some fp32 operations 1 to 3 ulp apart. On the spike text one activation at layer 15 sits
  on a rounding tie and quantizes one step apart; the step spreads to 0.74 at the logits.
  `MatMulInteger` is exact in both.

Over the parity text set, Rust INT8 against Python ORT INT8 gives a max pooled-probability
delta of 0.276, and 77 of 78 spans are equal. A tolerance that wide checks almost nothing,
and no tolerance gives equal spans.

So the INT8 check covers what the loader owns (agreed 2026-10-21): an ignored test runs
every window of the token parity text set through an INT8 worker and through a plain ONNX
Runtime session of the same file, and requires bit-identical logits. `docker/ctl parity`
runs it. No INT8 check against Python is made; the build gap is a known limit.

- *Alternative: a cross-build tolerance of about 0.3, with spans equal above the guard
  threshold.* Rejected. It would pass almost any regression, and the Python reference
  would need ONNX Runtime.

## Risks / Trade-offs

- [The offset map is wrong for edge cases: invalid UTF-8, multi-byte characters at a
  join, empty fragments] → Property tests in stage 4: every span's source bytes, decoded,
  equal the span's text, over generated units.
- [The decoder drifts from the reference] → The stage 3 parity test compares spans exactly
  and probabilities within 2e-4.
- [A misspelled label silently reports nothing] → Accepted (agreed); the docs say so.
- ["Any validator of the kind" is looser than per-pattern validation] → Accepted; the
  default config validates only cards, where the kind has one rule.
- [`validate_as` with `IP_ADDRESS` accepts almost every span: `IP_ADDRESS` has two
  patterns, IPv4 with `ip_check`, which returns true for any text without a dot, and
  IPv6 with no check (`Check::Any`)] → Accepted; the default config does not validate
  `IP_ADDRESS`.
- [The dev stack now runs two model guards, so each gets half the CPUs] → Expected; the
  latency in the research report is per worker.
- [`PERSON_NAME` blocks about a third of general-knowledge prompts] → A product question
  outside this change; the regex guard already does the same. Recorded in the research
  report.
- [INT8 differs from Python ORT: pooled probabilities by up to 0.276, 1 of 78 spans] →
  Accepted as a known limit of the two builds (D12); the exact test covers the loader.

## Migration Plan

All new config fields are optional for existing guards, and no existing config changes
meaning. The dev environment downloads one more model on `docker/ctl fetch_models`. To
roll back, remove the guard section; nothing else depends on it.

## Delivery

Seven stages, one commit each, in the order of `tasks.md`. Stages 1, 2 and 7 have no
dependency on each other. Stage 3 needs 2; stage 4 needs 1 and 3; stages 5 and 6 need 4.
Each stage runs `cargo test --workspace` and `cargo clippy --workspace --all-targets`, and
gets a `code-review` against this change's spec deltas before its commit. Specs are synced
with `openspec-sync-specs` as stages land, and archived after stage 7.
