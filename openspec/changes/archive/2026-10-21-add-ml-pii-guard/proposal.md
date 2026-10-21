## Why

The regex PII guard misses PII that has no fixed shape, or that comes from a country it
has no patterns for: names (span recall 0.79), postal addresses (0.59), bank accounts
(0.29), secrets (0.05) and document numbers (0.34) on the Gretel finance set. A token
classifier finds most of them. Measured on the default candidate, run beside the regex
guard, it cuts Gretel documents with PII that pass unblocked from 6.1% to 3.9%. It blocks
only 0.82% of benign Dolly prompts that the regex guard lets through. It costs about what
the shipped wolf-small guard costs on CPU. The measurements are in
`voidwall-internal/research/pii-model/README.md`.

## What Changes

- New adapter `token_classifier`. Any Hugging Face token-classification model that meets
  one contract runs through it:
  - `tokenizer.json`;
  - ONNX inputs `input_ids` and `attention_mask` (and optionally `token_type_ids`);
  - one `Float32` output of shape `[1, seq, n_labels]`;
  - a `config.json` whose `id2label` uses B-/I-/S- prefixes, or IO labels with no prefix.
- A fixed word-level decoder inside that adapter, ported from bards.ai's
  `pii_detector.py` (steps 1–5):
  - per-character probability accumulation across windows;
  - B/I/S pooling per type;
  - word split and edge trim;
  - mean argmax per word;
  - the B-mass merge rule.

  Its format checks and email regex are not ported. Configuration sets no decoder
  options. A model that needs other decoding gets another named adapter later.
- A finding of this adapter carries a byte span inside its unit and a confidence: the
  mean, over the span's merged words, of each word's winning pooled probability. In a
  unit parsed into fragments, no span crosses two fragments.
- Every finding of the adapter is trimmed at its edges, and the finding reports the
  trimmed span:
  - both edges: Unicode whitespace, `, . ; : ! ?`, and the quotes `" ' “ ” ‘ ’ « » „`;
  - trailing edge only: `) ] }`.
- `[guards.<name>]` gets three fields:
  - `config_path`: the model's `config.json`, the source of `id2label`. Required for
    `token_classifier`.
  - `[guards.<name>.validate_as]`: label → list of PII kind names. A span passes when any
    validator of the named kinds accepts it, and a span that fails is dropped. The
    validators are the regex guard's own, made public by `voidwall-pii`.
  - `class = "pii"`: a closed enum, absent by default. A guard that sets it counts in the
    `voidwall_pii_*` metric families.
- A kind vocabulary belongs to one guard. Two guards that report kinds of the same name do
  not share a vocabulary, and the engine merges their findings without resolution. The
  wording of `AGENTS.md`, `ARCHITECTURE.md` and `engine/mod.rs` already says this; the
  spec follows.
- `voidwall-pii` makes its validators reachable by kind: a public check of a span against
  a list of kinds, and a public test of whether a kind has a validator other than
  one that accepts every value. The kind table is built from the pattern tables, so it
  cannot drift.
- Dev environment default model: `bardsai/eu-pii-anonimization-multilang-v2` at revision
  `5e61416e77675881185767fc0c67759d48b35592`, INT8 ONNX, fetched by `docker/ctl
  fetch_models` and mounted like wolf-small. `docker/voidwall.toml` declares the guard
  with the agreed labels, thresholds and `validate_as`, `max_tokens = 512`, and
  `overlap_tokens = 128`.
- `docker/ctl parity` also checks the new model.
- The cause of the INT8 logit gap against Python ONNX Runtime (max 0.74; fp32 2e-5) is
  found: not the loader, but the two ONNX Runtime builds, which round fp32 a few ulp
  apart. An ignored test checks that an INT8 worker's logits equal those of a plain
  session of the same file, bit for bit, and `docker/ctl parity` runs it. No INT8 check
  against Python is made.
- The work lands in 7 stages, one commit each (see `tasks.md`).

Out of scope:
- Shipping the model in the Docker image; it stays a mounted file, as wolf-small is.
- Decoder options in configuration.
- Checking `labels` against the model's `id2label`.
- Span-based models such as GLiNER.
- The regex false positives found on Dolly (`docs/backlog.md` §3).

## Capabilities

### New Capabilities

None.

### Modified Capabilities

- `model-runtime`: adds the `token_classifier` adapter:
  - its tensor contract (3-D output);
  - `id2label` from `config.json`;
  - per-token probabilities with offsets;
  - the word-level decoder, the span trim and the confidence;
  - parity with a Python reference, and an exact INT8 check against a plain session.

  Also: `docker/ctl parity` checks the new model.
- `guard-configuration`: adds `config_path`, `validate_as` and `class` to a model guard,
  the labels rule for `token_classifier`, and spanned findings with a confidence. It also
  says what text a token classifier scores, and how its spans map back to unit bytes.
- `pii-scanning`: overlap resolution is scoped to one guard's vocabulary; same-named kinds
  from two guards are merged, never resolved.
- `metrics`: `voidwall_pii_detections_total` and `voidwall_pii_blocked_total` count every
  guard with `class = "pii"`, not only the `pii` guard.

## Impact

- **Code:**
  - `crates/voidwall-pii`: public kind-level validation.
  - `crates/voidwall-ml`: adapter, decoder, `LoadSettings` field for `config.json`, parity.
  - `crates/voidwall`: config fields and validation, `ModelGuard` spans, metrics.
- **Public API (workspace-internal):**
  - `voidwall-pii` gains functions.
  - `voidwall-ml`'s `Adapter` trait and `Worker` gain a per-token output path;
    `text_classifier` keeps its behaviour.
- **Config:** three new fields, all optional for `text_classifier`. No existing config
  changes meaning.
- **Operator-visible:**
  - a new adapter;
  - findings with spans from a model guard;
  - `voidwall_pii_*` counts guards that set `class = "pii"`.
- **Dev environment:** about 294 MiB more to download (INT8 model) plus a 33 MiB tokenizer;
  one more mounted directory.
- **Docs:**
  - `ARCHITECTURE.md` §4.8 and §5;
  - `docs/config-validation.md`;
  - `crates/voidwall-ml/parity/README.md`;
  - `DEVELOPMENT.md`.
- **Dependencies:** none new expected.
