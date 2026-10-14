## Why

Since `remove-configurable-actions` deleted the AI4Privacy harness, nothing measures how
well the `voidwall-pii` regex engine detects PII. A change to a pattern, a keyword list, or
a validator can raise or lower recall and precision, and nobody can see by how much.

The goal is to measure the regex engine, not Voidwall as a product. The old harness drove
the running proxy over HTTP because it scored the product. With the engine as the target,
the harness links `voidwall-pii` directly and reads each match's kind and span from it.
This reverses the "link `voidwall_pii` directly" alternative that
`remove-configurable-actions` rejected, because the reason for that rejection no longer
applies.

## What Changes

- Add a fourth workspace member, `crates/voidwall-eval`, that depends on `voidwall-pii`
  only. It holds one binary, `ai4privacy-eval`.
- The harness scores the `ai4privacy/pii-masking-300k` dataset (openpii300k) for one
  language or for all six (en, nl, fr, de, it, es).
- For each language, the harness builds a `voidwall_pii::Scanner` with that language and
  every supported country that uses it, plus `International`.
- The harness passes each row's matches through `voidwall_pii::resolve_overlaps` before it
  scores them, so it scores the set the regex PII guard reports.
- Add a label mapping from each AI4Privacy label to the `PiiKind`s that count as the right
  kind for it. A label with no `PiiKind` is unsupported.
- Scoring keeps the old rules: span overlap gives a true positive, an unmatched prediction
  a false positive, and an unmatched annotation a false negative.
- The report gives precision and recall per label, micro precision, recall, F1, and F2,
  and macro recall, in two variants: detection (any kind) and typed (the mapped kind). It ends with a legend
  that explains the variants and the columns.
- Add `docker/ctl ai4p-eval`. It fetches and caches the dataset files and runs the harness. It
  accepts `AI4P_LANG`, `DATASET`, `MAX_ROWS`, and `SUPPORTED_ONLY`.
- Document the evaluation. `README.md` gets an Evaluation section with an example command
  for English. `DEVELOPMENT.md`, `AGENTS.md`, `ARCHITECTURE.md`, `.gitignore`, and
  `docs/backlog.md` are updated to match.
- No skill is added.

## Capabilities

### New Capabilities

- `evaluation`: an offline harness that scores the `voidwall-pii` regex engine against the
  AI4Privacy openpii300k dataset, and its `docker/ctl ai4p-eval` runner.

### Modified Capabilities

None.

## Impact

- **New crate:** `crates/voidwall-eval` (workspace member, not part of the image). New
  dependency: `serde_json` in that crate only. New dev dependency: `proptest`, for the
  differential test of the scores.
- **`docker/ctl`:** a new `ai4p-eval` subcommand. Other subcommands are unchanged.
- **Docs:**
  - `README.md`: a new Evaluation section, with
    `AI4P_LANG=en SUPPORTED_ONLY=1 docker/ctl ai4p-eval` as the example.
  - `DEVELOPMENT.md`: a `docker/ctl ai4p-eval` row in the `docker/ctl` command table.
  - `AGENTS.md` (`CLAUDE.md` links to it): the workspace member list.
  - `ARCHITECTURE.md`: a `crates/voidwall-eval` row in the crate table.
  - `.gitignore`: the cache comment names `docker/ctl ai4p-eval`.
  - `docs/backlog.md` §4: the "Evaluation documentation" item is removed, because this
    change ships it.
- **Build:** `docker/ctl compile` builds every workspace member, so it also builds the
  harness. The Dockerfile copies only `target/release/voidwall`.
- **Unchanged:** the proxy, its HTTP API, its configuration, its metrics, and the
  `voidwall-pii` public API. The image does not ship the harness.
- `.cache/ai4privacy/` already holds the English file, so that language needs no new
  download.
