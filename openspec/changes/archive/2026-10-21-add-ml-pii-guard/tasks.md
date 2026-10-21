Each `##` section is one stage and one commit. Run a stage in a fresh session.
1. Read `proposal.md`, `design.md`, the stage's spec deltas, and the memory note
   `ml-pii-guard-decisions`.
2. Do the stage's tasks.
3. End the stage with its final task: workspace tests, Clippy, and `code-review` against
   the spec deltas.
4. The user commits.

Order: stages 1, 2 and 7 have no dependency on each other; 3 needs 2; 4 needs 1 and 3;
5 and 6 need 4.

## 1. Stage 1 — `voidwall-pii`: validation by kind (D6)

- [x] 1.1 Read `crates/voidwall-pii/AGENTS.md`. Build, once, a map from `PiiKind` to the check of each of that kind's patterns (duplicates kept), from the same pattern tables the detectors compile (`hyperscan_detector.rs`, `keyword_context_detector.rs`, and any other table with a `validator`). Verify: a unit test that every `PiiKind` with a pattern has an entry, and that a kind with two patterns of different validators (e.g. `UsDriversLicense`: `us_dl_check`, `us_dl_numeric_check`) holds both.
- [x] 1.2 Add a public `validate_as(kinds: &[PiiKind], text: &str) -> bool`: true when any validator of any listed kind accepts `text`. Verify: `#[test_case]` tests — a Luhn-valid placeholder card number passes `[CreditCard]` and a Luhn-failing one does not; a text passing only the second of two listed kinds passes; an empty list returns false.
- [x] 1.3 Add a public `has_validator(kind: PiiKind) -> bool`: false when every pattern of the kind is `Check::Any`. Verify: `#[test_case]` — `CreditCard` and `IpAddress` true; `Email` (if all its patterns are `Check::Any`) false; the result matches the table for every kind.
- [x] 1.4 Add a public way to parse a kind from its label (`PiiKind::label()` inverse), if none exists. Verify: round-trip test over `PiiKind::ALL`; an unknown name gives `None` or an error.
- [x] 1.5 Stage check. Verify: `cargo test -p voidwall-pii` and `cargo clippy --workspace --all-targets` pass; the regex guard's match set is unchanged (the existing tests pass with no edit); `code-review` against `specs/guard-configuration` (validate_as rules) finds no blocker.

## 2. Stage 2 — `voidwall-ml`: the `token_classifier` contract (D2, D3, D7)

- [x] 2.1 Add `AdapterKind::TokenClassifier` (`token_classifier`, score range `0.0..=1.0`) and an optional `config_path` in `LoadSettings`. Verify: the name round-trip test in `adapter.rs` covers it.
- [x] 2.2 Read `id2label` from `config.json` at load: JSON parse, keys exactly `0..n-1`, exactly one `O`, prefixes `B-`/`I-`/`S-` or none; build the type list and the label→type pooling and B/S mask. New `LoadError` variants name the config path. Verify: `#[test_case]` unit tests for each failure scenario in `specs/model-runtime` ("A token classifier reads its labels…"), and a BIO config giving the expected types.
- [x] 2.3 Output contract for `token_classifier`: rank 3, last dim = `id2label` length; smoke inference shape `[1, n, width]`; `infer` accepts `[1, len, width]` for token workers only. Verify: fixture models (extend `fixtures.rs` with a tiny token-classifier graph) for: width match loads; width mismatch fails naming both numbers; rank-2 output fails; a wrong token count at run time fails with the output-shape error; `text_classifier` checks unchanged.
- [x] 2.4 Two worker types (D2): `load()` returns classifier workers or token workers; a token worker's run returns, per window, the pooled probabilities and the B/S mass of each token with its byte offsets; cancellation and the window limit behave as for classifiers. Verify: unit tests — a token worker over a multi-window fixture text records each token once per window that holds it; `RunError::WindowLimit` and `Cancelled` behave as in the classifier tests; a whitespace-only text runs no inference and returns no span (spec "A token classifier finds nothing in blank text").
- [x] 2.5 Confirm that Rust `tokenizers` offsets are byte offsets (D3). Verify: a unit test on a non-ASCII text whose offsets land on the expected byte positions.
- [x] 2.6 Apply the spike lesson: the `UINT8` embedding `Gather` is found and INT8 initializers decode. Verify: an `#[ignore]` test (as in `research/pii-model/results/spike-int8-loader.patch`) loads the real INT8 file with 1 and 6 workers when `PII_MODEL_DIR` is set; RSS for 6 workers stays within 1.2× of 1 worker.
- [x] 2.7 Stage check. Verify: `cargo test --workspace`, `cargo clippy --workspace --all-targets`; `code-review` against `specs/model-runtime`.

## 3. Stage 3 — `voidwall-ml`: the word-level decoder and its parity (D1, D5, D11)

- [x] 3.1 Port the decoder from `voidwall-internal/research/pii-model/scripts/vw.py` (`BardsDecoder.predict`, upstream steps only) to Rust over byte positions: per-character accumulation, word split and edge trim, mean argmax, B-mass merge rule, confidence as the mean of word probabilities. Take hard-boundary positions as input; never merge across one. Verify: unit tests with hand-made probability arrays for each scenario of "A token classifier labels each word…" and "Neighbouring words of one type merge…", including the blank-line and the hard-boundary cases.
- [x] 3.2 Apply the span trim as the decoder's last step (D5). Verify: `#[test_case]` tests — trailing `).` removed, leading `(` kept, quotes both sides removed, a span trimmed to empty is dropped.
- [x] 3.3 Parity reference: add a token-classification mode to `crates/voidwall-ml/parity/reference.py` (PyTorch fp32 per window, then a checked-in Python copy of the decoder from `vw.py`, with Voidwall windows) and a placeholder-only text set (every agreed label, multi-window, non-ASCII, edge punctuation). Verify: the script runs on the fp32 bards v2 files and writes token IDs, pooled probabilities and spans.
- [x] 3.4 Rust parity test (`#[ignore]`): equal token IDs, pooled probabilities within 2e-4, equal spans and types, comparing offsets after the reference's character offsets are turned into bytes. Verify: it passes on fp32 bards v2 at revision `5e61416e…`.
- [x] 3.5 Stage check. Verify: `cargo test --workspace`, Clippy; `code-review` against `specs/model-runtime`.

## 4. Stage 4 — `voidwall`: the token classifier guard (D4, D6, D7)

- [x] 4.1 Config: `adapter = "token_classifier"`; `config_path` (required for it, rejected for `text_classifier`); `[guards.<name>.validate_as]` with its startup rules; `class` (closed enum `pii`). Verify: `#[test_case]` unit tests for every scenario of the `guard-configuration` delta that is about validation; `docs/config-validation.md` lists each new message.
- [x] 4.2 Unit text with a source map and hard boundaries (D4): plain text decoded lossily, with each U+FFFD recorded with its source range; fragments joined with `\n`, each recording its text range and its document-absolute source offset, with each join a boundary. Replace `boundaries: &[usize]` in `TokenWorker::spans` with a sorted `Boundaries` newtype from `voidwall-ml`, which the guard builds. Verify: property tests over generated units (random valid and invalid UTF-8, multi-byte characters, empty fragments): for every text range inside one segment, the mapped source bytes decode to the same text.
- [x] 4.3 Token `ModelGuard`: run the token worker, keep spans whose type is in `labels` with a threshold at or below the confidence, apply `validate_as` through `voidwall_pii::validate_as` on the span text, and map the span to unit bytes; report `Finding`s with span and confidence (add a constructor that sets both). Verify: unit tests with the fixture token model for the `guard-configuration` scenarios (two values, below threshold, threshold 0, card fails Luhn, any kind may accept, span after an invalid byte, span in a JSON value, neighbouring fragments); no log line or error holds span text (marker check).
- [x] 4.4 Engine wiring: build token guards from config with `config_path`; a load error names the guard. Verify: engine unit test selects the token guard by name; integration test (real server, fixture model) — `/v1/scan` of a body holding a placeholder value the fixture flags returns its kind, and the reverse proxy answers 403 naming it.
- [x] 4.5 Same-named kinds from two guards (D8): no resolution between guards. Verify: the `pii-scanning` scenario "Two guards report a kind of the same name" as an engine unit test — both findings kept, `kinds()` holds the kind once, `matches_count()` counts both.
- [x] 4.6 Docs: `ARCHITECTURE.md` §4.8 (the token adapter, spans, `validate_as`, `config_path`) and §5. Verify: the text matches the deltas; no PII value in examples.
- [x] 4.7 Stage check. Verify: `cargo test --workspace`, Clippy, `cargo deny check licenses`; `code-review` against `specs/guard-configuration` and `specs/pii-scanning`.

## 5. Stage 5 — `voidwall`: `class = "pii"` in the metrics (D9)

- [x] 5.1 Build at startup the set of PII guard names (`pii` plus every guard with `class = "pii"`), and make every `voidwall_pii_*` increment ask it. Verify: unit and integration tests for each new or changed scenario of the `metrics` delta (a PII model guard detects; only a PII model guard detects → both blocked counters; two PII guards → one increment; a classless model guard → no PII increment); every existing metrics test still passes.
- [x] 5.2 `pii_kind` values from a PII model guard are its configured labels. Verify: the scenario "A PII model guard's kind" in a test; no label value is ever taken from a request.
- [x] 5.3 Stage check. Verify: `cargo test --workspace`, Clippy; `code-review` against `specs/metrics`.

## 6. Stage 6 — dev environment, parity runner, docs (D10, D11)

- [x] 6.1 `docker/fetch-models.sh`: fetch bards v2 at revision `5e61416e77675881185767fc0c67759d48b35592` into `models/bards-v2/` (`onnx/model_quantized.onnx`, `tokenizer.json`, `config.json`), each against a pinned SHA-256; write `LICENSE` from a vendored Apache-2.0 text with the source repo and revision. Verify: a fresh run downloads and verifies; a second run downloads nothing; a corrupted file stops the script with a non-zero exit naming it.
- [x] 6.2 `docker/docker-compose.yml` mounts `models/bards-v2/` read-only; `docker/voidwall.toml` declares `[guards.pii_ml]` exactly as D10. Verify: `voidwall --validate docker/voidwall.toml` exits 0; `docker/ctl start` comes up, `/readyz` 200; a request body with a placeholder name and address is blocked naming `PERSON_NAME` and `POSTAL_ADDRESS`; a benign body passes.
- [x] 6.3 `docker/ctl parity` checks wolf-small and bards v2, with per-model default windows (2048/64, 512/128), `PARITY_MAX_TOKENS`/`PARITY_OVERLAP` overriding both, pinned fp32 files in `.cache/parity/`. Verify: the `model-runtime` parity-runner scenarios by running the command (both pass; a corrupted pinned file stops it naming the file).
- [x] 6.4 Docs: `crates/voidwall-ml/parity/README.md`, `DEVELOPMENT.md` (models, sizes), `docs/` operator docs for `token_classifier`, `config_path`, `validate_as`, `class`. Verify: every config example validates with `--validate`; no PII value in examples.
- [x] 6.5 Stage check. Verify: `cargo test --workspace`, Clippy; `code-review` of the stage.

## 7. Stage 7 — the INT8 logit gap (D12)

- [x] 7.1 Isolate the cause of the 0.74 max logit difference between the Rust loader and Python ORT on INT8 (fp32: 2e-5). Compare Rust sessions with and without initializer overrides and with and without prepacked weights against Python, on the same IDs. Verify: a short note in `voidwall-internal/research/pii-model/` names the cause with numbers, or states that it is ORT's INT8 kernel non-determinism, with evidence.
- [x] 7.2 Add an `#[ignore]` test: every window of the token parity text set gives bit-identical logits from an INT8 `token_classifier` worker and from a plain ONNX Runtime session of the same file (the worker's session options, no shared or prepacked weights). `docker/ctl parity` links `onnx/model_quantized.onnx` into its run directory and runs it. Verify: it passes on bards v2 INT8 through `docker/ctl parity`; `crates/voidwall-ml/parity/README.md` says what it checks and how to run it.
- [x] 7.3 Add the INT8 requirement to `specs/model-runtime` with `openspec-update-change`, stating the measured build gap as a known limit, and the INT8 check in the parity runner requirement. Verify: `openspec validate add-ml-pii-guard --strict` passes.
- [x] 7.4 Stage check, and close the change. Verify: `cargo test --workspace`, Clippy; `code-review` of the whole change against all four deltas and `ARCHITECTURE.md`; then `openspec archive add-ml-pii-guard`.
