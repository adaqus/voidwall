## 1. Crate setup

- [x] 1.1 Add `crates/voidwall-eval` to the workspace with `[[bin]] ai4privacy-eval`,
  depending on `voidwall-pii`, `serde`, and `serde_json`, and `test-case` as a dev
  dependency. Check: `cargo check -p voidwall-eval` passes and `cargo tree -p voidwall-eval`
  shows no `voidwall` or `voidwall-ml`.

## 2. Label mapping

- [x] 2.1 Add `enum Ai4pLabel` (28 openpii300k labels) and `Label::{Known, Unknown}`
  parsing. Check: `#[test_case]` for each label string, and for an unknown one.
- [x] 2.2 Add `labels_for(PiiKind)` with an exhaustive `match` (no wildcard) that follows
  the spec table. Check: `#[test_case]` for each spec row, including TEL with a country
  phone kind and IDCARD/SOCIALNUMBER with shared kinds (`NL_BSN`, `ZA_ID`,
  `IT_CODICE_FISCALE`).
- [x] 2.3 Derive the supported set from `PiiKind::all()`. Check: a test that the
  supported set equals the spec's mapped labels, and that the unsupported set equals
  PASS, TITLE, CARDISSUER, COUNTRY, CITY, STATE, SEX, DATE, TIME, USERNAME, BUILDING.

## 3. Scanner per language

- [x] 3.1 Add the language → countries `const` table and the parser for the row
  `language` field and for `AI4P_LANG` (code or full name, any case). Check: `#[test_case]` for
  each of the six languages in both forms, and for an unsupported language.
- [x] 3.2 Build one `Scanner` per language on first use, with that language and its
  countries. Check: a test that a French scanner detects an FR kind and an International
  kind, and does not detect a US-only kind.

## 4. Row model and offsets

- [x] 4.1 Port the lenient row model (`source_text`/`unmasked_text`, `privacy_mask` as an
  array or a JSON string, unknown fields ignored). Check: tests for both `privacy_mask`
  forms and an unknown field.
- [x] 4.2 Port the annotation offset fallbacks (`resolve_gt`). Check: the old tests plus a
  test for each fallback.
- [x] 4.3 Convert resolved byte spans to character offsets. Check: a test with
  multi-byte characters before a detected value gives an overlapping span.

## 5. Scoring

- [x] 5.1 Score one row from `resolve_overlaps(scanner.mark_piis(text))`: detection and
  typed hits per annotation, TP/FP per prediction, and the supported-only counts where a
  prediction that overlaps only unsupported annotations is neither TP nor FP. Check: tests
  for overlap TP, no-overlap FP, missed FN, right span with wrong kind, overlapping raw
  matches scored once, and the supported-only case.
- [x] 5.2 Aggregate: per-label recall and precision (a prediction counts toward every
  label that accepts its kind), micro P/R/F1, and macro recall over supported labels.
  Check: a test on a hand-built set of row outcomes with known totals.

## 6. Report and run

- [x] 6.1 Read `DATASET`, `AI4P_LANG`, `MAX_ROWS`, and `SUPPORTED_ONLY` from the environment.
  Exit non-zero on an unknown `AI4P_LANG` or a
  missing dataset. Check: tests for the config parse.
- [x] 6.2 Stream rows through a bounded channel to `available_parallelism()` workers. Stop
  after `MAX_ROWS` scored rows. Count parse errors and rows in an unsupported language.
  Check: `MAX_ROWS=200 AI4P_LANG=en` on the cached English file reports 200 rows.
- [x] 6.3 Print the report: counts, per-label table (detection and typed), micro totals,
  macro recall, unknown labels by name. Under `SUPPORTED_ONLY=1`, omit unsupported labels.
  Print no dataset text. Check: a test that the report output holds no annotated value
  from a test row.
- [x] 6.4 End the report with a legend for the detection and typed variants, the columns,
  and the totals. The legend is the same in both modes and does not name
  `SUPPORTED_ONLY`. Check: a test that the legend names both variants, and a test that it
  is the same with and without `SUPPORTED_ONLY` and does not contain that name.

## 7. Runner

- [x] 7.1 Add `docker/ctl ai4p-eval`: header comment for the variables, fetch of the
  openpii300k train files into `.cache/ai4privacy/` (skip a cached file), `AI4P_LANG` → file
  mapping, `DATASET` override, and the `cargo run` call. Add `ai4p-eval` to the usage line and
  the dispatch. Check: `AI4P_LANG=en docker/ctl ai4p-eval` fetches nothing (the English file is
  cached); `AI4P_LANG=pt docker/ctl ai4p-eval` exits non-zero and names the accepted values.

## 8. Documentation

- [x] 8.1 `README.md`: add an `## Evaluation` section before `## TODO`. It states what the
  eval measures (recall, precision, and F1 of the regex PII engine against AI4Privacy
  openpii300k), that it needs no running proxy, that the first run downloads the dataset,
  and gives `AI4P_LANG=en SUPPORTED_ONLY=1 docker/ctl ai4p-eval` as the example. Check: the example command runs
  as written.
- [x] 8.2 `DEVELOPMENT.md`: add a `docker/ctl ai4p-eval` row to the `docker/ctl` command
  table, naming `AI4P_LANG`, `DATASET`, `MAX_ROWS`, and `SUPPORTED_ONLY`. Check: the row
  matches the header comment in `docker/ctl`.
- [x] 8.3 `AGENTS.md`: update the workspace member list to four members. Check: the list
  names `crates/voidwall-eval/` and what it is for.
- [x] 8.4 `ARCHITECTURE.md`: add a `crates/voidwall-eval` row to the crate table. Check:
  the table has one row per workspace member.
- [x] 8.5 `.gitignore`: change the cache comment to name `docker/ctl ai4p-eval`. Check:
  `grep -rn "ctl eval"` over the repository, outside `openspec/changes/archive/`, finds
  nothing.
- [x] 8.6 `docs/backlog.md` §4: remove the "Evaluation documentation" item. Check: §4 no
  longer mentions the retired AI4Privacy harness.

## 9. Verification

- [x] 9.1 `cargo test --workspace` and `cargo clippy --workspace --all-targets` with no
  warnings. Check: both pass.
- [x] 9.2 `cargo deny check licenses`. Check: it passes with `serde_json` added.
- [x] 9.3 Full run on English. Check: the report finishes and shows every label of the
  file.
- [x] 9.4 Review the diff against the spec delta with the `code-review` skill. Check: no
  open findings.

## 10. Report correctness

- [x] 10.1 Apply `SUPPORTED_ONLY` to the per-label precision: under that option, a
  prediction that overlaps only unsupported annotations counts as neither a TP nor an FP
  in the precision of any label. Check: a test where such a prediction leaves the
  per-label precision unchanged under `SUPPORTED_ONLY=1` and counts as a TP without it.
- [x] 10.2 Golden report test: hand-built rows with injected predictions (no scanner) that
  cover a typed hit, a wrong-kind hit, a miss, an FP, one prediction on two annotations,
  two predictions on one annotation, a prediction on an unsupported annotation only, a
  prediction on a supported and an unsupported annotation, an unknown label, a label with
  no prediction, and PERSON_NAME (five labels). Check: the full report text equals the
  expected text, with and without `SUPPORTED_ONLY`, and a comment gives the arithmetic of
  each expected number.
- [x] 10.3 Differential test with `proptest` (dev dependency): a reference scorer written
  from the spec text, sharing only `Label::accepts` and `Label::is_supported` with the
  harness, against `score` and `Aggregate` on random rows. Check: the per-label counts,
  the micro totals, the macro recall, and the per-label precision are equal in both
  variants and both modes.
- [x] 10.4 Metamorphic tests. Check: `run` gives the same aggregate with one worker and
  with many, and with the rows in reverse order; a dataset written twice doubles every
  count and keeps every ratio; an added prediction that overlaps nothing changes only
  precision; an added unsupported annotation that overlaps no prediction does not change
  the `SUPPORTED_ONLY` report.
- [x] 10.5 End-to-end fixture: a JSONL file with values the engine detects (an email and
  an IBAN), multi-byte text before a value, byte offsets, `privacy_mask` as a string, and
  a row in an unsupported language. Check: `run` gives the expected count for each label.
- [x] 10.6 Rerun `cargo test --workspace`, `cargo clippy --workspace --all-targets`, and
  `cargo deny check licenses`. Check: all pass with `proptest` added.

## 11. F2

- [x] 11.1 Add F2 = 5·P·R / (4·P + R) to the micro totals in both variants, as an F2 column
  after F1, and a legend line for it. Check: `#[test_case]` values for `Prf` with exact
  F1 and F2, including P = 1, R = 0.5 → F2 = 5/9, P = 0.5, R = 1 → F2 = 5/6, and P = R = 0.
- [x] 11.2 Verify F2 in every test layer. Check: the golden reports hold F2 values worked out
  by hand, the differential reference computes F2 with its own formula, and the
  end-to-end fixture asserts F2 = 20/29. A wrong β and swapped P and R each fail all four
  layers.
- [x] 11.3 `README.md` and `DEVELOPMENT.md` name F2 beside F1. Check: both name F2.
- [x] 11.4 Rerun `cargo test --workspace` and `cargo clippy --workspace --all-targets`.
  Check: both pass.
