## 1. Crate layout

- [x] 1.1 Move the module declarations of `crates/voidwall-eval` into a library target,
  `src/lib.rs`, and make `src/main.rs` use it. No behavior change. Check:
  `cargo test -p voidwall-eval` passes with the same test count, and
  `AI4P_LANG=en SUPPORTED_ONLY=1 MAX_ROWS=200 docker/ctl ai4p-eval` prints the same report
  as before.

## 2. Span exporter

- [x] 2.1 Add the `piimb-spans` binary: arguments are the `test_sentences.jsonl` path and
  the task names; it streams rows, keeps the named tasks, runs
  `EvalLanguage::En.build_scanner()` with `resolve_overlaps`, and writes `uid`,
  `task_name`, and `entities` (`start`, `end`, `label`) in character offsets. Check: unit
  tests for a row of another task (skipped), multi-byte text before a detected value
  (character offset), two overlapping matches (resolved set only), and an output line
  that holds no text of the sentence.
- [x] 2.2 Check: the spans of `ai4privacy-en` at the pinned revision equal the scratch
  run's spans, line for line.

## 3. Scorer

- [x] 3.1 Add `crates/voidwall-eval/piimb/score.py`: load `piimb.models` and
  `piimb.metrics` from their files without `piimb/__init__.py`; pair spans with rows by
  position, as piimb does, and stop on a different line count or a line whose `uid` and
  task differ from its row's; run the self-check (ground truth against itself scores 1.0)
  for each task; score each task with the masking metric function. Check: a run on a
  spans file with one line removed stops with a non-zero status, a run with two lines
  swapped stops with a non-zero status, and a run where the spans equal the ground truth
  prints 1.000 in every column.
- [x] 3.2 Print the report: the revision, one row per task (sentences, F2, F1, P, R), the
  average row (mean of the task values) or, for a `PIIMB_TASK` run, the line that says it
  is not a full benchmark result, then the legend. Check: on the default run, each average
  equals the mean of the four printed task values; the report holds no sentence text.

## 4. Runner

- [x] 4.1 Add `docker/ctl piimb-eval`: header comment for `PIIMB_REVISION` and
  `PIIMB_TASK`; the `PIIMB_TASK` check; the `python3` 3.11+ check; the revision pin; the
  fetch of the three files into `.cache/piimb/<revision>/` through `.part` files, skipping
  cached ones; the venv in `.cache/piimb/venv` with the package pins and a marker file;
  `piimb-spans`, then `score.py`. Add `piimb-eval` to the usage line and the dispatch.
  Check: `PIIMB_TASK=mapa-eur-lex docker/ctl piimb-eval` exits non-zero and names the four
  tasks; a second run fetches and installs nothing; with `python3` hidden from `PATH` the
  run exits non-zero and names `python3`.
- [x] 4.2 Check that piimb's `uv.lock` at the pinned revision resolves the pinned versions
  of `nervaluate`, `pydantic`, `pydantic-extra-types`, `pycountry`, and `structlog`.
  Check: the five versions match.

## 5. Results

- [x] 5.1 Default run at the pinned revision. Check: the `ai4privacy-en` row gives F2
  0.464, F1 0.576, P 0.962, R 0.411; all four tasks and the average row print; exit
  status 0.
- [x] 5.2 `PIIMB_TASK=privy docker/ctl piimb-eval`. Check: one row, no average, and the
  "not a full benchmark result" line.

## 6. Documentation

- [x] 6.1 `README.md`: in the Evaluation section, add `docker/ctl piimb-eval` with an
  example command, what it measures, that it needs `python3`, and that the PII numbers in
  the guard list come from its `ai4privacy-en` row. Check: the example runs as written.
- [x] 6.2 `DEVELOPMENT.md`: a `docker/ctl piimb-eval` row naming `PIIMB_REVISION`,
  `PIIMB_TASK`, and the `python3` requirement. Check: the row matches the header comment in
  `docker/ctl`.
- [x] 6.3 `AGENTS.md` and `ARCHITECTURE.md`: name `piimb-spans` as the second binary of
  `crates/voidwall-eval` and say what it is for. Check: both name it.

## 7. Verification

- [x] 7.1 `cargo test --workspace` and `cargo clippy --workspace --all-targets` with no
  warnings. Check: both pass.
- [x] 7.2 `cargo deny check licenses`. Check: it passes.
- [x] 7.3 Review the diff against the spec delta with the `code-review` skill. Check: no
  open findings.
