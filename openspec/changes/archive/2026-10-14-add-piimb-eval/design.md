## Context

See `proposal.md` for the motivation and `specs/evaluation/spec.md` for the requirements.

A scratch run already produced the README numbers. It is the reference for this change:

1. A small Rust program read piimb's `data/test_sentences.jsonl`, kept the `ai4privacy-en`
   rows, ran the English scanner with `resolve_overlaps`, and wrote spans in character
   offsets.
2. A Python script loaded piimb's `src/piimb/models.py` and `src/piimb/metrics.py` from
   their files, without `src/piimb/__init__.py`, and called its metric function.

Facts that shape the design:

- piimb sentence offsets are Python code-point offsets, the same unit as Rust `char`.
- `src/piimb/__init__.py` imports `skops`, and the package depends on `torch`,
  `transformers`, `gliner`, `spacy`, and more. `metrics.py` needs only `pydantic`,
  `structlog`, and `nervaluate`; `models.py` needs `pydantic` and
  `pydantic-extra-types` (with `pycountry`), and uses `enum.StrEnum`, so Python 3.11 or
  later.
- `/v1/scan` returns kinds and a count, not spans, so the proxy cannot feed piimb.
- `piimb evaluate` has no pipeline type for an outside engine. A run of this change is
  comparable to a leaderboard row, but it is not a leaderboard submission.
- The leaderboard computes each `Avg` column as the mean of the task values
  (`df[source_cols].mean(axis=1)`), not as F2 of the mean precision and recall.
- At the pinned revision and at `main` (`7d797b9`), `data/test_sentences.jsonl` and
  `src/piimb/metrics.py` are byte-for-byte identical.

## Goals / Non-Goals

**Goals:**

- Reproduce the README's AI4Privacy EN numbers from the repository, exactly.
- Use piimb's metric code as published, so a difference from the leaderboard can only come
  from the predictions.

**Non-Goals:**

- piimb's supplementary NER metrics (nervaluate) and FPR. The report leaves them out.
- The `full_text` subset, the multilingual tasks, and a leaderboard submission.
- A `MAX_ROWS`-style limit. A run takes seconds on the engine side.
- Scanner setups other than the English one, such as the shipped `docker/voidwall.toml`.

## Decisions

### Two steps: Rust writes spans, Python scores them

`piimb-spans` writes a spans file; `crates/voidwall-eval/piimb/score.py` scores it. The
spans file is the only interface between the two.

*Alternatives:* port the metric to Rust (rejected by the user: it can drift from piimb);
install the whole `piimb` package (several GB of ML dependencies, and `piimb evaluate`
cannot call an outside engine anyway).

### `piimb-spans`

- A second `[[bin]]` in `crates/voidwall-eval`, `src/bin/piimb_spans.rs`, with no new
  crate dependency. Today the modules belong to the `ai4privacy-eval` binary
  (`src/main.rs` declares them), so a second binary cannot use them. The crate gains a
  library target, `src/lib.rs`, that declares the modules; both binaries use it.
  *Alternative:* `#[path]` includes of single modules into the second binary — rejected:
  they compile the same file twice and hide the dependency.
- It takes the path of `test_sentences.jsonl` and the task names to keep, streams the file
  line by line, and skips rows of other tasks.
- It builds the scanner with `EvalLanguage::En.build_scanner()`, so its setup is the `en`
  row of the existing scanner table, and it reuses the crate's byte-to-character index.
- It writes one JSON line per kept sentence: `uid`, `task_name`, and `entities`, each with
  `start`, `end`, and `label`. The label is `PiiKind::label()`, for example `EMAIL`. The
  masking metric ignores labels; they make the file readable.
- One thread. The four tasks hold about 121,000 sentences, and the scratch run scored
  18,538 in under one second.

### `score.py` loads two files, not the package

The script creates an empty `piimb` module in `sys.modules`, then loads `piimb.models` and
`piimb.metrics` from their file paths with `importlib.util`. This skips
`piimb/__init__.py` and its heavy imports, and runs the published code unchanged.

- It calls the masking metric function only, once per task, with the ground truth from
  `test_sentences.jsonl` and the spans from `piimb-spans`, paired by position, as piimb
  pairs predictions with rows. A `uid` is not unique in the benchmark: at the pinned
  revision, 1,302 `nemotron-pii` uids occur twice, most with different text. A different
  line count, or a span line whose `uid` and task differ from its row's, stops the run.
- Before it scores a task, it scores the ground truth against itself, and stops the run
  unless precision, recall, F1, and F2 are all 1.0. This self-check runs on every run.
- It prints the report: the revision, one row per task (sentences, F2, F1, P, R), the
  average row for a default run or the "not a full benchmark result" line for a
  `PIIMB_TASK` run, and the legend.
- It runs with `python -I`, and takes every path as an argument.

### `docker/ctl piimb-eval`

1. Check `PIIMB_TASK` against the four tasks, and check that `python3` exists and is 3.11
   or later.
2. Resolve the revision: `PIIMB_REVISION`, or the pinned SHA.
3. Fetch `data/test_sentences.jsonl`, `src/piimb/models.py`, and `src/piimb/metrics.py`
   from `https://huggingface.co/datasets/piimb/pii-masking-benchmark/resolve/<revision>/`
   into `.cache/piimb/<revision>/`, through a `.part` file, as `ai4p-eval` does. Skip a
   file the cache holds.
4. Create `.cache/piimb/venv` once and install the pinned packages. A marker file in the
   venv records the pin list; a second run with the same list installs nothing.
5. Run `cargo run --release -p voidwall-eval --bin piimb-spans`, writing the spans to
   `.cache/piimb/<revision>/voidwall-spans.jsonl`. This runs every time, because the
   engine changes between runs.
6. Run `score.py` with the venv's Python.

`.cache/` is already in `.gitignore`.

### Package pins

The venv installs the versions piimb's `uv.lock` resolves: `nervaluate==1.2.1`,
`pydantic==2.13.3`, `pydantic-extra-types==2.11.1`, `pycountry==26.2.16`, and
`structlog==25.5.0`. The pins live in `docker/ctl`, next to the revision pin. A task checks
that the lock at the pinned revision resolves the same versions.

### Average

For each of F2, F1, precision, and recall, the average is the mean of the four task values,
as on the leaderboard. A `PIIMB_TASK` run prints no average.

## Risks / Trade-offs

- [The run executes code fetched from Hugging Face on the host] → The default revision is
  a commit SHA, so the content is fixed. The script loads two files only, in an isolated
  venv. `PIIMB_REVISION` is an explicit opt-in to other code.
- [Another revision can change the metric code, its imports, or the data format] → The
  self-check and the line-by-line pairing check stop the run with an error instead of
  printing wrong numbers. The package pins can lag behind a new revision; the run then
  fails at import.
- [The benchmark is CC BY-NC 4.0] → The run downloads it to `.cache/` only. The repository
  holds neither data nor piimb code.
- [The numbers depend on the English scanner setup, not on the shipped proxy config] →
  Stated as a non-goal; the README says which engine setup it scores.
- [`score.py` has no automated test; `cargo test` does not run it, and the repository has
  no Python test setup] → Accepted. Every run checks itself: the self-check and the
  line-by-line pairing stop a broken run. The checks of tasks 3.1 and 3.2 were run by
  hand; rerun them after a change to `score.py`.
- [A new host requirement, `python3` 3.11 or later] → Only for this command. The runner
  checks it first and names it in the error.
