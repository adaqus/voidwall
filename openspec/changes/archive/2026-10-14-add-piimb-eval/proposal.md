## Why

`docker/ctl ai4p-eval` scores the regex engine with its own rules on one dataset. Its
numbers cannot stand next to published PII detectors. The PII Masking Benchmark (piimb)
publishes a leaderboard of 35 models, with a public test set and public metric code. A
one-off scratch run of the engine on its AI4Privacy EN task gave F2 0.464, P 0.962, R 0.411,
and the README now states those numbers. Nothing in the repository can reproduce them.

## What Changes

- Add `docker/ctl piimb-eval`. It scores the `voidwall-pii` regex engine on the four
  English piimb tasks — `ai4privacy-en`, `gretel`, `nemotron-pii`, and `privy` — on the
  `sentences` subset, the way the piimb leaderboard scores a model.
- Add a second binary, `piimb-spans`, to `crates/voidwall-eval`. It runs the English
  scanner of `voidwall-eval` on each sentence, passes the matches through
  `voidwall_pii::resolve_overlaps`, and writes the spans in character offsets.
- Score the spans with piimb's own `metrics.py`, unmodified, at the benchmark revision of
  the run. It runs in a Python virtual environment under `.cache/`, so the host needs
  `python3`.
- The report gives F2, F1, precision, and recall per task, then the simple average of each
  over the four tasks, as the leaderboard computes it, and ends with a legend.
- Pin the benchmark revision to `5f47fff823b3fd7138cfed39e25ca24af8549e25`, the revision of
  30 of the 35 leaderboard results. `PIIMB_REVISION` overrides it.
- `PIIMB_TASK` scores one of the four tasks only.
- Document it: `README.md` (Evaluation section, and the source of the PII numbers it
  states), `DEVELOPMENT.md` (`docker/ctl` table row), `AGENTS.md`, and `ARCHITECTURE.md`
  (the second binary of `crates/voidwall-eval`).

## Capabilities

### New Capabilities

None.

### Modified Capabilities

- `evaluation`: adds the piimb evaluation of the regex engine and its `docker/ctl
  piimb-eval` runner. The capability comes from the change `add-ai4privacy-eval`, which is
  not archived yet; this change adds requirements only and changes none of that change's
  requirements.

## Impact

- **`crates/voidwall-eval`:** a second `[[bin]]`, `piimb-spans`. No new crate dependency.
- **`docker/ctl`:** a new `piimb-eval` subcommand. Other subcommands are unchanged.
- **New host requirement for this command only:** `python3`. The other commands do not
  need it.
- **Python packages:** installed into the virtual environment under `.cache/`, never into
  the host Python and never into the image.
- **Benchmark data and code:** licensed CC BY-NC 4.0. They are fetched at run time into
  `.cache/` and never committed.
- **Docs:** `README.md`, `DEVELOPMENT.md`, `AGENTS.md` (`CLAUDE.md` links to it), and
  `ARCHITECTURE.md`.
- **Unchanged:** the proxy, its API, its configuration, its metrics, the `voidwall-pii`
  public API, the image, and `docker/ctl ai4p-eval`.
- **Order:** archive `add-ai4privacy-eval` before this change, because it creates the
  `evaluation` capability and the `voidwall-eval` crate.
