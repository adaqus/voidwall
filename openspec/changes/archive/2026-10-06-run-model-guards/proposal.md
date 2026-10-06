## Why

S5 and S6 load a model into N checked workers and let a worker score one unit, but
nothing in `voidwall` runs them. A `[guards.<name>]` section still only parses and logs
"configured but not executed". This change wires the workers into a guard, so a
configured model guard inspects traffic and its findings block like any other guard's.

## What Changes

- New model guard in `voidwall`, one per `[guards.<name>]` section. It owns a worker pool
  in the shape of `ScannerPool`: N OS threads, each owning one `voidwall_ml::Worker`, a
  bounded channel for requests and a `oneshot` for replies.
- Scores become findings: a unit whose score is at or above a label's threshold gives one
  finding of that kind, with no span and the unit score as its confidence. A label with no
  threshold gives no finding (already specified).
- New optional `threads` field per model guard (#8):
  - The number of workers. Default: available CPUs ÷ number of model guards, at least 1.
  - `threads = 0` fails validation.
  - When the sum of all model guards' threads is above the CPU count, startup logs one
    warning and continues. PII scanner threads are not in that sum.
- New optional `overlap_tokens` field per model guard (#2). Validation uses the same bound
  as `voidwall_ml::check_overlap`: at most `max_tokens / 2`. Absent means the
  `voidwall-ml` default.
- Errors (#10):
  - A runtime failure of a model guard (pool full, worker died, tokenizer error, ONNX
    Runtime error, invalid output) follows `on_error`, answers 500 under `fail_close`, and
    counts as `reason="inference_failure"`.
  - A unit past the window limit follows `on_error`, answers 413 under `fail_close`, and
    counts as the new `reason="window_limit"`. Its body is the fixed
    `{"error":"tokenized content too long to scan"}`. This holds in the reverse proxy and in
    `/v1/scan`.
- `text_multilabel_classifier` fails config validation, so `--validate` also rejects it.
- Startup order:
  - The admin server binds first. `/healthz` answers 200, `/readyz` answers 503.
  - The engine then builds every guard; model guards load in this step.
  - The data-plane listeners bind only after every guard loaded. `/readyz` then answers
    200.
  - A load failure stops the start with a non-zero exit.
- `--validate` stays offline: it does not load a model.
- **BREAKING** (spec only): removes "Model guard settings parse but the guard does not
  run" and the "configured but not executed" warning. A configured model guard now runs.
- Fixes the `labels` rule for `text_classifier` (#1): exactly one label, and it names
  class 1, not output position 0.
- The 403 `error` text becomes `content blocked` (was `PII detected`), because a model
  guard can cause the block too. The status, the `kinds` array, and the headers do not
  change.
- PII metrics count PII only: `voidwall_pii_detections_total` counts only the kinds the
  built-in `pii` guard found, and `voidwall_pii_blocked_total` counts only a 403 that a
  `pii` finding caused. A model guard shows in `voidwall_detections_total` and
  `voidwall_blocked_total`.
- `voidwall-ml` exposes its in-code fixture builder under a `test-fixtures` cargo feature,
  so `voidwall`'s integration tests can write a fixture model and tokenizer to a temp dir.

Out of scope: cancelling an abandoned inference (S8). Without it, an abandoned run keeps
its worker busy until the run ends.

## Capabilities

### New Capabilities

None.

### Modified Capabilities

- `guard-configuration`: a model guard runs; `threads` and `overlap_tokens` fields; the
  `labels` rule for `text_classifier`; removes "parses but does not run".
- `configuration`: validation of `threads`, `overlap_tokens`, and the multilabel adapter;
  the thread-total warning; removes "no model guard runs"; a model load failure stops the
  start; `--validate` does not load models.
- `admin-server`: the admin server binds before the guards load; `/readyz` answers 503
  until the guards loaded and the listeners bound.
- `reverse-proxy`: a window-limit error under `fail_close` answers 413; a model guard
  detection blocks with the fixed 403.
- `http-api`: a window-limit error follows `on_error` (413 under `fail_close`); a
  model guard finding counts as one match.
- `metrics`: new `voidwall_errors_total` reasons `inference_failure` and `window_limit`;
  a model guard's detection increments `voidwall_detections_total` with its name; the
  `voidwall_pii_*` families count only the `pii` guard's findings.

## Impact

- Code:
  - `crates/voidwall/src/engine/`: new model guard module and its worker pool;
    `Engine::new` takes the model guards.
  - `crates/voidwall/src/config.rs`: new fields and rules; the "not executed" warning goes.
  - `crates/voidwall/src/error.rs`: error variants for an inference failure and a window
    limit, so the handlers pick status and reason.
  - `crates/voidwall/src/reverse_proxy.rs`, `http_api.rs`: map the two errors to status
    and reason.
  - `crates/voidwall/src/main.rs`: admin server first, engine next, listeners last.
  - `crates/voidwall-ml/`: `test-fixtures` feature; no change to load or run behavior.
- Tests: unit tests for config rules and the guard; integration test with a real server
  and a fixture model that answers 403 `PROMPT_INJECTION`.
- Docs: `docker/voidwall.toml` (the comment on the commented model guard), `ARCHITECTURE.md` §4.8 and §5, `docs/config-validation.md`, `docs/openapi.json`
  if the 413 and 500 descriptions name only the scanner.
- Operator-visible: a configured model guard now loads at start (seconds per guard) and
  blocks traffic. The image ships no model guard, so the default image is unchanged.
