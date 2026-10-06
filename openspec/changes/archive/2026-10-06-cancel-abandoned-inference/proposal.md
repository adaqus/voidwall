## Why

When the engine abandons a model guard (another guard's finding blocks the message), the
guard's ONNX run keeps its worker thread busy until the run ends: up to 6.4 s for one
2048-token Wolf window, and longer for a unit with many windows. Queued jobs of abandoned
messages also still run. `ort` 2.0.0-rc.13 can stop a run from another thread
(`RunOptions::terminate`, measured stop lag ≤ 43 ms), so an abandoned run can give its
worker back at once (#12).

## What Changes

- `voidwall-ml` exposes a `Cancel` handle: one `RunOptions` and a cancelled flag.
  `Cancel::cancel()` sets the flag and calls `RunOptions::terminate()`. It is `Send + Sync`,
  so another thread can call it through an `Arc`.
- `Worker::score` takes a `&Cancel`. It checks the flag before it tokenizes and before
  each window, and runs each window with `run_with_options` on the handle's `RunOptions`.
  A cancelled score returns the new `RunError::Cancelled`.
- Each model guard job carries its own `Arc<Cancel>`. Dropping the guard future (the
  engine abandons it) calls `cancel()`.
- A worker skips a job whose reply channel is already closed, before it scores the first
  unit, and stops scoring the job's remaining units once the job is cancelled.
- A cancelled run is not a failure: no `inference_failure`, no `voidwall_errors_total`
  increment, no error log. The worker discards the result and takes the next job.
- A cancelled session runs the next job normally; each job uses fresh options.

Out of scope: deadlines (the *Policy, Errors, and Deadlines* phase). Whether a deadline
uses the same mechanism is not decided here. The regex PII guard is unchanged.

## Capabilities

### New Capabilities

None.

### Modified Capabilities

- `model-runtime`: a score can be cancelled from another thread; an abandoned model guard
  cancels its run and frees its worker; a cancelled run is not a failure.

## Impact

- `crates/voidwall-ml/src/run.rs`: `Cancel`, `RunError::Cancelled`, `Worker::score`
  signature, `infer` uses `run_with_options`. Public API change inside the workspace; the
  only caller is `voidwall`'s model guard. The load's smoke inference runs with options
  that are never cancelled.
- `crates/voidwall-ml/src/fixtures.rs`: a slow fixture model, so a test can cancel a run
  in progress.
- `crates/voidwall/src/engine/model.rs`: job carries `Arc<Cancel>`, drop guard in
  `detect`, worker skip checks.
- `ARCHITECTURE.md`: §4.3 (abandoned guard) and §4.8 / the `voidwall-ml` section.
- No new dependency, config field, metric, or error code.
