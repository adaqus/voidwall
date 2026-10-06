## 1. Slow fixture (D3)

- [x] 1.1 Add `slow: Option<usize>` to `Fixture`: a chain of input-dependent `MatMul` nodes with an identity weight, reduced, multiplied by 0, and added to the logits. Verify: a `voidwall-ml` test — the slow fixture loads, gives the same score as `Fixture::default()` on the same text, and one full run takes at least 4× as long as a run on the default fixture.

## 2. `Cancel` in `voidwall-ml` (model-runtime; D1)

- [x] 2.1 Add `Cancel` (`new`, `cancel`, `is_cancelled`) and `RunError::Cancelled`; change `Worker::score` to take `&Cancel`, check the flag before tokenizing and before each window, and run each window with `run_with_options`; map a run `Err` to `Cancelled` only when the flag is set. Pass an uncancelled `Cancel` in the smoke inference, the existing `run.rs` tests, and `parity.rs`. Verify: `cargo test -p voidwall-ml` passes unchanged otherwise; a compile-time assertion that `Cancel: Send + Sync`.
- [x] 2.2 Test "Cancelled before the run". Verify: cancel, then `score` → `RunError::Cancelled`, and the `inferences` counter is 0.
- [x] 2.3 Test "Cancelled during an inference" on the slow fixture with a multi-window unit. Verify: measure a full run T; a second thread cancels at about T/2; `score` returns `Cancelled` in under T/4 after the cancel. Which window the cancel lands in is timing-dependent and is not asserted (see 2.5).
- [x] 2.4 Test "The session runs again after a cancel". Verify: after a cancelled run, the same worker with a new `Cancel` scores a unit equal to the score from a fresh worker.
- [x] 2.5 Test "Cancelled between windows" with the test-only `Worker::cancel_after` hook. Verify: `cancel_after = Some(1)` on a three-window unit → `RunError::Cancelled` and `inferences == 1`; the test fails when the per-window check in `score` is removed.

## 3. Model guard cancels on drop (model-runtime; D2)

- [x] 3.1 Add `cancel: Arc<Cancel>` to `ModelJob`, a `CancelOnDrop` held inside the `detect` future, the `reply_tx.is_closed()` check before a job's first unit, and a `score_job` result that is `None` for a cancelled job (the thread then sends nothing and logs nothing). `Cancel::new()` failure → `Error::Inference`. `run_error` returns `None` for `Cancelled` and lists every `RunError` variant with no catch-all. Verify: existing `engine/model.rs` tests pass; test `a_cancelled_run_maps_to_no_error`.
- [x] 3.2 Test "A block abandons a long inference". Verify: a one-thread guard on the slow fixture; start `detect` on a long unit, drop the future at about T/2, then `detect` a short unit; the short unit's result arrives in under T/4 after the drop.
- [x] 3.3 Test "A queued job of an abandoned message". Verify: a one-thread guard busy with a long job; a second `detect` is queued then dropped; after the first job ends, the worker's `inferences` (or an equivalent test counter) shows the queued job ran no inference.
- [x] 3.4 Test "A cancelled run is not counted as an error". Verify: an engine-level test with a fake blocking guard and the slow model guard under `fail_close` → the result holds the block and no error; a reverse proxy integration test (`model_guard_integration.rs`) with `pii` blocking and a slow model guard → 403, `voidwall_errors_total` unchanged, and the next request answers in under T/4.

## 4. Docs and checks

- [x] 4.1 Update `ARCHITECTURE.md`: §4.3 (an abandoned model guard cancels its run; the worker is freed within one graph node) and the `voidwall-ml` section (`Worker::score` takes a `Cancel`). Verify: `grep -n "runs to completion" ARCHITECTURE.md crates/voidwall/src/engine/mod.rs` finds no stale claim; the comment at `engine/mod.rs` "The worker behind an abandoned future runs to completion" is updated.
- [x] 4.2 Run `cargo test --workspace` and `cargo clippy --workspace --all-targets`. Verify: both pass with no warnings.
