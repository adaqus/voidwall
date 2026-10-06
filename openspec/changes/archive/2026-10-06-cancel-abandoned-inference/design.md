## Context

See proposal.md for why. The current state that shapes the approach:

- `Worker::score(&mut self, text)` tokenizes, cuts windows, and calls `infer` per window.
  `infer` calls `self.session.run(inputs)`. The load's smoke inference also calls `infer`.
- `ModelPool` threads loop on `rx.recv()` and always send `score_job(..)` on the
  `oneshot`. `score_job` stops at the first `RunError`.
- `Engine::guard` drops `in_flight` after a block. Today that drops the guard future and
  its `oneshot::Receiver`; the worker runs on and its `send` fails silently.
- `ort` 2.0.0-rc.13: `RunOptions::new() -> Result`, `terminate(&self) -> Result`,
  `RunOptions<NoSelectedOutputs>` is `Send + Sync`, `Session::run_with_options(inputs,
  &RunOptions)`. A terminated run returns an `Err` whose only marker is its message text.
- Measured stop lag ≤ 43 ms (Wolf fp32, 2048 tokens); a flag set before the run returns
  in 0.06 ms (`cancel-abandoned-inference-research.md`).

## Goals / Non-Goals

**Goals:**

- A cancelled run cannot be confused with a failure, by construction: no `Error` variant
  for it in `voidwall`.
- No lost cancel: a cancel that lands between a check and the next inference still stops
  that inference.

**Non-Goals:**

- Deadlines. A later phase may reuse `Cancel`; this change does not decide it.
- The regex PII guard. A regex scan is short; it is not cancelled.
- Reusing `RunOptions` across jobs with `unterminate`. Each job gets fresh options.

## Decisions

### D1. `Cancel` in `voidwall-ml` (agreed with the user)

```rust
// crates/voidwall-ml/src/run.rs
pub struct Cancel {
    options: RunOptions,        // NoSelectedOutputs: Send + Sync
    cancelled: AtomicBool,
}
impl Cancel {
    pub fn new() -> Result<Self, RunError>;   // RunOptions::new() failure → RunError::Inference
    pub fn cancel(&self);                     // flag (Release), then options.terminate()
    pub fn is_cancelled(&self) -> bool;       // Acquire
}
Worker::score(&mut self, text: &str, cancel: &Cancel) -> Result<f32, RunError>
RunError::Cancelled
```

- Test-only hook: `Worker::cancel_after: Option<usize>` (`#[cfg(test)]`) cancels the run
  once that many inferences have returned, so a test lands a cancel between two windows
  without timing.

- `score` checks `is_cancelled()` before it tokenizes and before each window, and returns
  `RunError::Cancelled`. `infer` runs `run_with_options(inputs, &cancel.options)`.
- An `Err` from `run_with_options` is `Cancelled` when `is_cancelled()` is true, else
  `Inference`. This avoids matching ONNX Runtime's message text.
- Order in `cancel()`: flag first, then `terminate()`. ONNX Runtime's terminate flag is
  sticky, so a cancel between the last check and `run_with_options` still stops the run
  at its first node. `terminate()`'s `Result` is ignored: the flag alone still stops the
  next window, and there is nothing useful to do with the error in a `Drop`.
- The smoke inference passes a `Cancel` nobody cancels.
- `Cancel` is not `Clone`; callers share it through `Arc`.

Alternative rejected: `score(text, &RunOptions, abandoned: impl Fn() -> bool)` with
`voidwall` passing `|| reply_tx.is_closed()`. Two cancel inputs that must agree, and a
`voidwall-ml` test cannot drive it without a channel.

### D2. Model guard: cancel on drop, skip closed jobs

```
detect()                                  worker thread
  cancel = Arc::new(Cancel::new()?)         recv (job, reply_tx)
  _armed = CancelOnDrop(cancel.clone())     reply_tx.is_closed()? → skip, next job
  submit(job{.., cancel}).await             for each unit: worker.score(text, &job.cancel)
  ── engine drops future ──►                  Cancelled → stop, send nothing, next job
     CancelOnDrop::drop → cancel.cancel()     Ok/Err    → as today
```

- `ModelJob` gains `cancel: Arc<Cancel>`. `Cancel::new()` failing in `detect` is an
  `Error::Inference` for that guard, like any other runtime failure.
- `CancelOnDrop` is a small struct whose `Drop` calls `cancel()`. It lives inside the
  `async move` block, so it drops with the future. On normal completion it also fires;
  the job is done, so that cancel touches nothing.
- `run_error` returns `Option<Error>`: `None` for `RunError::Cancelled`. It lists every
  `RunError` variant with no catch-all, so a new variant must be mapped there by hand.
  `score_job` maps through it and returns `Option<Reply>`: `None` for a cancelled job.
  The thread sends only `Some`. So a cancelled run never becomes an `Error`, never
  reaches `voidwall_errors_total`, and the worker writes no log for it. No `Error`
  variant is added.
- The `is_closed()` check runs before the first unit, as agreed. Inside the job the
  `Cancel` flag covers the rest; it is set in the same `Drop` that closes the receiver.

### D3. A slow fixture for timing tests

`Fixture` gains `slow: Option<usize>`: a chain of that many `MatMul` nodes over the
embedding output (so it depends on the input and is not constant-folded), with an identity
weight so values stay finite, reduced and multiplied by 0 before it is added to the
logits. Scores do not change; only run time grows with the chain length.

Tests size the chain so one full run takes about 1 s on one intra-op thread, and assert
with wide margins: a cancel at about half the run returns `Cancelled` in under a quarter
of the full run time. One node is a small fraction of that, so the bound proves
"stopped at a node boundary" without depending on exact timing.

The timing tests assert the stop lag only. Which window a cancel at T/2 lands in depends
on timing: under parallel load the measured run is slower than the cancelled one. That no
window starts after a cancel is tested with the D1 hook instead.

## Risks / Trade-offs

- [Timing tests flake on a loaded CI machine] → Ratios against a full run measured in the
  same test, not absolute times; margins of 4× or more.
- [ORT optimizes the slow chain away] → Fixture test asserts a full run takes at least a
  set fraction of the target time; if the optimizer removes the chain, that test fails
  first and points at the fixture.
- [`Worker::score` signature change] → Only caller is `voidwall`'s model guard and the
  parity harness; both change in this diff.
- [A cancel that arrives after the last window] → The run already has its score; the
  result is discarded because the receiver is gone. No harm.
