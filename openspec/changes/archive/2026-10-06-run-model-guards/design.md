## Context

See proposal.md for why. The current state that shapes the approach:

- `voidwall_ml::load(&LoadSettings)` returns `Vec<Worker>`. `Worker::score(&mut self,
  text)` returns `Result<f32, RunError>`. `RunError::WindowLimit` is a distinct variant.
  No `RunError` carries input text.
- `RegexPiiGuard` owns a `ScannerPool`: N OS threads, a bounded crossbeam channel
  (capacity 4 × N), `send_timeout` of 1 s on the blocking pool, a `oneshot` reply, and a
  `Drop` that closes the channel and joins every thread.
- `Engine::new(&BuiltinGuards)` builds only the PII guard. `AppConfig::load` calls
  `warn_on_model_guards()`.
- `main.rs` builds the engine first, then spawns the admin server, then the listeners, then
  sets the `ready` flag.
- Handlers hard-code `reason="scanner_failure"` for every guard error and count every kind
  in `voidwall_pii_detections_total`.
- `Finding::whole_unit(unit, kind, guard, confidence)` exists.
- `voidwall-ml`'s fixture builder is `#[cfg(test)]`. `Fixture::default()` passes every
  load check, and the token `trigger` makes it score high.

## Goals / Non-Goals

**Goals:**

- A model guard in the same shape as `RegexPiiGuard`, so the engine does not change.
- The status and the metric reason of a guard error come from the error, not from the
  handler.
- Tests that start a real server with a fixture model.

**Non-Goals:**

- Cancelling an abandoned run (S8). An abandoned job keeps its worker until the run ends.
- Batching several units into one inference. Batching hurts on CPU (benchmarks).
- Loading model guards in parallel with each other. Each load already loads its N
  sessions in parallel.
- Changing `voidwall-ml` load or run behaviour.

## Decisions

### 1. Model guard and its pool

New module `crates/voidwall/src/engine/model.rs` with `ModelGuard` and `ModelPool`.

```
detect(units, selected)
  └─► ModelPool::submit(job) ──bounded channel──► worker thread k
                                                    owns voidwall_ml::Worker
                                                    for each selected unit:
                                                      score = worker.score(text)?
                                                      score >= threshold → Finding::whole_unit
  ◄── oneshot reply: Result<Vec<Finding>, Error> ◄──┘
```

- One job per message, holding every selected unit, like `ScanJob`. A worker scores the
  units in order and stops at the first error.
- The channel, the 1 s `send_timeout`, the rate-limited "channel full" log, and the
  `Drop` join copy `ScannerPool`.
- The guard keeps `(kind, Option<threshold>)` for its single label. With no threshold it
  still runs and reports nothing (spec: absence disables the kind).

- Text of a unit: plain text is decoded lossily (U+FFFD for invalid bytes), so one bad
  byte cannot hide a unit. A JSON unit's fragment values are joined with `\n` in offset
  order; keys are left out. API-aware decoders (for example one Anthropic message per
  unit, with a cached verdict) replace this in the decoder phases.

Alternatives:

| Option | Why not chosen |
|---|---|
| Score each JSON value alone, unit score = max | Many small inferences per body, and an attack split across two values is missed. API decoders will choose the unit instead |
| Skip invalid UTF-8, like the PII guard | One invalid byte would bypass the model guard |
| One job per unit, to score the body and the path on two workers | Only matters when a surface admits several units; the default is the body alone. Can come later without a spec change |
| Generic pool shared with `ScannerPool` | The two pools differ in the worker state and in the error type. A generic type now is a refactor of the PII guard, which this change does not need |

### 2. Errors carry their own status and reason

Two new `Error` variants:

| Variant | Status under `fail_close` | Body | `reason` |
|---|---|---|---|
| `Inference { guard, detail }` | 500 | `{"error":"internal error"}` | `inference_failure` |
| `WindowLimit { guard, windows, limit }` | 413 | `{"error":"tokenized content too long to scan"}` | `window_limit` |
| `Scanner(_)` (unchanged) | 500 | `{"error":"internal error"}` | `scanner_failure` |

- A new `Error::scan_reason(&self) -> &'static str` gives the reason. `handle_scan_error`
  (reverse proxy) and `handle_scanner_failure` (API) use it instead of the literal.
- `IntoResponse` gives the status and the fixed body. `guard`, `detail`, `windows`, and
  `limit` go to the log only.
- Every `ModelPool` failure (pool full, dead workers, dropped reply) and every `RunError`
  except `WindowLimit` becomes `Inference`. `RunError::WindowLimit` becomes `WindowLimit`.

Alternative: the handler matches on the guard name to pick the reason. Rejected: it
breaks "add a detector by adding a guard, never by branching inside a handler".

### 3. Configuration

- `threads: Option<usize>` with a semantic rule against 0, like `scanner_threads`.
  `Option<NonZeroUsize>` was tried first: its TOML error shows the line but not the guard
  name the spec asks for. `effective_model_threads` returns `NonZeroUsize`.
- `overlap_tokens: Option<usize>`. Validation calls `voidwall_ml::check_overlap`, so one
  rule lives in one place. The "window longer than overlap" check needs the tokenizer, so
  it stays in the load.
- `text_multilabel_classifier` and a `text_classifier` with `labels.len() != 1` are
  semantic rules in `validate_model_guards`.
- `AppConfig::effective_model_threads(name)`: the set value, or
  `max(1, available_parallelism / guards.len())`. `warn_on_model_guards` is replaced by
  `warn_on_model_thread_total`, which logs once when the sum is above
  `available_parallelism`.

### 4. Engine and startup order

- `Engine::from_config(&AppConfig)` calls `Engine::new(&BuiltinGuards)` (kept, so its test
  callers do not change), then builds each model guard in name order. The
  load uses `LoadSettings { workers: effective_model_threads, max_body_size, overlap_tokens,
  .. }`. A `LoadError` becomes `Error::Config` naming the guard, and startup exits 1.
- The startup sequence moves from `main.rs` into a library function so an integration test
  can drive it:

```
admin binds   (/healthz 200, /readyz 503)
  └─► spawn_blocking(Engine::new)      ← seconds per model guard
        ├─ Err → log with guard name, exit 1
        └─ Ok  → bind data-plane listeners → ready = true (/readyz 200)
```

- `Engine::new` runs on the blocking pool, so the admin server keeps answering during a
  load.
- The test hook is the engine builder: the library function takes a closure that builds
  the engine. The integration test passes one that waits on a channel, probes the admin
  and data ports, then releases it.

Alternative: test the order by hand only. Rejected: the order is a spec requirement.

### 5. PII metrics count only the `pii` guard

`ScanResult::kinds_of(guard)` returns the sorted, distinct kinds of one guard. Handlers
use `kinds_of(BUILTIN_PII_GUARD_NAME)` for `voidwall_pii_detections_total`, and increment
`voidwall_pii_blocked_total` only when that list is not empty. The 403 body and
`/v1/scan` keep `kinds()` over every guard.

### 6. Fixtures for `voidwall` tests

`voidwall-ml` gets a `test-fixtures` feature: `#[cfg(any(test, feature =
"test-fixtures"))] pub mod fixtures;`. `voidwall` enables it in `[dev-dependencies]` only,
so the release binary does not carry it. The integration test writes the fixture model
and tokenizer to a temp dir and configures `labels = ["PROMPT_INJECTION"]`.

### 7. What the integration test proves

| Test | Path |
|---|---|
| Body with `trigger` → 403 `["PROMPT_INJECTION"]`, upstream not reached | real server, fixture model |
| Clean body → forwarded | real server, fixture model |
| `/v1/scan` with `trigger` → `matches_count` 1, `kinds` `["PROMPT_INJECTION"]` | real server, fixture model |
| Admin before load, data plane after | library startup with a held builder |
| Bad model file → exit non-zero, no data port | binary, startup test |
| Window limit → 413 / pass, `window_limit` reason | unit test with a fake guard returning `Error::WindowLimit`, plus a `ModelGuard` test that maps `RunError::WindowLimit` |

A body inside `max_body_size` cannot reach the window limit with the fixture tokenizer (a
token covers at least one byte), so the limit is tested below the server.

## Risks / Trade-offs

- [Startup takes seconds per model guard] → the admin server answers during the load, and
  `/readyz` tells an orchestrator when to route traffic.
- [An abandoned run keeps its worker busy] → S8 adds cancellation. Until then a slow unit
  under load fills the queue and later requests get `inference_failure` after 1 s.
- [ONNX Runtime error text reaches the log] → it sees token IDs, never text (S6). The text
  never reaches a response body or a metric label.
- [The even thread split cannot lend an idle guard's CPU to a busy one] → accepted in #8;
  the operator sets `threads` per guard.
- [`labels` on a model with reversed class order fails open] → not checkable at startup
  (#1). Docs state the class order `text_classifier` expects.

## Migration Plan

- The default image declares no model guard, so it behaves as before.
- A deployment that already declared `[guards.<name>]` now loads the model at startup and
  blocks on findings. The model and tokenizer files must exist (already checked) and pass
  the load checks. Rollback: remove the section or the guard from the route's `guards`.
- Dashboards that read `voidwall_pii_detections_total` see no change while only the `pii`
  guard runs.

## Open Questions

- Should a model guard whose only label has no threshold skip loading its model? It
  reports nothing either way. Answering it later changes neither spec nor tasks.
