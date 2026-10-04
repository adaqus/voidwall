## Context

See proposal.md (Why). `Engine::guard` returns `Result<ScanResult, Error>`, and the first
guard error returns `Err` at once. Two callers exist:

- `reverse_proxy::run_engine` passes `BlockPolicy::AnyFinding`. On `Err` it writes a
  rate-limited `warn!` and calls `handle_scan_error`.
- The `/v1/scan` handler in `http_api.rs` passes `BlockPolicy::Never`. On `Err` it writes a
  rate-limited `warn!` and calls `handle_scanner_failure`.

The forward proxy does not call the engine. Only one real guard exists (regex PII), so the
two-guard cases can only be tested with the test guard in `engine::test_guard`.

## Goals / Non-Goals

**Goals:**

- The engine returns the findings of the guards that succeeded together with the error.
- Each caller decides the outcome: a block first, then `on_error`.

**Non-Goals:**

- The `inference_failure` error reason. It comes with the model guards (S7).
- A change to the `on_error` that the engine passes to each guard.
- A guard name in the error log line of the handlers.

## Decisions

### `ScanResult` carries the error

`Engine::guard` returns `ScanResult`, not `Result`. `ScanResult` gets an
`error: Option<Error>` field and an accessor that takes the error out.

- Rejected: a new `GuardOutcome { result, error }` struct. It adds a second type for the
  callers to unpack.
- Rejected: `Result<ScanResult, ScanFailure { error, partial }>`. The findings then live
  in two places, and a caller must read both branches.

`Error` is not `Clone` (it holds `std::io::Error`), so `ScanResult` loses its `Clone`
derive. Nothing clones a `ScanResult` today.

### The first error is returned; later errors go to the log

The engine keeps the first guard error. It writes each later error to the log with the
guard name, through `SCANNER_ERROR_LIMITER`. So one message increments the error metric
once.

### The engine loop

The loop stops on a blocking batch only. An `Err` batch is stored (the first) or logged
(a later one), and the loop continues. The short-circuit rule does not change.

### The caller order

Reverse proxy `run_engine`:

1. When the result has a finding, block as today. If it also carries an error, write the
   `warn!` and increment `voidwall_errors_total{outcome="blocked",reason="scanner_failure"}`.
2. Otherwise, when it carries an error, call `handle_scan_error` as today.
3. Otherwise, pass.

`/v1/scan` handler:

1. When the result carries an error, write the `warn!`.
   - `fail_close`: increment the detection counter for each kind found, then answer the
     fixed 500 (`handle_scanner_failure`).
   - `fail_open`: increment `voidwall_errors_total{outcome="passed"}`, then build the
     report from the findings as on the normal path.
2. Otherwise, answer as today.

### Tests

`TestGuard` gets a builder that makes `detect` return `Error::Scanner`. Engine unit tests
cover the error + finding and error-alone cases. The handler cases need a second guard, so
they are unit tests in `reverse_proxy.rs` and `http_api.rs` over `Engine::with_guards`. An
integration test cannot reach the `#[cfg(test)]` test guard.

## Risks / Trade-offs

- [Under `fail_close`, a message with a guard error waits for the slowest guard] →
  Accepted in decision #10. The block from a slow guard is the point of the wait.
- [A handler unit test needs a router state built over a test engine] → Build the state
  directly in the test module. If the state cannot be built without a config file, add a
  `#[cfg(test)]` constructor next to the existing one.
