## 1. Engine

- [x] 1.1 In `engine/mod.rs` `test_guard`, add a `TestGuard` builder that makes `detect`
  return `Error::Scanner`, after the optional delay. Verify: it compiles, and the existing
  engine tests still pass.
- [x] 1.2 Add engine unit tests:
  - A failing guard and a slower guard that reports a finding under
    `BlockPolicy::AnyFinding`: the result holds the finding and carries the error.
  - The same pair under `BlockPolicy::Never`: the result holds the finding and carries
    the error.
  - A failing guard alone, and a failing guard with a guard that reports nothing: no
    finding, and the result carries the error.
  - Two failing guards: the result carries one error.

  Verify: the tests fail (or do not compile) before 1.3.
- [x] 1.3 In `engine/finding.rs`, add `error: Option<Error>` to `ScanResult`, with an
  accessor that takes it out. Remove the `Clone` derive. Verify: `cargo check -p voidwall`
  passes after 1.4.
- [x] 1.4 In `engine/mod.rs`, `Engine::guard` returns `ScanResult`. The loop keeps the
  first error, writes each later error to the log with the guard name through
  `SCANNER_ERROR_LIMITER`, and continues. It stops on a blocking batch only. Update the
  doc comment. Verify: the tests from 1.2 pass, and so do the existing engine tests.

## 2. Reverse proxy

- [x] 2.1 Add unit tests in `reverse_proxy.rs` over `Engine::with_guards` with a failing
  guard and a guard that reports a finding:
  - Under `fail_open` and under `fail_close`: the answer is 403 naming the kind, and
    `voidwall_errors_total{outcome="blocked",reason="scanner_failure"}` increments by one.
  - A failing guard alone under `fail_open`: the message passes. Under `fail_close`: 500
    with the body `{"error":"internal error"}`.

  Verify: the tests fail before 2.2.
- [x] 2.2 In `run_engine`, apply the order from design.md: a finding blocks. When the
  result also carries an error, write the rate-limited `warn!` and increment the error
  counter with `outcome="blocked"`. Otherwise an error goes to `handle_scan_error`.
  Verify: the tests from 2.1 pass.

## 3. REST API

- [x] 3.1 Add unit tests in `http_api.rs` over `Engine::with_guards` with a failing guard
  and a guard that reports a finding:
  - `fail_open`: 200 with a report holding the finding, and the error counter increments
    with `outcome="passed"`.
  - `fail_close`: 500 with the body `{"error":"internal error"}`, and the detection
    counter increments for the found kind.

  Verify: the tests fail before 3.2.
- [x] 3.2 In the `/v1/scan` handler, apply the order from design.md. Under `fail_close`,
  increment the detection counter for each kind found, then answer the fixed 500. Under
  `fail_open`, increment the error counter with `outcome="passed"`, then build the report
  from the findings. Verify: the tests from 3.1 pass, and the existing http-api
  integration tests still pass.

## 4. Checks

- [x] 4.1 Run `cargo test --workspace`. Verify: all tests pass.
- [x] 4.2 Run `cargo clippy --workspace --all-targets`. Verify: no warnings.
- [x] 4.3 Run `openspec validate guard-error-does-not-end-scan --strict`. Verify: it
  passes.
