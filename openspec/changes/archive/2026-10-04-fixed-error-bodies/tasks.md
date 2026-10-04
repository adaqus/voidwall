## 1. Tests first

- [x] 1.1 In `crates/voidwall/src/error.rs`, change the `into_response` test cases:
  `Error::Config("msg")` and `Error::Scanner("msg")` expect the body `internal error`,
  and `Error::Proxy("msg")` expects `upstream error`. `into_response_io` also checks
  the body `upstream error`. Verify: `cargo test -p voidwall error::tests` fails
  before 2.1.
- [x] 1.2 In `crates/voidwall/tests/reverse_proxy_integration.rs`,
  `scanner_failure_fail_close_answers_500` also asserts that the body is exactly
  `{"error":"internal error"}`. Verify: the test fails before 2.1.
- [x] 1.3 In the same file, `upstream_unreachable_answers_502` also asserts that the body
  is exactly `{"error":"upstream error"}`. Verify: the test fails before 2.1.
- [x] 1.4 In `crates/voidwall/tests/http_api_integration.rs`,
  `scanner_failure_fail_close_returns_500` also asserts that the body is exactly
  `{"error":"internal error"}`. Verify: the test fails before 2.2.

## 2. Fixed bodies

- [x] 2.1 In `error.rs`, add one constant for `internal error` and one for
  `upstream error`. The `Config` and `Scanner` arms of `IntoResponse for Error` answer
  the first, and the `Proxy` and `Io` arms answer the second. No arm reads the error
  details. `Display` stays as it is. Verify: tests 1.1 to 1.3 pass, and the `display`
  test still passes.
- [x] 2.2 In `http_api.rs`, `handle_scanner_failure` builds its 500 body from the
  `internal error` constant. Verify: test 1.4 passes.
- [x] 2.3 In `reverse_proxy.rs`, `buffer_body` writes an `error!` line with the read
  error before it returns the 502. Verify: the code review confirms that every
  `Error::Proxy` and `Error::Io` response in `reverse_proxy.rs` has a log line before it.

## 3. Checks

- [x] 3.1 Run `cargo test --workspace`. Verify: all tests pass.
- [x] 3.2 Run `cargo clippy --workspace --all-targets`. Verify: no warnings.
- [x] 3.3 Run `openspec validate fixed-error-bodies --strict`. Verify: it passes.
