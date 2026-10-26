## 1. Bind error

- [x] 1.1 Add `Listener` (`Admin`, `ReverseProxy`, `HttpApi`) and `Error::Bind { listener,
  addr, source }` to `crates/voidwall/src/error.rs` (D2). Give `Bind` an arm in every
  match: the 500 arm with the fixed body. Verify: `cargo check --workspace` passes.
- [x] 1.2 Add unit tests in `error.rs`: the Display of each listener reads
  `<listener> could not bind <addr>: <source>`, `source()` returns the I/O error, and the
  response is the fixed 500 body. Verify: `cargo test -p voidwall error` passes.

## 2. Bind in `run`

- [x] 2.1 Split `admin::serve`, `reverse_proxy::serve`, and `http_api::serve` into a
  `serve_on(listener, ...)` that only serves, and a `serve(&config, ...)` that binds and
  calls it (D1). Verify: the integration tests that call `serve` pass unchanged.
- [x] 2.2 In `server::run`, bind the admin listener before the guard build and each
  enabled data-plane listener after it. On a bind error, cancel the token and return
  `Error::Bind` (D1, D3). Verify: `cargo check --workspace` passes.
- [x] 2.3 Set the readiness flag in `run` after the last data-plane bind, and remove the
  `yield_now` task and its comment (D4). Verify: the existing test that `/readyz` answers
  503 while the guards load and 200 after it passes.
- [x] 2.4 Log an `Err` from `server::run` in `main.rs` as `failed to start` (D5). Verify:
  `grep "failed to initialize detection engine" crates/` finds no match.

## 3. Tests of the spec delta

- [x] 3.1 In `admin_integration.rs`, hold a listener on an address, give that address to
  `reverse_proxy.listen`, and call `server::run`. Verify: it returns `Error::Bind` naming
  the reverse proxy and that address, and the admin server stops serving.
- [x] 3.2 Same as 3.1 for `http_api.listen`. Verify: `Error::Bind` names the HTTP API.
- [x] 3.3 Same for `admin.listen`, with a build closure that records whether it ran.
  Verify: `Error::Bind` names the admin server, and the closure never ran.
- [x] 3.4 In `startup_integration.rs`, hold a listener on the reverse proxy address and
  start the binary. Verify: it exits non-zero, and its log holds `failed to start`,
  `reverse proxy could not bind <addr>`, and `Address already in use`.

## 4. Startup test retries

- [x] 4.1 In `startup_integration.rs` and `model_guard_integration.rs`, retry a start
  whose process exited with `Address already in use` in its log, in place of the `failed`
  log line; any other early exit still fails the test (D6). Verify: both test files pass
  10 runs in a row.

## 5. Checks

- [x] 5.1 Run `cargo test --workspace` and `cargo clippy --workspace --all-targets`.
  Verify: both pass with no warnings.
- [x] 5.2 Start the release binary with `reverse_proxy.listen` on a port another process
  holds. Verify: it exits non-zero once the guards have loaded, and logs the listener and
  the address.
- [x] 5.3 Review the diff against the spec delta with the `code-review` skill. Verify: no
  finding is left open.
