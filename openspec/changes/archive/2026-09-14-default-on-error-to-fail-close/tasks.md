## 1. Error taxonomy and status codes

- [x] 1.1 Add an `Error::BodyParse` variant to `crates/voidwall/src/error.rs` with a
  `Display` arm, and map it to 400 in `IntoResponse`. Verify: a new `#[test_case]` row in
  the `into_response` table asserts `StatusCode::BAD_REQUEST`, and the `Display` table
  gains a row for the new variant.
- [x] 1.2 Remap `Error::Scanner` from `BAD_GATEWAY` to `INTERNAL_SERVER_ERROR` in the same
  `IntoResponse` match. Verify: the existing `#[test_case]` row at `error.rs:159` asserts
  `INTERNAL_SERVER_ERROR`, and the `Error::Proxy` and `Error::Io` rows still assert
  `BAD_GATEWAY`.
- [x] 1.3 Change `classify_scan_body` in `crates/voidwall/src/reverse_proxy.rs` to build
  `Error::BodyParse` instead of `Error::Scanner("body parse failed")`. Leave the
  `metrics::inc_error("blocked", "body_parse_failed")` call untouched. Verify:
  `cargo test -p voidwall structured_scanning` passes, and
  `json_parse_failure_fail_close_blocks_request` asserts 400 rather than any 5xx.
- [x] 1.4 Tighten `json_parse_failure_fail_close_blocks_request` in
  `crates/voidwall/tests/structured_scanning_integration.rs` to assert the exact status.
  Verify: the test names 400 explicitly instead of checking a status range.
- [x] 1.5 Add an integration test that a scanner failure under `fail_close` answers 500 in
  the reverse proxy. Verify: `cargo test -p voidwall` runs it green.
- [x] 1.6 Add an integration test that the 400, 413, and 500 error bodies name the
  error only and carry no fragment of the scanned message. Covers the `reverse-proxy`
  delta scenario "An error body carries no scanned text", which the original task list
  missed. Verify: each of the three responses is asserted not to contain the placeholder
  value the request carried.

## 2. Flip the default

- [x] 2.1 Change `default_on_error()` at `crates/voidwall/src/config.rs:185` and the
  `on_error` field in `impl Default for ScanConfig` to `OnError::FailClose`. Verify: the
  unit tests at `config.rs:862` and `config.rs:877` assert `OnError::FailClose`.
- [x] 2.2 Add a config unit test that an explicit `on_error = "fail_open"` in TOML still
  parses and still wins over the default. Verify: `cargo test -p voidwall config` passes.
- [x] 2.3 Sweep every test that builds a `ScanConfig` without naming `on_error` and decide
  for each whether it now exercises the blocking path on purpose. Verify: `grep -rn
  "ScanConfig" crates/voidwall/src crates/voidwall/tests` lists no default-constructed
  config whose assertions depend on forwarding after an error.
- [x] 2.4 Add an integration test that a proxy started with no `on_error` in its config
  blocks on scanner failure. Verify: the test asserts 500 and
  `voidwall_errors_total{outcome="blocked"}`.

## 3. A skipped content type is not an error

- [x] 3.1 Add a reverse-proxy integration test that a body whose content type sits outside
  `scan.content_types` is forwarded under `on_error = "fail_close"`. Verify: the test
  asserts 200 and that the upstream received the body unchanged. The no-increment half of
  the requirement is held up by structure rather than a runtime delta, which would flake
  against the process-wide registry; see design.md.

## 4. Configuration examples

- [x] 4.1 Remove the `on_error` line from `docker/voidwall.toml`. Verify: the file no
  longer names `on_error`, and the container still starts against it.
- [x] 4.2 Leave `on_error = "fail_open"` in place in every file under
  `crates/voidwall/benches/configs/`. Verify: `grep -c fail_open
  crates/voidwall/benches/configs/*.toml` reports one per file, unchanged.

## 5. Documentation

- [x] 5.1 Update the error-handling paragraph in `AGENTS.md` and the matching paragraph in
  `openspec/config.yaml` to name `fail_close` as the default. Verify: both read the same
  and neither still implies `fail_open` is what you get by default.
- [x] 5.2 Write the release note: the new default, `on_error = "fail_open"` as the opt-out,
  the 413 that `max_body_size` now produces, and the 502-to-500 and 502-to-400 moves.
  Verify: the note names every status that changed.

## 6. Verification

- [x] 6.1 Run `cargo test --workspace`. Verify: green.
- [x] 6.2 Run `cargo clippy --workspace --all-targets`. Verify: no warnings.
- [x] 6.3 Run `openspec validate default-on-error-to-fail-close --strict`. Verify: passes.
- [x] 6.4 Review the diff against the two spec deltas with the `code-review` skill, then
  against `ARCHITECTURE.md`. Verify: every delta scenario has a test behind it.

## 7. Review follow-ups

- [x] 7.1 Add `/v1/scan` integration tests for a scanner failure under both policies, and
  give `TestApi` a `start_with_pii` so a test can own a failing pool. Closes the review
  finding that the default flip changed the API's failure mode from a 200 reporting
  nothing to a 500, with neither branch tested. Verify: the two scenarios in
  `openspec/specs/http-api/spec.md` under "A scanner error follows the on_error policy"
  each have a test, and both pass.
- [x] 7.2 Add a config unit test pinning that a route override does not inherit `on_error`
  from `[scan]`. Closes the review finding that an operator who sets `fail_open` globally
  still gets `fail_close` on every route carrying its own scan table, which is the
  documented rollback failing where it is needed most. Verify: the test asserts the
  top-level value is `fail_open` and the route's is `fail_close`.
- [x] 7.3 Add the two delta scenarios that had no test: a scanner failure under
  `fail_open` still forwards, and an unreachable upstream still answers 502. The second
  matters because this change moved scanner failures off 502 and nothing else pinned what
  remains on it. Verify: both tests pass and every scenario in the two spec deltas now
  names a test.
