## 1. Tests first

- [x] 1.1 In `crates/voidwall/src/engine/finding.rs`, add tests for `ScanResult::guards()`:
  four findings from one guard give one name; findings from two guards give both names,
  sorted; no findings give an empty list. Verify: `cargo test -p voidwall finding::tests`
  fails to compile before 2.2.
- [x] 1.2 In `crates/voidwall/src/metrics.rs`, add `#[test_case]` tests for
  `inc_guard_detection` and `inc_message_blocked`, like the existing increment tests.
  Verify: the tests fail to compile before 2.1.
- [x] 1.3 In `crates/voidwall/src/reverse_proxy.rs` tests, use `run_guards` with a route
  no other test uses:
  - two detecting guards, one with four units' worth of findings: each guard's
    `voidwall_detections_total` increments by exactly one;
  - one detecting guard and one slow guard that is abandoned: only the detecting guard
    is counted;
  - a silent guard: `voidwall_detections_total` does not increment.
  Verify: the tests fail before 2.3.
- [x] 1.4 In `crates/voidwall/src/http_api.rs` tests, extend
  `fail_close_answers_500_and_counts_the_detections`: `voidwall_detections_total` with
  `guard="detecting"` increments by one, and with `guard="failing"` does not. Use guard
  names no other test uses. Add one test: a 500 or a reported detection on `/v1/scan`
  does not move `voidwall_blocked_total` for `mode="http_api"`. Verify: the tests fail
  before 2.4.
- [x] 1.5 In `crates/voidwall/tests/reverse_proxy_integration.rs`, each test uses its own
  route prefix and checks `voidwall_blocked_total` and `voidwall_pii_blocked_total` from
  `prometheus::default_registry().gather()`:
  - a PII request is blocked with 403: both increment by one with `direction="request"`,
    and `voidwall_detections_total{guard="pii"}` increments by one;
  - a PII response is blocked with 403: both increment by one with
    `direction="response"`;
  - an oversize body under `fail_close` answers 413: only `voidwall_blocked_total`
    increments;
  - an unparseable JSON body under `fail_close` answers 400: only
    `voidwall_blocked_total` increments;
  - a scanner failure under `fail_close` answers 500: only `voidwall_blocked_total`
    increments;
  - the same three errors under `fail_open` pass: `voidwall_blocked_total` does not
    increment;
  - an unreachable upstream answers 502: `voidwall_blocked_total` does not increment.
  Verify: the tests fail before 2.3 and 2.5.
- [x] 1.6 In `crates/voidwall/tests/admin_integration.rs`, after a PII detection, the
  scrape carries `voidwall_detections_total` and `voidwall_blocked_total` samples with
  the label sets of the spec, and no `pii_kind` label on either. Verify: the test fails
  before 2.3.

## 2. Implementation

- [x] 2.1 In `metrics.rs`, register `GUARD_DETECTIONS_TOTAL`
  (`voidwall_detections_total`, labels `guard`, `mode`, `route`, `direction`) and
  `MESSAGES_BLOCKED_TOTAL` (`voidwall_blocked_total`, labels `mode`, `route`,
  `direction`), with `inc_guard_detection` and `inc_message_blocked`. Verify: test 1.2
  passes.
- [x] 2.2 In `finding.rs`, add `ScanResult::guards() -> Vec<Arc<str>>`: the guard names
  of the findings, sorted and distinct. Verify: test 1.1 passes.
- [x] 2.3 In `reverse_proxy.rs`, `run_engine` increments `inc_guard_detection` once per
  name in `scan_result.guards()`, next to the per-kind loop. Verify: tests 1.3 and the
  403 cases of 1.5 pass for `voidwall_detections_total`.
- [x] 2.4 In `http_api.rs`, `process` increments `inc_guard_detection` once per name in
  `scan_result.guards()`, next to the per-kind loop and before the guard error is
  handled. Verify: test 1.4 passes.
- [x] 2.5 In `reverse_proxy.rs`, `handle_proxied_request` increments
  `inc_message_blocked` in the request and the response arms that return
  `PipelineResult::Block` or `PipelineResult::Error`. `buffer_body` takes the route and
  increments it in its `fail_close` oversize branch only. The doc comment on
  `PipelineResult::Error` states that it means a stopped message. `inc_blocked` for the
  PII family stays in `run_engine`. Verify: every case of test 1.5 passes.

## 3. Checks

- [x] 3.1 Run `cargo test --workspace`. Verify: all tests pass.
- [x] 3.2 Run `cargo clippy --workspace --all-targets`. Verify: no warnings.
- [x] 3.3 Run `openspec validate add-guard-metrics --strict`. Verify: it passes.
- [x] 3.4 Review the diff against the spec deltas with the `code-review` skill. Verify:
  no finding is left open.
