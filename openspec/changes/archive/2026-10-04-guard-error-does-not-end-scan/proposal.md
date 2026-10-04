## Why

Today the first guard error ends the scan (`let batch = result?;` in `Engine::guard`). The
result then depends on which guard finishes first, and under `fail_open` a failure of one
guard lets through a message that another guard would block. This conflicts with the rule
"the engine short-circuits for a block and nothing else". It must be fixed before a second
guard (a model guard) can fail at run time. Decision #10 in the `voidwall-ml` plan.

## What Changes

- A guard error no longer ends the scan. The engine keeps waiting for the other guards.
- Reverse proxy: when another guard reports a finding, the block wins. The proxy answers the
  fixed 403, under `fail_open` and under `fail_close`.
- Reverse proxy: `on_error` applies only when no guard blocks. The status and the 500 body
  do not change.
- When a block wins over an error, the error is still written to the log through the
  rate-limited `warn!`. `voidwall_errors_total` still increments, with `outcome="blocked"`
  and `reason="scanner_failure"`.
- `/v1/scan` under `fail_open`: a guard error answers 200 with the findings of the guards
  that succeeded. Today it answers a report that detects nothing. **BREAKING** for a
  client that relies on the empty report.
- `/v1/scan` under `fail_close`: a guard error answers 500, as today. The detection counter
  increments once per kind that the guards that succeeded found.
- Under `fail_close`, a message with a guard error can take longer to answer, because the
  engine waits for the other guards.

## Capabilities

### New Capabilities

None.

### Modified Capabilities

- `pii-scanning`: the engine does not stop on a guard error. It returns the findings of the
  guards that succeeded together with the error.
- `reverse-proxy`: a block from another guard wins over a guard error. `on_error` applies
  only when no guard blocks.
- `http-api`: under `fail_open`, a guard error answers the findings of the guards that
  succeeded.
- `metrics`: an error that a block overrules increments `voidwall_errors_total` with
  `outcome="blocked"`. The detections that come with a 500 from `/v1/scan` increment the
  detection counter.

## Impact

- Code: `crates/voidwall/src/engine/mod.rs` (`Engine::guard` and its return type),
  `crates/voidwall/src/reverse_proxy.rs` (`run_engine`), `crates/voidwall/src/http_api.rs`
  (the `/v1/scan` handler and `handle_scanner_failure`).
- Tests: engine unit tests with a fake guard that fails. Reverse proxy and REST API
  handler tests for an error together with a finding.
- API: the `/v1/scan` answer under `fail_open` changes when a guard fails. The OpenAPI
  document does not change, because the response shape is the same.
- No configuration or dependency change. No new metric or label value.
