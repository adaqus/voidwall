## Why

The detection and block metrics name PII: `voidwall_pii_detections_total{pii_kind, …}`
and `voidwall_pii_blocked_total`. A model guard is not PII, so its detections have no
metric to land in. Two new metrics count detections and blocks for every guard, with the
guard as a label. This step comes before the model runtime, so the runtime lands on
metrics that already exist and are tested with the PII guard.

## What Changes

- New counter `voidwall_detections_total{guard, mode, route, direction}`. It increments
  once per guard per message when that guard reported at least one finding. Several
  findings from one guard in one message count once. It has no kind label.
- The `guard` label holds the name configuration gave the guard. The built-in regex PII
  guard is `guard="pii"`.
- `voidwall_detections_total` increments whether the message is blocked or reported on,
  and when a guard error makes `/v1/scan` answer 500 under `fail_close`. It counts the
  guards whose findings the engine returned.
- When a detection blocks a message, the engine abandons the guards still running. An
  abandoned guard is not counted in `voidwall_detections_total`.
- New counter `voidwall_blocked_total{mode, route, direction}`. It increments once per
  message the reverse proxy stops. A stopped message is a 403 for a detection, or a
  `fail_close` error answer: 413 for an oversize body, 400 for an unparseable body, 500
  for a scanner failure. It has no `guard` label.
- `/v1/scan` never increments `voidwall_blocked_total`. It reports and stops no message.
- `voidwall_pii_detections_total` and `voidwall_pii_blocked_total` do not change. The
  PII blocked counter still counts only the 403 for a detection.
- The metric label rule allows a guard name as a label value.

## Capabilities

### New Capabilities

None.

### Modified Capabilities

- `metrics`: two new families, `voidwall_detections_total` and `voidwall_blocked_total`,
  with their count rules. The `guard` label is added to the allowed label values.
- `reverse-proxy`: a 403 for a detection also increments `voidwall_blocked_total` once
  and `voidwall_detections_total` once per guard that reported.
- `security`: a metric label may hold a guard name. A guard name is fixed by
  configuration and never holds a detected value.

## Impact

- Code: `crates/voidwall/src/metrics.rs` (two families and their increment functions),
  `crates/voidwall/src/reverse_proxy.rs` (the 403 path and the `fail_close` error paths),
  `crates/voidwall/src/http_api.rs` (the detections path).
- Tests: unit tests in `metrics.rs`, `reverse_proxy.rs`, and `http_api.rs`, and
  integration tests that scrape the admin metrics endpoint.
- Metrics: two new families. No existing family changes. Dashboards and alerts that use
  the PII families keep working.
- No configuration, API body, or dependency change.
