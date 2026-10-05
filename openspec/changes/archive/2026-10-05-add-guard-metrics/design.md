## Context

`metrics.rs` registers `voidwall_pii_detections_total{pii_kind, mode, route, direction}`
and `voidwall_pii_blocked_total{mode, route, direction}`. Two handlers increment them:

- `reverse_proxy.rs`, `run_engine`: after a detection, once per kind and once for the
  block. This is the only place the PII blocked counter moves.
- `http_api.rs`, `process`: once per kind, before the guard error is handled, so a
  `fail_close` 500 still counts the detections.

Each `Finding` carries `guard: Arc<str>`, the name configuration gave the guard.
`ScanResult::kinds()` already derives the sorted, distinct kind list from the findings.

The reverse proxy stops a message in four places today. Each `fail_close` place also
increments `voidwall_errors_total{outcome="blocked"}`:

| Place | Answer | Direction |
|---|---|---|
| `run_engine`, detection | 403 | request or response |
| `handle_scan_error`, `fail_close` | 500 | request or response |
| `classify_scan_body`, `fail_close` | 400 | request or response |
| `buffer_body`, `fail_close` | 413 | request |

`buffer_body` also returns a 502 for a body read failure. That is not a block.

The forward proxy builds no response yet, so it increments nothing.

## Goals / Non-Goals

**Goals:**

- `voidwall_detections_total{guard, mode, route, direction}`: once per guard with
  findings, per message.
- `voidwall_blocked_total{mode, route, direction}`: once per message the reverse proxy
  stops, by a detection or by a `fail_close` error.
- The PII families stay as they are.

**Non-Goals:**

- A kind label on the new families.
- A `guard` label on the blocked family.
- Waiting for abandoned guards so that they are counted. The engine contract stays.
- `/v1/scan` in the blocked family.
- Model guards. They arrive in a later change and use these families with no change.

## Decisions

**The guard list comes from `ScanResult`.** Add `ScanResult::guards()`, the twin of
`kinds()`: the guard names of the findings, sorted and distinct. A handler loops over it
and increments once per name. This puts "once per guard per message" in one place that
a unit test covers. The alternative, a dedup in each handler, repeats the rule in two
files.

**`guards()` returns `Vec<Arc<str>>`.** The names already live in `Arc<str>`, so a clone
is a reference count, not a copy. The order is by name, so it is stable for tests.

**The detection counter moves next to the PII detection counter.** In `run_engine` and
in `process`, the new loop sits beside the existing per-kind loop. The rule "count
whatever happens to the message" then holds for both families at once, including the
API `fail_close` 500.

**The blocked counter moves where the pipeline result is known.** In
`handle_proxied_request`, the request and the response arms that return
`PipelineResult::Block` or `PipelineResult::Error` increment `voidwall_blocked_total`
with the route and the direction. `buffer_body` increments it in its `fail_close`
oversize branch, because its error result also carries the 502, which is not a block.
`buffer_body` gets the route as a parameter for the label.

Alternative: increment at each of the four places next to `inc_error("blocked", …)`.
That needs a `MetricContext` in `classify_scan_body` and `buffer_body`, and repeats the
call four times. The chosen form has two call sites in the match arms and one in
`buffer_body`. A new reason that returns `PipelineResult::Error` is then counted with no
extra code.

**`PipelineResult::Error` means a stopped message.** Today only `fail_close` paths
build it. The doc comment on the variant says so, so a later caller does not use it for
a 502.

**The PII blocked counter stays in `run_engine`.** It keeps counting only the 403. It is
not moved to the match arms, so its count does not change.

**Function names.** `metrics.rs` gets `inc_guard_detection(guard, mode, route,
direction)` and `inc_message_blocked(mode, route, direction)`, and the statics
`GUARD_DETECTIONS_TOTAL` and `MESSAGES_BLOCKED_TOTAL`. The existing `inc_detection`,
`inc_blocked`, `DETECTIONS_TOTAL`, and `BLOCKED_TOTAL` keep their names, because a
rename touches code this change does not need.

## Risks / Trade-offs

- [An abandoned guard is not counted] → A dashboard that compares guards under-counts
  the slower guard on blocked messages. The spec states it, and `/v1/scan` counts every
  guard.
- [`voidwall_blocked_total` and `voidwall_pii_blocked_total` differ] → The new family
  also counts `fail_close` errors. The spec states the difference. The error reason is
  in `voidwall_errors_total`.
- [Tests share one global registry] → Every new test uses a guard name or a route that
  no other test uses, so its count is exact.
