## Why

Detection today is one hard-coded path: `execute_scan` calls the regex scanner, resolves
overlaps, redacts, and reports, all on the pool thread. Every later tier — the ML PII
tier, injection detection, the L1 gate, the verdict cache — needs a second and a third
detector to run beside the first, and none of them fits that path. This change cuts the
aggregation seam once, so the tiers after it are additions rather than rewrites.

The seam is a **guard**: one detection concern that returns findings and nothing else. One
**Engine** in `voidwall` owns the guards, filters them by declared interest, fans out,
sorts, and short-circuits. The handler acts. `voidwall-pii` is not touched.

Cutting it now is cheapest: one real guard exists, so the whole conversion is mechanical
and every existing test is a regression check on it. Every phase after this one depends on
the contract, so it is done in one pass.

## What Changes

- **Add the finding types** in `voidwall`: `Unit`, `UnitId`, `UnitKind`, `UnitContent`,
  `Finding`, `FindingKind`, and a `ScanResult` whose `detected`, `matches_count`, and
  `kinds` become derived methods over `findings` rather than stored fields.
- **Add `trait Guard`** — `name`, `interest`, `detect` — with `Interest`, `GuardInput`, and
  `DetectFuture`. Object-safe, defined in `voidwall`, because `voidwall-pii` cannot depend on
  `voidwall`.
- **Add `Engine`**: a config-constructed `Vec<Box<dyn Guard>>`, an interest filter, a
  `FuturesUnordered` fan-out, a canonical sort, and a block predicate. It replaces
  `Arc<ScannerPool>` in `ApiState`, `ReverseProxyState`, and `main.rs`.
- **Move the regex path behind `RegexPiiGuard`**, which owns `ScannerPool`.
  `ScannerPool` becomes unreachable outside the guard module.
- **BREAKING (observable): kind lists become deterministically ordered.** They are drawn
  from a `HashSet` today, so `/v1/scan`, `/v1/redact`, `X-PII-Detected`, and the 403 body
  emit them in an order that varies between runs. They become alphabetical and stable.
- **Redaction becomes an action.** `redact` and `redact_strategy` leave the scan request;
  the redacted buffers leave the scan result; the action engine produces the redacted
  bytes from the findings. Output stays byte-identical.
- **Shutdown becomes `Drop`-only.** The pool sits behind `Box<dyn Guard>`, so no caller can
  reclaim it to call an explicit `shutdown`. `Drop for ScannerPool` still joins every
  thread.
- **Add a test-only second guard**, which is what makes the interest filter, the fan-out,
  and the short-circuit testable while one real guard exists.
- **No new config key and no new metric.**

## Capabilities

### New Capabilities

None. The change re-cuts an existing seam; it adds no capability.

### Modified Capabilities

- `pii-scanning`: gains the guard contract, the Engine's aggregation rules, and the
  ordered kind list; overlap resolution is re-scoped from the scanner to a vocabulary;
  redaction ownership moves to the action engine; pool shutdown becomes `Drop`-only.
- `actions`: the redact action produces the redacted bytes instead of forwarding what the
  scan produced; every kind list the engine emits is deterministically ordered.
- `http-api`: the `kinds` array and the `X-PII-Detected` header are deterministically
  ordered.
- `metrics`: the detection counter is re-anchored to the Engine's resolved finding set,
  and increments once per distinct kind however many guards reported that kind.

## Impact

**Code.** `crates/voidwall/src/` — `scanner.rs` (split), a new guard module, `action.rs`,
`http_api.rs`, `reverse_proxy.rs`, `main.rs`. About 3,200 of the binary crate's 6,800
lines are in the blast radius. `crates/voidwall-pii/` is **not** touched:
`git diff --stat crates/voidwall-pii/` must be empty, and that is the sharpest single
check that the seam was cut in the right place.

**Tests.** 126 unit tests in the four touched modules and 58 integration tests across
`http_api_integration.rs`, `reverse_proxy_integration.rs`, and
`structured_scanning_integration.rs`. Only the kind-order assertions and the
pool-construction fixtures should change.

**Dependencies.** Adds `futures-util` for `FuturesUnordered`.

**Not in this change, deliberately.** `TrustClass` and the I/E/T interest axis — nothing
reads either before Phase 28. The gate and cache stages — this change owes them the `Unit`
type they attach to, not empty stage functions. `Unscannable` — nothing here produces one.
Per-guard policy surfaces — they need a second real guard to be testable. `PipelineResult`
keeps its shape, so the reverse-proxy handler does not change and `reverse-proxy` needs no
delta.
