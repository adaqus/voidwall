## Context

See `proposal.md` — Why.

Today `execute_scan` in `scanner.rs` is the whole detection path: it selects the fields,
calls `voidwall_pii::Scanner` on a pool thread, runs `resolve_overlaps` per field, redacts
in place, and returns a `ScanResult` carrying counts, kinds, and four redacted buffers.
Both handlers call it, and `action.rs` reads what it produced.

Three constraints shape everything below.

| Constraint | Consequence |
| --- | --- |
| `voidwall-pii` cannot depend on `voidwall` | The shared trait cannot live in layer 1. Detection crates stay independent; the contract is defined in `voidwall` and each guard adapts one crate to it. |
| The scanner is CPU-bound and must never run on the tokio runtime | A guard's `detect` is `async` but does almost no work: it hands the unit to a pool thread and awaits a oneshot. |
| Exactly one real guard exists | Every per-guard *policy* surface is untestable here. Only the contract and the aggregation can be built and proved now. |

The decisions below are `D1`–`D16` of `voidwall-internal/research/detection-architecture.md`,
restated so this repo stands alone. That document is the source; where the two disagree,
it wins.

## Goals / Non-Goals

**Goals**

- One aggregation type owns stage order, so later stages (the L1 gate, the verdict cache)
  attach to it instead of to a handler.
- A guard is replaceable and addable without touching a handler.
- The conversion is provably mechanical: `git diff --stat crates/voidwall-pii/` is empty and
  every existing test keeps its expected values, kind order excepted.

**Non-Goals**

- Per-guard policy: enable, order, timeout, budget, and failure mode. They need a second
  real guard to be testable. Phase 27.
- The gate and cache stages themselves. This change owes them the `Unit` type they attach
  to, not empty stage functions with exactly one possible value.
- Cooperative cancellation. Abandon is enough until a guard is expensive enough to be
  worth cancelling.
- An `Unscannable` outcome. Nothing here produces one.

## Decisions

### The trait lives in `voidwall`, and layer 1 implements nothing

`trait Guard` — `name`, `interest`, `detect` — is defined in `voidwall`. `voidwall-pii` keeps
`Detector` as its own internal chain-member trait and learns nothing about findings.

*Alternative rejected:* a shared trait in a third crate that both depend on. It buys
nothing while each layer-1 engine has a different natural input shape, and it makes the
FFI-backed engines of later tiers harder, not easier.

### The guard declares interest; the engine applies it

`Interest` carries **one axis in this change: the unit kinds a guard wants**. No
`TrustClass`, no internal/external/tool axis.

*Why one axis:* nothing produces a trust class before Phase 28, and freezing a taxonomy
that nothing exercises is how the pre-2026-09-04 design failed. The axis is added when a
producer exists.

### Fan-out uses `FuturesUnordered`, not task spawning

A guard future is mostly awaiting a oneshot, so spawning buys no parallelism — the real
parallelism is already in the pool threads — and it costs a `'static` bound on everything
the future borrows. `FuturesUnordered` lets a guard borrow the shared `Arc<[Unit]>` rather
than clone it.

*Trade-off:* the futures make progress only while the engine is polled. That is exactly
what a request handler does, so it costs nothing here.

### Short-circuit on block only, and abandon rather than cancel

The engine stops awaiting when a finding triggers a block, because the message is not
going anywhere. It does not stop for redact or header, because those need the full set.
Abandoned futures are dropped; the pool thread behind one keeps running to completion and
its result is discarded.

*Consequence, deliberately accepted:* an abandoned guard's findings are missing from
`kinds`, from `matches_count`, and from the detection counter. With one real guard the set
is never partial, so nothing observable degrades in this change. It becomes real in
Phase 27, and the three contracts degrade together.

### Output order is canonical, not arrival order

Findings are sorted by `(unit, span start, span end, guard, kind)`, span-less last, and
the kind list is a sorted set. Arrival order of the fan-out is therefore invisible.

This is the first of the two observable changes: kind lists come from a `HashSet` today,
so they vary run to run. Making them sorted is what lets a test assert them at all.

### Overlap resolution is scoped to a vocabulary, not to a guard

While one guard is the only producer of a kind vocabulary, that guard resolves its own
matches and the engine adds nothing. When a second producer of the same vocabulary
appears, resolution moves to the engine over the union, and the per-guard pass is removed.

`resolve_overlaps` is a greedy pairwise pass. Resolving twice is not the same as resolving
once, so the shortcut is safe only while one producer exists. Worked example, checkable
against `crates/voidwall-pii/src/overlap.rs`:

```
guard A returns   EMAIL  [10, 25)     length 15
guard B returns   PHONE  [ 0, 20)     length 20

resolve(A) = {EMAIL}      resolve(B) = {PHONE}
union of the resolved sets      → EMAIL and PHONE, overlapping on [10, 20)
resolve(union of the raw sets)  → partial overlap, longer wins → PHONE only
```

Leaving the union unresolved keeps two overlapping findings and reports
`matches_count = 2` where the engine's own contract says 1. The rule is therefore: resolve
once, at the level of the vocabulary, never once per guard and again over the union.

*Why the shortcut is provably safe here:* `execute_scan` already resolves per field — the
body, the path, the query, and each header value separately. One `Unit` per body, path,
query, and header value is a one-to-one mapping of that granularity, so `matches_count()`
equals the old `matches_count` by construction rather than by coincidence.

### Redaction becomes an action, as a free function

`redact` and `redact_strategy` leave the scan request. The four redacted buffers leave the
scan result. `redact_in_place` moves from `scanner.rs` to `action.rs` as a free
`pub(crate)` function over `(units, findings, strategy)` returning the replaced bytes per
unit.

*Why a free function and not a step inside `execute`:* `/v1/redact` builds no action set
and cannot route through the action engine. Both `execute` and that handler call the same
function, so there is one redaction implementation, not two.

*Why it reads rather than mutates:* an abandoned guard's pool thread may still hold a
clone of the unit content, so exclusive access is not guaranteed.

### `PipelineResult` keeps its shape

The redaction map is unpacked back into the three redacted fields inside
`pipeline_result_from_outcome`. The reverse-proxy handler, `rebuild_uri`, and
`apply_redacted_headers` do not change.

*Alternative rejected:* re-cut `PipelineResult` around units now. It widens the diff into
the handler for no behaviour gain, and Phase 26 has to re-cut it anyway when the decoders
land. Chose the smaller diff; the cost is one unpacking function that Phase 26 deletes.

One detail worth stating so the shorter list does not read as a bug: today the scanner
returns **every** header when any one is redacted; the map returns only the changed ones.
`apply_redacted_headers` inserts per entry, so the forwarded message is identical.

### Shutdown becomes `Drop`-only

The pool sits behind a boxed trait object inside a guard, so no caller can reclaim it to
call an explicit `shutdown`. `Engine::shutdown` logs and drops; `Drop for ScannerPool`
still closes the channel and joins every thread.

*Alternative rejected:* a fourth `Guard` method so the engine can ask each guard to shut
down. It buys one warning line — "still referenced, dropping without explicit shutdown" —
at the cost of putting lifecycle into a contract that is otherwise purely about detection.

### Guards are config-constructed, and `name()` is a fixed string

The engine builds its guards from configuration at startup. `name()` returns a fixed
string per guard type, never an operator-supplied one, because the name reaches metric
labels and an operator-supplied name is unbounded label cardinality.

### A second guard exists, for tests only

Without it, the interest filter, the fan-out, and the short-circuit are unreachable code.
The test guard is what turns each of them into a passing test.

## Risks / Trade-offs

| Risk | Mitigation |
| --- | --- |
| The seam is cut in the wrong place and detection logic leaks into `voidwall` | `git diff --stat crates/voidwall-pii/` must be empty. This is the single sharpest check in the change, and the earlier attempt at this refactor failed exactly here. |
| A reviewer "fixes" the kind loop to once-per-match when `kinds` becomes derived, and silently multiplies every detection counter | The metrics delta states once-per-kind explicitly and adds a many-findings-one-kind scenario. |
| Kind order changes break assertions in a way that hides a real regression | Order is the only expected diff. Any test whose *set* of kinds or whose count changes is a real failure, not a re-ordering. |
| Redaction output drifts while moving between modules | `/v1/scan`, `/v1/redact`, and both proxy directions must be byte-identical on every existing test. |
| `Drop`-only shutdown leaves a scanner thread running if a stray reference outlives the engine | The threads join when the last holder releases the pool. Assert that every thread joins before the shutdown log line. |
| The change is large and tempting to land in parts | Every later phase depends on the contract. Land it in one pass. |

## Migration Plan

No data migration and no configuration migration: no config key is added, removed, or
renamed, and no metric family changes. An operator upgrading sees two differences.

1. Kind lists — `/v1/scan`, `/v1/redact`, `X-PII-Detected`, and the 403 body — become
   sorted. A consumer that depended on the previous order was depending on `HashSet`
   iteration order, which was never stable.
2. Redaction is applied by the action engine. Output bytes are unchanged.

Rollback is a revert of one change. Nothing persists across the boundary.

## Open Questions

- The `reverse-proxy` spec has a scenario worded "the scan redacts both the path and the
  body". After this change the action engine redacts, so the wording is stale while the
  behaviour is identical. Left alone deliberately: `PipelineResult` keeps its shape, so
  no reverse-proxy requirement changes. Fix the wording in Phase 26, when that spec is
  edited anyway.
- The shared kind vocabulary across tiers is not settled. It is not needed until a second
  vocabulary producer exists, and it is due before Phase 27.
