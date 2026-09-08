## 1. The finding types

- [x] 1.1 Add `Unit`, `UnitId`, `UnitKind`, and `UnitContent` in `voidwall` — verify: a unit
  carries flat text or structured fragments with the raw bytes, and `cargo check
  --workspace` passes
- [x] 1.2 Add `Finding` and `FindingKind`, each finding naming its unit, its kind, its
  guard, and an optional span and confidence — verify: unit tests cover a finding with a
  span and a span-less finding carrying a confidence
- [x] 1.3 Make `detected`, `matches_count`, and `kinds` derived methods over `findings`
  rather than stored fields — verify: `kinds()` is sorted, holds each kind once, and two
  runs over the same findings return the same list; four findings of one kind yield one
  entry
- [x] 1.4 Confirm the boundary — verify: `grep` finds none of the new type names anywhere
  under `crates/voidwall-pii/`

## 2. The guard contract

- [x] 2.1 Add `trait Guard` with `name`, `interest`, and `detect`, plus `Interest`,
  `GuardInput`, and `DetectFuture` — verify: the trait is object-safe (a
  `Box<dyn Guard>` compiles), lives in `voidwall`, and names `Finding`
- [x] 2.2 Give `Interest` the unit-kind axis only — verify: no `TrustClass` and no
  internal/external/tool axis appears in the type
- [x] 2.3 Document `GuardInput.on_error` on the field: the guard needs it only to pick the
  message when the pool drops its reply channel; the `on_error` policy itself stays in the
  handlers — verify: no `match` on the policy appears in any `detect` body

## 3. The engine

- [x] 3.1 Add `Engine` holding a config-constructed guard list — verify: `Engine::guard` is
  the only public entry point and the guards are built at startup, not per request
- [x] 3.2 Add the interest filter — verify: a request whose units match no guard's declared
  interest calls no guard, proved by a counting test guard
- [x] 3.3 Add the `FuturesUnordered` fan-out over a shared `Arc<[Unit]>` — verify: the guard
  futures borrow the units rather than clone them, and `futures-util` is the only new
  dependency
- [x] 3.4 Add the canonical sort — verify: findings come back ordered by unit, span start,
  span end, guard, then kind, with span-less findings last, whatever order the guards
  finish in
- [x] 3.5 Add the block predicate and the short-circuit — verify: a blocking finding
  abandons a guard still running, and a redact-only outcome does not

## 4. The regex guard

- [x] 4.1 Move the regex path behind `RegexPiiGuard`, which owns `ScannerPool` — verify:
  `ScannerPool` is `pub(crate)` inside the guard module and is unreachable from
  `http_api.rs`, `reverse_proxy.rs`, and `main.rs`
- [x] 4.2 Make `execute_scan` detect-only: scan the selected units, resolve overlaps per
  unit on the pool thread, map each match to a `Finding` — verify: `matches_count()` equals
  the previous `matches_count` on every existing test
- [x] 4.3 Confirm the seam — verify: `git diff --stat crates/voidwall-pii/` is empty, and no
  `detect` body reaches `voidwall_pii::Scanner` without crossing the pool

## 5. Redaction as an action

- [x] 5.1 Remove `redact` and `redact_strategy` from the scan request and the four redacted
  buffers from the scan result — verify: `cargo check --workspace` passes and no caller
  reads a redacted buffer off a scan result
- [x] 5.2 Move `redact_in_place` to `action.rs` as a free `pub(crate)` function over units,
  findings, and the strategy, returning the replaced bytes per unit — verify: it reads the
  units without mutating them, and both `action::execute` and the `/v1/redact` handler call
  it
- [x] 5.3 Have `action::execute` take the units and carry the replacement map on its forward
  outcome — verify: redaction still runs after block and before header
- [x] 5.4 Unpack the map back into the redacted path, query, and headers inside
  `pipeline_result_from_outcome` — verify: `PipelineResult` keeps its shape, the
  reverse-proxy handler is unchanged, and `rebuild_uri` and `apply_redacted_headers` are
  unmoved
- [x] 5.5 Confirm the output — verify: `/v1/scan`, `/v1/redact`, and both proxy directions
  produce byte-identical output on every existing test

## 6. Wiring and shutdown

- [x] 6.1 Swap the shared scanner pool for the engine in the API state, the reverse-proxy
  state, and `main.rs` — verify: three wiring sites change and no fourth exists
  (`forward_proxy.rs` and `tls.rs` are empty)
- [x] 6.2 Have both handlers build their units and call `Engine::guard` — verify: two call
  sites remain, and `/v1/scan` and `/v1/redact` pass no block policy
- [x] 6.3 Make shutdown `Drop`-only: `Engine::shutdown` logs and drops, and the pool's
  `Drop` still closes the channel and joins every thread — verify: every scanner thread
  joins before the shutdown log line, and the "still referenced" warning path is gone
- [x] 6.4 Confirm the blast radius — verify: no integration test changes except the
  pool-construction fixtures and the kind-order assertions

## 7. The test-only second guard

- [x] 7.1 Add a second guard behind `#[cfg(test)]` — verify: it never appears in a release
  build
- [x] 7.2 Cover the aggregation with it — verify: four tests pass, one each for the
  interest filter skipping it, the fan-out awaiting both, a blocking finding abandoning the
  other, and a redact-only policy not abandoning it
- [x] 7.3 Cover the shared-kind rules with it — verify: two guards reporting the same kind
  produce one entry in `kinds()` and one increment of the detection counter

## 8. Documentation

- [x] 8.1 Update `ARCHITECTURE.md` for the engine, the guard contract, and redaction as an
  action — verify: it no longer describes the scanner as producing redacted buffers
- [x] 8.2 Record the vocabulary-scoped resolution rule where a future author will meet it —
  verify: `crates/voidwall-pii/AGENTS.md` and the engine module agree that resolution runs
  once per vocabulary, never per guard and again over the union

## 9. Gates

- [x] 9.1 Run the workspace build and tests — verify: `cargo test --workspace` passes
- [x] 9.2 Run Clippy — verify: `cargo clippy --workspace --all-targets` reports no warning
- [x] 9.3 Review the diff against the spec deltas with the `code-review` skill — verify:
  every requirement in `specs/` has a test behind it and nothing was specified that is not
  built
