## 1. Fixtures for `voidwall` tests (D6)

- [x] 1.1 Add the `test-fixtures` feature to `voidwall-ml` and gate `fixtures` with `#[cfg(any(test, feature = "test-fixtures"))] pub mod fixtures;`; enable it in `voidwall`'s `[dev-dependencies]` only. Verify: `cargo test -p voidwall-ml` passes; `cargo tree -p voidwall -e features --edges normal` shows no `test-fixtures`; a scratch `voidwall` test writes `Fixture::default()` and a tokenizer to a temp dir and `voidwall_ml::load` returns 1 worker.

## 2. Configuration (guard-configuration, configuration; D3)

- [x] 2.1 Add `threads: Option<NonZeroUsize>` and `overlap_tokens: Option<usize>` to `ModelGuardConfig`. Verify: `#[test_case]` tests — `threads = 3` and an absent `threads` parse; `threads = 0` fails and the diagnostic names `guards.<name>.threads` (if it does not, switch to a semantic rule on `Option<usize>` per D3 and test the same message).
- [x] 2.2 Validate `overlap_tokens` through `voidwall_ml::check_overlap`. Verify: `#[test_case]` — `max_tokens = 16` with overlap 8 passes; with 9 fails naming the guard, 9, and 8; absent passes.
- [x] 2.3 Add the semantic rules: `text_multilabel_classifier` fails naming the guard and the adapter as not built; `text_classifier` with `labels.len() != 1` fails naming the guard and the one-label rule. Verify: unit tests for each, plus a `--validate` test (`validate.rs`) that categorises the multilabel case as semantic.
- [x] 2.4 Add `effective_model_threads(name)` (`max(1, available_parallelism / guards.len())` when unset) and replace `warn_on_model_guards` with `warn_on_model_thread_total`. Verify: `#[test_case]` tests on a pure helper taking the CPU count: (8 CPUs, 2 guards) → 4 each; (2 CPUs, 3 guards) → 1 each and the sum 3 is above 2; (4 CPUs, `threads = 6`) → above. The old "configured but not executed" warning and its test are gone.

## 3. Errors carry status and reason (D2)

- [x] 3.1 Add `Error::Inference { guard, detail }` and `Error::WindowLimit { guard, windows, limit }`, `Error::scan_reason()`, and their `IntoResponse` arms. Verify: `#[test_case]` tests in `error.rs` — `Inference` → 500 `{"error":"internal error"}`; `WindowLimit` → 413 `{"error":"tokenized content too long to scan"}`; neither body holds `guard`, `detail`, or the numbers; `scan_reason` gives `inference_failure`, `window_limit`, and `scanner_failure` for `Scanner`.
- [x] 3.2 Make `handle_scan_error` (reverse proxy) and `handle_scanner_failure` (API) take the reason and the response from the error. Verify: reverse proxy unit tests with a fake guard returning each variant under `fail_close` and `fail_open` — status 500/413 or forwarded, `voidwall_errors_total` with the right `outcome` and `reason`, and `voidwall_blocked_total` +1 only under `fail_close`; API unit tests — 413 / 500 under `fail_close`, 200 with the good guards' findings under `fail_open`.

## 4. Model guard (D1)

- [x] 4.1 Write `engine/model.rs`: `ModelPool` (threads owning one `voidwall_ml::Worker` each, bounded channel 4 × N, 1 s `send_timeout`, `oneshot` reply, `Drop` joins) and `ModelGuard` (name, interest from `ModelGuardSurface`, label, optional threshold). Verify: unit tests with the fixture — a unit holding `trigger` above the threshold gives one `whole_unit` finding with the score as confidence and no span; a unit at exactly the threshold gives one; a clean unit gives none; two selected units above the threshold give two findings; no threshold gives none; a plain unit with `trigger` and an invalid UTF-8 byte gives a finding; a structured unit whose values hold `trigger` gives one finding; dropping the guard joins every thread.
- [x] 4.2 Map failures: `RunError::WindowLimit` → `Error::WindowLimit`; every other `RunError`, a full channel, dead workers, and a dropped reply → `Error::Inference` naming the guard. Verify: unit tests — the NaN-bias fixture gives `Inference`; a fixture load with a tiny `max_body_size` and a long unit gives `WindowLimit`; neither error's `Display` holds the unit's text (marker string check).

## 5. Engine and startup order (D4)

- [x] 5.1 Change `Engine::new` to take the config and build each model guard with `LoadSettings` from its section, `max_body_size`, and `effective_model_threads`; a `LoadError` becomes an error naming the guard. Verify: engine unit tests — a fixture model guard is selected by name and by default; a bad model file fails naming the guard and the path.
- [x] 5.2 Move the startup sequence into a library function that takes an engine-building closure: bind admin, build the engine on `spawn_blocking`, exit 1 on error, then bind listeners and set `ready`. `main.rs` calls it. Verify: integration test with a builder held on a channel — `/healthz` 200, `/readyz` 503, data port refuses; after release `/readyz` 200 and the data port answers.
- [x] 5.3 Confirm `--validate` does not load a model. Verify: `validate_cli_integration` test — a config whose model file exists but is not ONNX passes `--validate` with exit 0.
- [x] 5.4 Startup with a bad model exits non-zero. Verify: `startup_integration` test — the binary with a model guard pointing at a non-ONNX file exits non-zero, logs the guard name and the path, and the data port never accepts.

## 6. PII metrics count only the `pii` guard (D5)

- [x] 6.1 Add `ScanResult::kinds_of(guard)` and use it for `voidwall_pii_detections_total` and `voidwall_pii_blocked_total` in both handlers. Verify: unit tests — a fake model guard reporting `PROMPT_INJECTION` alone gives a 403, `voidwall_blocked_total` +1, `voidwall_detections_total{guard=<name>}` +1, and no change to either `voidwall_pii_*` family; `pii` and a model guard both reporting one kind increment `voidwall_pii_detections_total` for that kind by one.

## 7. End-to-end with a fixture model (D7)

- [x] 7.1 Reverse proxy integration test with a real server, a mock upstream, and a `[guards.injection]` fixture guard (`labels = ["PROMPT_INJECTION"]`). Verify: a body holding `trigger` → 403 with `kinds` `["PROMPT_INJECTION"]` and the upstream not reached; a clean body is forwarded unchanged.
- [x] 7.2 `/v1/scan` integration test with the same guard. Verify: a body holding `trigger` → 200 with `detected` true, `matches_count` 1, `kinds` `["PROMPT_INJECTION"]`.

## 8. Docs

- [x] 8.1 Update `docker/voidwall.toml` (the comment on the commented model guard, plus `threads` and `overlap_tokens`), `ARCHITECTURE.md` §4.8 and §5, `docs/config-validation.md`, and the 413 and 500 descriptions in `docs/openapi.json` (regenerated from `http_api.rs` if it is generated). Verify: `grep -rn "not executed\|none runs" ARCHITECTURE.md docs docker` finds nothing stale; the OpenAPI test passes.

## 9. Workspace checks

- [x] 9.1 Run the workspace gates. Verify: `cargo test --workspace` and `cargo clippy --workspace --all-targets` pass with no warning; `openspec validate run-model-guards --strict` passes.
- [x] 9.2 Review the diff against the spec deltas with the `code-review` skill. Verify: every spec scenario maps to a test named in tasks 2 to 7, or the gap is reported to the user.
