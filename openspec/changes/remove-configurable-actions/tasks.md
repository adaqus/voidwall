Ordering note: `config.rs` holds the types every consumer names, so it is edited late, not
first. Group 4 is one atomic step — `build_state` reads `DirectionConfig.actions` to build
the `ActionSet`, and `action.rs` reads `DirectionConfig` to interpret it, so neither side
can move without the other. Splitting it needs bridge code that the next task deletes.

## 1. Delete the evaluation harness

- [x] 1.1 Delete `crates/voidwall/benches/ai4privacy_eval.rs`. Verify: `rg ai4privacy_eval` finds nothing outside `Cargo.toml`.
- [x] 1.2 In `crates/voidwall/Cargo.toml`, remove the `[[bin]] ai4privacy-eval` block, the `eval` feature, and the optional `[dependencies] reqwest`. Keep the `[dev-dependencies] reqwest` — integration tests use it unconditionally. Verify: `cargo check --workspace --all-features`.
- [x] 1.3 In `docker/ctl`, remove `cmd_eval`, `ai4privacy_files`, `fetch_mini10k`, the base-URL variables, the eval usage line, the eval env-var comment block, and the `eval)` dispatch arm. Verify: `bash -n docker/ctl` and `docker/ctl 2>&1 | grep -c eval` is 0.
- [x] 1.4 Delete `openspec/specs/evaluation/`. Verify: `openspec list --json` still parses.
- [x] 1.5 Delete the four `ai4privacy-{audit,eval,merge,sweep}` skills: the real directories under `.agents/skills/` and the symlinks under `.claude/skills/`. Verify: `ls -la .claude/skills/` shows no dangling link.
- [x] 1.6 Delete `scripts/merge_ai4privacy_valid.py`, `scripts/move_ai4privacy_rows.py`, `scripts/prune_ai4privacy_rows.py` — the deleted skills were their only callers. Verify: `rg 'ai4privacy_rows|merge_ai4privacy' --glob '!.cache'` finds nothing.
- [x] 1.7 Leave `.cache/ai4privacy*` on disk; it is gitignored. Verify: `git status --short` lists no `.cache` path.

## 2. Remove `/v1/redact` from the HTTP API

Do this before group 4: it removes one of the two `redact_units` callers, so the tree stays green.

- [x] 2.1 Delete the `/v1/redact` route, `redact_handler`, its `#[utoipa::path]` block, and `build_redact_response`. Verify: `cargo check --workspace`.
- [x] 2.2 Delete the `Mode` enum; drop the `mode` parameter from `process` and the `content_type`, `original_body`, and `mode` parameters from `handle_scanner_failure`. Verify: `cargo test -p voidwall --lib http_api`.
- [x] 2.3 Update the OpenAPI surface: drop `redact_handler` from `paths(...)`, reword the `info(description = ...)` and the `pii` tag description, and collapse the `["/v1/scan", "/v1/redact"]` loop in `expand_supported_content_types` with its response-content branch. Verify: `cargo test -p voidwall --test http_api_integration openapi`.
- [x] 2.4 Update the CORS comment that justifies `allow_origin(Any)` by naming `/v1/redact`. Verify: `rg 'v1/redact' crates/voidwall/src` finds nothing.

## 3. Reference the spec before changing behaviour

- [x] 3.1 Confirm `structured/json.rs` and `structured/csv.rs` offset tests cover escape sequences, nested arrays, and CSV quoting — after this change they are the only guard on offset correctness, which `pii-scanning` now requires as *Fragment offsets are document-absolute*. Add cases for any gap. Verify: `cargo test -p voidwall --lib structured`.

## 4. Collapse the config, fold block into the proxy, delete `action.rs` (atomic)

- [x] 4.1 In `config.rs`, reduce `DirectionConfig` to `{ scan: bool }` with `scan` defaulting to true, and delete `Action`, `RedactStrategy`, `default_block_status`, and `DirectionConfig::with_actions`. Verify: compiles after 4.3.
- [x] 4.2 In `config.rs`, delete `redact_strategy` and `mask_char` from `HttpApiConfig`; delete `DirectionKind`, `validate_direction_config`, `validate_forward_proxy`, and `validate_http_api` with their calls in `validate()`. Keep `validate_reverse_proxy`, which still checks duplicate `path_prefix` and upstream URLs. Verify: compiles after 4.3.
- [x] 4.3 Delete `crates/voidwall/src/action.rs` and its `pub mod action;` in `lib.rs`. Verify: `cargo check --workspace`.
- [x] 4.4 In `reverse_proxy.rs`, replace the four action fields of `ReverseProxyState` with `request_scan` and `response_scan`; collapse `PipelineResult` to `Block | Pass | Error`; delete `pipeline_result_from_outcome`, `apply_redacted_headers`, `rebuild_uri`, and `string_of`. Verify: `cargo check --workspace`.
- [x] 4.5 Make `run_engine` always pass `BlockPolicy::AnyFinding`, increment detections per kind and blocked once, and return the fixed 403 carrying `error` and a sorted `kinds` array. Add a private metric-context struct in place of `ActionContext`. Verify: `cargo test -p voidwall --lib reverse_proxy`.
- [x] 4.6 Drop the `content-length` removal in the response path — it existed because redaction changed body size. Verify: `cargo test -p voidwall --test reverse_proxy_integration clean_request`.
- [x] 4.7 Delete `REDACTED_TOTAL`, `inc_redacted`, and `inc_redacted_increments` from `metrics.rs`. Verify: `cargo test -p voidwall --lib metrics`.
- [x] 4.8 Rewrite the `config.rs` unit tests: delete the ones testing removed rules, replace `valid_empty_actions_disables_scanning` with a `scan = false` case, update both defaults tests and the round-trip fixture, and strip `actions = []` boilerplate. Add cases rejecting `actions`, `block_status`, and `redact_strategy` as unknown keys. Verify: `cargo test -p voidwall --lib config`.
- [x] 4.9 Re-anchor `validate.rs`: `schema_error_categorised_as_schema` uses `actions = ["redact"]` (now a schema error), and `semantic_error_categorised_as_semantic` uses a duplicate `path_prefix`, the closest surviving semantic rule. Verify: `cargo test -p voidwall --lib validate`.
- [x] 4.10 Add a unit test asserting the block response is fixed: status 403, JSON content type, sorted `kinds`, and byte-identical bodies across two scans of the same content. This is the guarantee that leaves with `action.rs`. Verify: `cargo test -p voidwall --lib reverse_proxy block`.

## 5. Prune the redaction surface

- [x] 5.1 Delete `RedactWith`, `to_redact_with`, the `RedactStrategy` import, and the three `to_redact_with_*` tests from `scanner.rs`. Keep everything else in the file. Verify: `cargo test -p voidwall --lib scanner`.
- [x] 5.2 Drop `redact_strategy` from `ApiState` and `build_state` in `http_api.rs`. Verify: `cargo check --workspace`.

## 6. Dead-code cascade in the engine

- [x] 6.1 Delete `Unit.label` and drop the header name from the unit push path. Verify: `cargo check --workspace`.
- [x] 6.2 Delete `UnitContent::source_str` and `UnitContent::source`. Verify: `cargo check --workspace`.
- [x] 6.3 Delete the `raw: Bytes` field of `UnitContent::Structured` and stop building it in `classify_body`; update the hand-written `Debug` impl. Verify: `cargo test -p voidwall --lib unit`, with `debug_never_prints_the_content` still passing — it backs a `security` requirement.
- [x] 6.4 Rewrite the unit tests that read the removed items: `regex_pii.rs` uses `content.source()`, and `reverse_proxy.rs::push_scan_headers_picks_configured` asserts `label` and `source_str`. Verify: `cargo test -p voidwall --lib`.
- [x] 6.5 Rename `engine/mod.rs::a_redacting_finding_does_not_abandon_a_guard_still_running` to name the non-blocking policy it actually exercises. Verify: `cargo test -p voidwall --lib engine`.
- [x] 6.6 Reword the doc comments in `engine/{finding,guard,mod,unit}.rs` and `structured/{mod,json,csv}.rs` that justify offsets and unit identity by redaction, tying them to overlap resolution and match counting instead. Verify: `rg -n redact crates/voidwall/src` finds nothing.

## 7. Integration tests

- [x] 7.1 In `reverse_proxy_integration.rs`, replace the four direction fixtures with `scan` on and off, and delete the redaction, header, and custom-block-status tests. Verify: the file compiles.
- [x] 7.2 Rewrite the surviving redaction tests to assert a 403 and its `kinds`, keeping their inputs so query-string, header, custom-PII, and person-name coverage survives. Verify: `cargo test -p voidwall --test reverse_proxy_integration`.
- [x] 7.3 Add a test asserting the 403 body kinds are sorted and stable across two identical requests. Verify: same command.
- [x] 7.4 In `http_api_integration.rs`, delete every `redact_*` test, drop the redaction parameters from the test-server builder, and assert the OpenAPI document declares no `/v1/redact`. Add a case asserting `POST /v1/redact` answers 404. Verify: `cargo test -p voidwall --test http_api_integration`.
- [x] 7.5 Rewrite all nine `structured_scanning_integration.rs` tests to assert detection rather than redacted output, keeping every input. This file is the only coverage that JSON key paths and CSV column headers reach the scanner. Keep `json_parse_failure_fail_close_blocks_request` — it blocks through `on_error`, not detection. Verify: `cargo test -p voidwall --test structured_scanning_integration`.
- [x] 7.6 Update `validate_cli_integration.rs` fixtures to the `scan` schema and convert the unknown-action case to a retired-key case. Verify: `cargo test -p voidwall --test validate_cli_integration`.
- [x] 7.7 Run the whole suite. Verify: `cargo test --workspace` and `cargo clippy --workspace --all-targets` with no warnings.

## 8. Bench and deployment configuration

- [x] 8.1 Rewrite the surviving `benches/configs/*.toml` to the `scan` schema and delete the header, redact, and no-actions configurations. Verify: `cargo run -p voidwall -- --validate <each file>` exits 0.
- [x] 8.2 Delete `benches/k6/action_comparison.js`, remove its scenario from `benches/run.sh` and `benches/README.md`, and fix the stale redact comments and the `ENDPOINT` default in the remaining k6 scripts. Verify: `bash -n benches/run.sh` and `benches/run.sh baseline` completes.
- [x] 8.3 Switch the PII payload to clean content in the scenarios that measure proxying cost — a 403 now stops the message at the proxy, so the forward path is otherwise unmeasured. Note the `structured_scanning` re-baseline. Verify: `benches/run.sh body_size_scaling` reaches the upstream.
- [x] 8.4 Rewrite `docker/voidwall.toml` with both direction tables stated explicitly, so the response direction does not inherit `scan = true` and begin blocking. Remove `[http_api] redact_strategy`. Verify: `cargo run -p voidwall -- --validate docker/voidwall.toml` exits 0.
- [x] 8.5 Remove the `voidwall_pii_redacted_total` series from `docker/grafana/dashboards/voidwall.json` and retitle the panel. Verify: `jq . docker/grafana/dashboards/voidwall.json` parses and `rg redacted docker/grafana` finds nothing.
- [x] 8.6 Update `docker/demo/index.html`: drop the `/v1/redact` option and the redacted-count display, and reword the intro. Verify: `docker/ctl start` and the demo page posts to `/v1/scan` successfully.

## 9. Documentation

- [x] 9.1 Update `ARCHITECTURE.md`: the opening description, the action-engine box in the diagram, the module list, request-path steps 7 to 9, §4.1, §4.3, §4.4, and the crate table. Verify: `rg -n 'redact|X-PII|action engine' ARCHITECTURE.md` finds nothing.
- [x] 9.2 Update `AGENTS.md`: the opening paragraph, the module list, the Detection Engine paragraphs, the Match Resolution line naming `/v1/redact`, the Configuration line, and delete the Action Precedence section. Verify: `rg -n 'redact|header action' AGENTS.md` finds nothing.
- [x] 9.3 Update the `context` block of `openspec/config.yaml` in all three places: the product sentence, the match-resolution phrasing, and the action-precedence paragraph. Verify: `openspec validate remove-configurable-actions --strict`.
- [x] 9.4 Update `.agents/skills/code-review/SKILL.md` — its checklist asserts the old action precedence and would flag this change as a regression. Verify: `rg -n 'precedence|redact' .agents/skills/code-review/SKILL.md` finds nothing stale.
- [x] 9.5 Update `docs/api-docs.md`, `docs/custom-pii.md` (keep the keyword-span statement, drop only the redaction justification), `docs/config-validation.md` (replace the block-plus-header semantic example with duplicate `path_prefix`), and `docs/backlog.md`. Verify: `rg -n 'redact|X-PII' docs/*.md` returns only intentional text.
- [x] 9.6 Rewrite `docs/load-testing.md`: delete the Action Comparison section, fix every setup line, the Test Configs list, and the Success Criteria rows. Note in the change that this file already carried pre-existing drift — it names a `warn` action and two configurations that have never existed. Verify: every config named in the file exists on disk.
- [x] 9.7 Add this change to `docs/roadmap.md` ahead of Configurable Guard and Policy Design, and flag that `voidwall-internal/research/guardrails-roadmap.md` needs the same entry — it lives in another repository and is not edited here. Verify: `docs/roadmap.md` lists the entry.

## 10. Close out

- [x] 10.1 Confirm an old configuration fails loudly. Verify: `cargo run -p voidwall -- --validate` on a file carrying `actions = ["redact"]` exits non-zero naming the key.
- [x] 10.2 Confirm end-to-end behaviour. Verify: `docker/ctl start`, then a request carrying a sample email answers 403 with a `kinds` array and no matched text; the same body on `POST /v1/scan` answers 200 with `detected: true`; `/metrics` shows the detection and blocked counters and no `voidwall_pii_redacted_total`; `/openapi.json` lists three routes.
- [x] 10.3 Run the full gate. Verify: `cargo test --workspace`, `cargo clippy --workspace --all-targets`, `cargo check --workspace --all-features`.
- [x] 10.4 Review the diff against the spec deltas with the `code-review` skill. Verify: no finding outstanding.
