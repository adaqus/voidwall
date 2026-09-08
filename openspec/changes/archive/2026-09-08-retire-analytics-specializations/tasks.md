Ordered by dependency: the module and its consumers go first, because everything after them
is edited against a tree that already compiles without a `Specialization`.

## 1. Delete the module and its consumers

- [x] 1.1 Delete `crates/voidwall/src/specialization/` and its `pub mod specialization;`
  declaration in `lib.rs` → verify: `grep -rn "specialization\|Specialization" crates/voidwall/src`
  returns nothing.
- [x] 1.2 Remove the specialization branch from both scan directions in `reverse_proxy.rs`,
  the `specialization` field on the route state, its resolution in `build_state`, and the
  two `merge_with_default_scan` call sites → verify: a route with a body and a query is
  scanned by the default path, and `cargo test -p voidwall reverse_proxy` passes.
- [x] 1.3 Delete the in-file specialization pipeline tests in `reverse_proxy.rs`, including
  the `PipelineOkSpec`, `PipelineDecodeSpec`, and `PipelineUnsupportedSpec` doubles and
  `build_state_resolves_route_specialization` → verify: `cargo test -p voidwall reverse_proxy`
  passes with no test referencing a specialization.
- [x] 1.4 Remove the `?specialization=` query parameter, `resolve_specialization`, the
  specialization body path, both aggregate response builders, the `X-PII-Specialization`
  header, and the two OpenAPI parameter declarations from `http_api.rs` → verify:
  `cargo check --workspace` passes and the generated OpenAPI document names no
  `specialization` parameter.
- [x] 1.5 Delete `ga4_integration.rs`, `ga4_spec_integration.rs`, `matomo_integration.rs`,
  and `matomo_spec_integration.rs` → verify: `cargo test --workspace` passes.

## 2. Configuration

- [x] 2.1 Remove the `specialization` field from `Route` and its startup validation, and
  delete the three unit tests covering a known, an absent, and an unknown name rather than
  adapting them → verify: `cargo check --workspace` passes and no config test names a
  specialization.
- [x] 2.2 Add `#[serde(deny_unknown_fields)]` to all ten `Deserialize` structs in `config.rs`
  → verify: a unit test asserts that a file carrying an undefined key fails validation naming
  the key, and a second asserts that a route carrying `specialization` fails the same way.
- [x] 2.3 Confirm every configuration file in the repository still validates → verify:
  `cargo run -p voidwall -- --validate <path>` exits 0 for `docker/voidwall.toml` and for each
  of the nine surviving files under `crates/voidwall/benches/configs/`.

## 3. Metrics and actions

- [x] 3.1 Remove `voidwall_specialization_errors_total`, `inc_specialization_error`, and the
  `specialization` label from `voidwall_pii_detections_total` and
  `voidwall_pii_redacted_total`, together with their unit tests → verify: `cargo test -p voidwall metrics`
  passes and no test case names `ga4` or `matomo`.
- [x] 3.2 Remove `ActionContext.specialization` and drop the argument from the two
  `metrics::inc_*` call sites in `action.rs` → verify: `cargo test -p voidwall action` passes.
- [x] 3.3 Confirm the scrape output carries six families and no `specialization` label →
  verify: an admin integration test asserts that `/metrics` exposes no
  `voidwall_specialization_errors_total` and that a detection sample carries no
  `specialization` label.

## 4. Remaining integration tests

- [x] 4.1 Delete the specialization tests in `http_api_integration.rs` (the block headed
  "Specialization (`?specialization=`) tests") and the OpenAPI parameter assertion → verify:
  `cargo test -p voidwall --test http_api_integration` passes and the file names no
  specialization.
- [x] 4.2 Remove the `specialization: None` route literals in `reverse_proxy_integration.rs`
  and `structured_scanning_integration.rs` → verify: both test files compile and pass.
- [x] 4.3 Confirm `crates/voidwall/src/structured/` was not touched → verify:
  `git diff --stat crates/voidwall/src/structured/` is empty and
  `cargo test -p voidwall --test structured_scanning_integration` passes.

## 5. Load tests and Docker surfaces

- [x] 5.1 Delete `k6/ga4_g_collect.js`, `k6/ga4_mp_collect.js`, `k6/matomo_specialization.js`,
  `configs/reverse_proxy_ga4.toml`, and `configs/reverse_proxy_matomo.toml`; remove the three
  scenarios from all three scenario lists in `run.sh` (the usage comment, `ALL_SCENARIOS`, and
  the argument-validation `case`), from their dispatch blocks, and from the `README.md` table;
  drop the response-dispatch comment in `echo_server.rs` → verify:
  `grep -n "ga4\|matomo" crates/voidwall/benches/run.sh crates/voidwall/benches/README.md`
  returns nothing, and `benches/run.sh structured_scanning` still completes and prints a
  summary row.
- [x] 5.2 Remove the specialization comment block and the two commented route examples from
  `docker/voidwall.toml` → verify: `docker/ctl start` brings the stack up and the proxy
  serves a request.
- [x] 5.3 Remove the Specialization dropdown, its two example buttons, and the `spec` field
  and `x-pii-specialization` read in `docker/demo/index.html` → verify: the demo page loads,
  the JSON, CSV, and plain-text examples still post and still report detections.

## 6. Documentation and specs

- [x] 6.1 Delete `docs/specializations.md` → verify: `grep -rn "specializations.md" docs AGENTS.md ARCHITECTURE.md`
  returns nothing.
- [x] 6.2 Remove § 4.4 and the four other specialization references in `ARCHITECTURE.md`
  (the module list, the scan-stage note, the crate responsibility table, and the decision-log
  row) → verify: `grep -n "specialization\|GA4\|Matomo" ARCHITECTURE.md` returns nothing.
- [x] 6.3 Remove § 1.4 and § 1.5 and the `docs/specializations.md` bullet from
  `docs/backlog.md` → verify: `grep -n "specialization" docs/backlog.md` returns nothing.
- [x] 6.4 Confirm the Grafana dashboard needs no edit → verify:
  `grep -c specialization docker/grafana/dashboards/voidwall.json` is 0 and every Voidwall
  panel still renders against a running stack.

## 7. Close out

- [x] 7.1 Run the full gate → verify: `cargo test --workspace` passes and
  `cargo clippy --workspace --all-targets` reports no warning.
- [x] 7.2 Review the diff against the spec deltas with the `code-review` skill → verify: the
  review reports no requirement implemented differently from its delta.
- [x] 7.3 Archive the change → verify: `openspec archive retire-analytics-specializations`
  succeeds and `openspec/specs/specializations/` is gone.
