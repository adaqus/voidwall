## 1. Configuration types

- [x] 1.1 Add top-level `max_body_size`, `content_types`, and `on_error` to `AppConfig`
  with their current defaults. Verify: a unit test asserts each default when the key is
  absent, and `cargo test -p voidwall config` passes.
- [x] 1.2 Add `GuardSurface` with `url_path`, `query_params`, and `body`, each
  defaulting to true, and put the header allowlist on `Route` instead. Verify: a unit
  test asserts the default surface, one with `body = false`, that `surface.headers` is
  rejected, and that a route carries its own header list.
- [x] 1.3 Add `BuiltinGuards` holding `pii: Option<PiiGuardConfig>`, and
  `PiiGuardConfig` carrying `enabled` (default true), `countries`, `languages`,
  `scanner_threads`, `detect`, `ignore`, `custom`, and `surface`. Verify: a unit test
  parses a section without `enabled` and finds it enabled, and one with
  `enabled = false` and finds it disabled.
- [x] 1.4 Remove `PiiConfig` and `ScanConfig` and the `pii` and `scan` fields of
  `AppConfig`. Verify: `cargo check --workspace` fails nowhere, and a unit test asserts
  that a config holding `[pii]` or `[scan]` is rejected with the `schema` category.
- [x] 1.5 Replace `Route.scan` with `Route.guards: Option<Vec<String>>`. Verify: a unit
  test parses a route with `guards = ["pii"]`, one with `guards = []`, and one with no
  `guards` key, and asserts the three resolved guard sets.
- [x] 1.6 Move `effective_scanner_threads` onto `PiiGuardConfig`. Verify: the existing
  thread-count tests pass unchanged against the new owner.

## 2. Validation

- [x] 2.1 Reject an unknown key under `[builtin_guards]`. Verify: a unit test asserts
  that `[builtin_guards.jailbreak]` fails validation naming the unknown guard.
- [x] 2.2 Reject a configured guard taking a reserved built-in name. Verify: a unit test
  asserts the failure names `pii` and carries the `semantic` category.
- [x] 2.3 Reject a `route.guards` entry naming a guard that is not enabled. Verify: a
  unit test asserts the failure names the guard and carries the `semantic` category.
- [x] 2.4 Move the `detect`/`ignore` exclusivity, country reachability, custom-entry cap,
  label collision, and duplicate-label checks onto the guard section. Verify: the
  existing validation tests pass against the new paths.
- [x] 2.5 Warn once at startup when no guard is enabled, and start anyway. Verify: an
  integration test starts the binary with every guard disabled, asserts it serves
  traffic unscanned, and asserts the warning is logged.

## 3. Engine

- [x] 3.1 Change `Guard::name()` and `Finding::guard` to `Arc<str>`. Verify:
  `cargo check --workspace` passes and the canonical-order test still sorts by guard
  name.
- [x] 3.2 Build `Interest` from a guard's configured `surface` instead of a fixed set.
  Verify: a unit test asserts that a guard with `surface.body = false` is not called
  with the body unit.
- [x] 3.3 Build the engine's guard list from `BuiltinGuards`, skipping a disabled or
  absent guard. Verify: a unit test asserts no `ScannerPool` thread starts when the PII
  guard is disabled.
- [x] 3.4 Give the engine a per-route guard selection, so `Engine::guard` runs only the
  named guards. Verify: a unit test asserts an empty selection calls no guard and
  returns no findings.

## 4. Handlers

- [x] 4.1 Build units from the union of the selected guards' surfaces, so a unit no
  selected guard wants is never constructed. Verify: a unit test asserts that no header
  unit is built when no selected guard lists a header.
- [x] 4.2 Read the top-level `max_body_size` and `content_types` in the reverse proxy and
  the HTTP API. Verify: the existing 413 and 415 tests pass against the new paths.
- [x] 4.3 Resolve a route's guard set in the reverse proxy, falling back to every enabled
  guard. Verify: an integration test drives two routes, one with `guards = []` and one
  without the key, and asserts the first forwards PII and the second blocks it.
- [x] 4.4 Run every enabled guard in the HTTP API, which carries no guard selection.
  Verify: the existing `/v1/scan` detection tests pass.

## 5. Example configuration and documentation

- [x] 5.1 Rewrite `docker/voidwall.toml` in the new format, ingest keys first. Verify:
  `cargo run -- --validate docker/voidwall.toml` succeeds.
- [x] 5.2 Rewrite the seven bench configs under `crates/voidwall/benches/configs/`.
  Verify: each passes `--validate`, and the scanner-thread bench still varies the thread
  count it is named for.
- [x] 5.3 Update `docs/custom-pii.md` for `[[builtin_guards.pii.custom]]`. Verify: every
  TOML block in the file passes `--validate` when pasted into a minimal config.
- [x] 5.4 Replace the guard-name rule in `CLAUDE.md`, `engine/guard.rs`, and
  `engine/finding.rs` with "bounded by startup configuration, never by request content".
  Verify: `grep -rn "operator-supplied"` over those three files shows no claim that a
  guard name cannot be one.

## 6. Integration tests

- [x] 6.1 Assert a config in the old format is rejected at startup naming `pii` or
  `scan`. Verify: the test asserts a non-zero exit and the offending key in the message.
- [x] 6.2 Assert two guard surfaces are applied independently once more than one guard
  can exist. Verify: a test engine with two stub guards, one admitting the body and one
  the query, asserts each receives only its own units.
- [x] 6.3 Assert a route with `guards = []` forwards a body holding a placeholder PII
  value unchanged. Verify: the upstream receives the body and the response is not 403.

## 7. Workspace verification

- [x] 7.1 Run `cargo test --workspace`. Verify: every test passes.
- [x] 7.2 Run `cargo clippy --workspace --all-targets`. Verify: no warning.
- [x] 7.3 Run `openspec validate restructure-guard-configuration --strict`. Verify: the
  change reports valid.
- [x] 7.4 Review the diff against the spec deltas with the `code-review` skill. Verify:
  every delta requirement maps to code and a test.
