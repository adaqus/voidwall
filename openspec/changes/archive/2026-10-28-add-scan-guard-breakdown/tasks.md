## 1. Per-guard view over the scan result

- [x] 1.1 Add unit tests in `crates/voidwall/src/engine/finding.rs` for a per-guard
  breakdown: sorted by guard name, one entry per guard, per-guard count, per-guard kinds
  sorted and deduplicated, empty without findings, counts add up to `matches_count()`.
  Verify: the tests fail before 1.2.
- [x] 1.2 Add the per-guard breakdown to `ScanResult`, derived from `findings` like
  `kinds()` and `guards()`. Verify: `cargo test -p voidwall finding` passes.

## 2. `/v1/scan` response

- [x] 2.1 Add `guards` to `ScanResponse` in `crates/voidwall/src/http_api.rs` as an array
  of `{name, matches_count, kinds}` objects, with a `ToSchema` type, doc comments, and the
  schema example extended. Fill it in `build_scan_response`. Verify: `cargo test -p
  voidwall --lib http_api` passes except the OpenAPI freshness test.
- [x] 2.2 Regenerate `docs/openapi.json` with
  `UPDATE_OPENAPI=1 cargo test -p voidwall --lib openapi`. Verify: the freshness test
  passes and the diff shows only the new `guards` schema and example.

## 3. Integration tests

- [x] 3.1 In `crates/voidwall/tests/http_api_integration.rs`, assert that a clean body
  returns `guards` `[]` and a body with PII returns one `pii` entry. Verify: the spec
  scenario "Body is clean" passes.
- [x] 3.2 In `crates/voidwall/tests/model_guard_integration.rs`, configure the `pii` guard
  with `detect = ["Email"]` and a custom definition labelling `trigger` as `SECRET`, and a
  token classifier `pii_ml` labelling `trigger` as `SECRET`. Post a body holding `trigger`
  and assert `matches_count` 2, `kinds` `["SECRET"]`, and `guards` holding `pii` and
  `pii_ml` with one `SECRET` each. Post a body holding only an email address and assert
  `guards` holds `pii` alone. Verify: the spec scenarios "Two guards report the same kind
  for one value" and "Only guards with findings are listed" pass.

## 4. Documentation

- [x] 4.1 Update the `/v1/scan` example outputs in `README.md` (lines 36, 105, 113) to
  show `guards`. Verify: each example matches a real response of the shipped image config.
- [x] 4.2 In `docs/model-guards.md` near the `matches_count` paragraph, say that `guards`
  shows each guard's share. Verify: the text matches the spec delta.

## 5. Checks

- [x] 5.1 Run `cargo test --workspace` and `cargo clippy --workspace --all-targets`.
  Verify: both pass with no warnings.
- [x] 5.2 Run `openspec validate add-scan-guard-breakdown --strict`. Verify: it passes.
