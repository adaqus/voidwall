Two design open questions are resolved here as stated assumptions, both easy to change:
the first adapter names are `text_classifier` and `text_multilabel_classifier`, and an
adapter's score range is `0.0..=1.0` inclusive.

## 1. Config types

- [x] 1.1 Add `ModelGuardSurface` to `config.rs` with `body` defaulting to true and
  `url_path`, `query_params`, `headers` defaulting to false, `deny_unknown_fields`.
  *Verify*: a unit test deserialising `url_path = true` alone asserts body true, query
  false, headers false — the partial-table case design.md calls the footgun.
- [x] 1.2 Add `headers: bool` to `GuardSurface`, defaulting true, and extend
  `Interest::from_surface` so `headers = false` drops `UnitKind::HeaderValue`.
  *Verify*: `guard.rs` tests — the existing `every_surface_admits_header_values` is
  rewritten to assert the default admits headers and `headers = false` does not.
- [x] 1.3 Add `Adapter`, a fieldless enum deserialising `text_classifier` and
  `text_multilabel_classifier`, carrying its score range.
  *Verify*: `#[test_case]` over both names plus one unknown name asserting a schema error.
- [x] 1.4 Add `ModelGuardConfig` with `adapter`, `model_path`, `tokenizer_path`,
  `max_tokens`, `labels`, `thresholds`, `surface`, `deny_unknown_fields`.
  *Verify*: a unit test loads the smallest valid section from § 3 of the research doc; a
  second asserts `runtime = "onnx"` is rejected as an unknown field.
- [x] 1.5 Add `guards: BTreeMap<String, ModelGuardConfig>` to `AppConfig`, defaulting empty.
  *Verify*: `cargo test -p voidwall config` passes with every existing config fixture
  unchanged, proving the key is optional.

## 2. Guard name rules

- [x] 2.1 Extend `validate_configured_guard_name` with the ASCII `[a-zA-Z0-9_-]` charset,
  a non-empty check, and a 64-character cap, keeping the reserved-name check.
  *Verify*: `#[test_case]` over `injection`, `injection_check`, `general-safety` accepted
  and `injection.v2`, `""`, a 65-character name, `pii` rejected.
- [x] 2.2 Call it for every key in `AppConfig.guards` during validation — it has no caller
  today.
  *Verify*: an integration-style config test asserts a file declaring `[guards."inj.v2"]`
  fails to load, naming the guard.

## 3. Startup validation

- [x] 3.1 Reject a `thresholds` key absent from that guard's `labels`. A label itself is
  not checked against a vocabulary: the build has no closed set of finding kinds.
  *Verify*: a unit test asserting the message names the guard and the kind, and a second
  asserting a label the build has never heard of still loads.
- [x] 3.2 Reject a threshold outside its adapter's range, and a surface with all four
  targets disabled.
  *Verify*: two unit tests asserting the message names the guard, and for the threshold
  case the range.
- [x] 3.3 Report a missing `model_path` or `tokenizer_path` with the expected path, under
  the `file` category; give every other new failure the `semantic` category.
  *Verify*: a test per category asserting the category and that the message holds the path
  or the guard name.
- [x] 3.4 Confirm validation never opens an artifact.
  *Verify*: a test pointing `model_path` at a temp file holding non-model bytes asserts the
  config loads.
- [x] 3.5 Reject an empty `labels` list, a label listed twice, and a `max_tokens` below
  the floor of 10.
  *Verify*: a unit test per rule asserting the message names the guard, and the label or
  the limit; plus one asserting `max_tokens` exactly on the floor is accepted.
- [x] 3.6 Gate the header-unit collection on the selection's interest, so a unit kind no
  selected guard admits is not built — the rule the path and the query already follow.
  *Verify*: a `reverse_proxy.rs` test asserting a selection with `headers = false` builds
  no header unit from a header the route named.

## 4. Startup behaviour

- [x] 4.1 Log one warning at startup naming every configured model guard as configured but
  not executed, alongside the existing empty-guard-set warning. Build no guard.
  *Verify*: an integration test in `crates/voidwall/tests/` starts the proxy with one model
  guard configured and asserts it starts and serves.
- [x] 4.2 Confirm a route may select a configured model guard by name without failing
  validation, and that the route's other guards still run.
  *Verify*: an integration test with `guards = ["pii", "injection"]` asserts a PII body is
  still blocked with 403.

## 5. Documentation and examples

- [x] 5.1 Add a commented `[guards.*]` example to `docker/voidwall.toml`, left disabled or
  absent so the image's default start is unchanged.
  *Verify*: `cargo run -- --config docker/voidwall.toml --validate` (or the existing
  pre-flight path) exits zero.
- [x] 5.2 Update `docs/config-validation.md` with the new failure categories and messages.
  *Verify*: every message in the doc appears verbatim in a test assertion.
- [x] 5.3 Update `ARCHITECTURE.md` where it describes the guard set and the scan surface,
  including that `headers` is now a per-guard boolean.
  *Verify*: read the diff against `specs/guard-configuration/spec.md` in this change.

## 6. Verification

- [x] 6.1 Run `cargo test --workspace` and `cargo clippy --workspace --all-targets`,
  treating a warning as an error.
  *Verify*: both exit zero.
- [x] 6.2 Review the diff against this change's spec deltas and then `ARCHITECTURE.md`
  using the `code-review` skill.
  *Verify*: every requirement in both delta files maps to a test.
- [x] 6.3 Confirm no bench config under `crates/voidwall/benches/configs/` broke.
  *Verify*: each config loads through the pre-flight validation path.
