## 1. Kinds, validators, and the deny list

- [x] 1.1 Add the 20 `PiiKind` variants of design D1 to `crates/voidwall-pii/src/lib.rs`
  and update every inventory and mapping method there (label, country
  `International`, `all()`). Verify: `cargo check --workspace` fails only on the
  exhaustive match in `crates/voidwall-eval/src/label.rs`.
- [x] 1.2 Map the 20 kinds to no label (`&[]`) in `labels_for` in
  `crates/voidwall-eval/src/label.rs`, beside the AWS kinds. Verify:
  `cargo test -p voidwall-eval` passes.
- [x] 1.3 Confirm the current jwt.io sample token and the AWS docs sample values. Add the
  known-sample deny list to `crates/voidwall-pii/src/validators.rs` (design D7), with
  `#[test_case]` tests for each listed value and for a one-character variant. Verify:
  `cargo test -p voidwall-pii validators` passes.
- [x] 1.4 Switch `AwsAccessKey` (`hyperscan_detector.rs`) and `AwsSecretKey`
  (`keyword_context_detector.rs`) from `Check::Any` to the deny-list check. Replace the
  sample values in their positive tests and in `scanner.rs` with real-shaped values that
  are not on the list, and add negative cases for the sample values. Verify: spec
  scenarios "The AWS docs sample key is not reported" and "A real-shaped AWS key is still
  reported" pass in `cargo test -p voidwall-pii`.

## 2. Checksums

- [x] 2.1 Confirm the npm checksum input (with or without `npm_`) and the base62 alphabet
  against one real npm token that is then revoked. This needs a person with an npm
  account. Record the result in design D6. Verify: the recomputed checksum of that token
  equals its last 6 characters.
- [x] 2.2 Add `crc32fast` as a direct dependency of `voidwall-pii`. Add the GitLab routable
  and npm checksum validators to `validators.rs`, with tests built from tokens the test
  itself generates by the design D6 rule, plus one wrong-checksum case each. Verify:
  `cargo test -p voidwall-pii validators` passes and `cargo deny check licenses` passes.

## 3. Patterns

Each task adds `PatternDef`s with `som_fallback: true` and a structure validator (design D2,
D3), and extends the parameterized positive and negative tests in
`hyperscan_detector.rs`. Test values are synthetic, never real keys.

- [x] 3.1 AI providers: `OpenAiApiKey`, `AnthropicApiKey`, `OpenRouterApiKey`,
  `PerplexityApiKey`, `XaiApiKey`, `GroqApiKey`, `ReplicateApiToken`, `FirecrawlApiKey`.
  Use the minimums of design D4. Verify: spec scenarios "A provider key is reported", "A
  prefix with too short a body is not reported", "A long body is reported", and "A body
  below the minimum is not reported" pass.
- [x] 3.2 Platforms: `SlackToken` (tokens and webhook URLs), `StripeSecretKey`,
  `GoogleApiKey`, `GitlabToken` (legacy and routable, with the checksum of 2.2),
  `HuggingFaceToken`, `NpmToken` (with the checksum of 2.2), `PypiToken`,
  `SupabaseSecretKey`, `AzureAdClientSecret`. Verify: spec scenarios "Two token types of
  one provider share a kind", "A shape inside a longer run is not reported", the four
  test-key scenarios, and the three checksum scenarios pass.
- [x] 3.3 Structural kinds: `PrivateKey`, `Jwt` (with the deny-list check), and
  `UrlCredentials` with the placeholder validator of design D8. Verify: the private-key,
  JWT, jwt.io-sample, and four `URL_CREDENTIALS` spec scenarios pass.
- [x] 3.4 Check overlap: run every new positive test value, alone and beside an email
  address, an IP address, and each other, through `resolve_overlaps`. Add a
  `PRIORITY_GROUPS` entry in `overlap.rs` only if an equal-span pair of two kinds appears
  (design D9). Verify: `cargo test -p voidwall-pii overlap` passes and each test value
  resolves to its own kind.

## 4. Proxy-level checks

- [x] 4.1 Add a config test in `crates/voidwall/src/config.rs`: a custom entry with label
  `OPENAI_API_KEY` fails validation naming the collision, and `ignore = ["Jwt"]`
  parses. Verify: `cargo test -p voidwall config` passes.
- [x] 4.2 Add an integration test in `crates/voidwall/tests/http_api_integration.rs`: with
  the default `[builtin_guards.pii]` config, `/v1/scan` on a body holding a synthetic
  `r8_<37>` token reports `REPLICATE_API_TOKEN`, and with `ignore = ["Jwt"]` a body
  holding a JWT reports nothing. Verify: spec scenarios "A default guard reports a new
  kind" and "One provider is ignored" pass.
- [x] 4.3 Regenerate `docs/openapi.json` with
  `UPDATE_OPENAPI=1 cargo test -p voidwall --lib openapi`. Verify: the freshness test
  passes and the diff shows only the 20 new labels.

## 5. Benchmarks

- [x] 5.1 Record a baseline: `cargo bench -p voidwall-pii` on the current mixed corpus,
  before the patterns of section 3. Verify: the baseline numbers are saved in the change
  folder.
- [x] 5.2 Update `crates/voidwall-pii/benches/pii_benchmark.rs`: a realistic corpus and a
  per-kind entry for each new kind, a mixed-input sample holding several secrets, and the
  replaced AWS sample values. Add a separate `AzureAdClientSecret` entry (design Risks).
  Verify: `cargo bench -p voidwall-pii` runs, and the mixed-corpus result is compared with
  5.1 and recorded.

## 6. Checks

- [x] 6.1 Run `cargo test --workspace` and `cargo clippy --workspace --all-targets`.
  Verify: both pass with no warning.
- [x] 6.2 Review the diff against `specs/secret-detection/spec.md` and `ARCHITECTURE.md`
  with the `code-review` skill. Verify: every spec scenario maps to a passing test, and
  no test or log line holds a real key.
