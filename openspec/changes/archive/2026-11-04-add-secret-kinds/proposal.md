## Why

The regex `pii` guard detects three secret kinds: `AWS_ACCESS_KEY`, `AWS_SECRET_KEY`, and
`GITHUB_TOKEN`. OWASP LLM02 (Sensitive Information Disclosure) and LLM08 scenario 1 ask for
more, and the competitor survey found Slack and generic API keys in other products. This is
priority 1 of the OWASP coverage analysis (item B). Leak data (GitGuardian 2026) shows that
leaks of AI-service keys grew 81 % in one year.

## What Changes

- 20 new `PiiKind`s in `voidwall-pii`, one kind per provider, all `Country::International`:
  - Provider tokens: `OPENAI_API_KEY`, `ANTHROPIC_API_KEY`, `SLACK_TOKEN`,
    `STRIPE_SECRET_KEY`, `GOOGLE_API_KEY`, `GITLAB_TOKEN`, `HUGGINGFACE_TOKEN`, `NPM_TOKEN`,
    `PYPI_TOKEN`, `AZURE_AD_CLIENT_SECRET`, `SUPABASE_SECRET_KEY`.
  - Commonly leaked AI services with a unique prefix: `OPENROUTER_API_KEY`,
    `PERPLEXITY_API_KEY`, `XAI_API_KEY`, `FIRECRAWL_API_KEY`, `GROQ_API_KEY`,
    `REPLICATE_API_TOKEN`.
  - Structural kinds: `PRIVATE_KEY` (PEM header), `JWT`, `URL_CREDENTIALS`
    (`scheme://user:pass@host`).
- Test, sandbox, and publishable keys are not secrets and are not reported: Stripe
  `sk_test_`, `rk_test_`, `pk_`; Supabase `sb_publishable_`; TestPyPI tokens.
- Every Stripe organization key (`sk_org_`) is reported, because its prefix does not show
  live or sandbox mode.
- Where the official docs give no length (Anthropic, xAI, Groq, Supabase), a kind checks a
  minimum length only, with no maximum.
- npm tokens and GitLab routable tokens must pass their CRC32 checksum.
- `URL_CREDENTIALS` does not report a placeholder password: template syntax, a mask, or a
  placeholder word.
- A deny list of documented sample values. A value on it is not reported. It covers the
  existing AWS kinds, so the AWS docs sample keys stop being reported.
- **BREAKING**: a `[builtin_guards.pii]` custom entry whose `label` equals one of the 20 new
  kind names now fails startup validation, by the existing label-collision rule.
- **BREAKING**: the AWS docs sample keys (`AKIAIOSFODNN7EXAMPLE` and its paired secret key)
  are no longer reported.
- `docs/openapi.json` lists the new built-in labels.

Not in this change: keyword-context secrets (`password=`, `api_key=`), which are deferred.
Not included because the prefix is not unique: DeepSeek, Mistral, Clipdrop, Vapi, Cohere.
Brave Search and Supabase `sbp_` tokens are also not included.

## Capabilities

### New Capabilities

- `secret-detection`: the secret kinds of the regex `pii` guard. It covers their shapes,
  what is not a secret (test keys, publishable keys, placeholders, documented samples),
  minimum lengths, and checksums.

### Modified Capabilities

None. The label-collision rule in `configuration` and the generated label list in
`http-api` do not change. Only the set of built-in labels they apply to grows.

## Impact

- `crates/voidwall-pii/src/lib.rs`: 20 `PiiKind` variants, labels, country mapping, and
  inventory.
- `crates/voidwall-pii/src/hyperscan_detector.rs`: new patterns, all as `som_fallback`
  Rust-regex patterns.
- `crates/voidwall-pii/Cargo.toml`: `crc32fast` as a direct dependency (already in
  `Cargo.lock`).
- `crates/voidwall-pii/src/validators.rs`: CRC32 checks, the deny list, and the
  `URL_CREDENTIALS` placeholder check.
- `crates/voidwall-pii/src/overlap.rs`: priority groups if a new kind can share a span with
  another kind.
- `crates/voidwall-pii/benches/pii_benchmark.rs`: corpus and per-kind entries, and new AWS
  sample values.
- Existing AWS tests that use the sample keys as positive cases:
  `keyword_context_detector.rs`, `scanner.rs`, `hyperscan_detector.rs`.
- `crates/voidwall-eval/src/label.rs`: the new kinds in the exhaustive kind match.
- `docs/openapi.json`: regenerated.
- Scan cost: each new fallback pattern adds one linear Rust-regex pass over each unit.
