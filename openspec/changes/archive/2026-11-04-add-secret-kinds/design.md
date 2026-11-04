## Context

See proposal.md for the motivation and specs/secret-detection/spec.md for the requirements.
The formats, their sources, and the leak data are in the internal research note
`voidwall-internal/research/owasp-coverage/item-b-secret-formats.md`.

Current state of `voidwall-pii`:

- `HyperscanDetector` holds one `PatternDef` per kind: an expression, a `Check` validator,
  and `som_fallback`. A pattern with `som_fallback: false` goes into one Vectorscan database
  with `SOM_LEFTMOST`. A pattern with `som_fallback: true` never enters Vectorscan. Both
  `has_piis` and `mark_piis` run it as its own Rust `regex` `find_iter` over the whole unit
  (`hyperscan_detector.rs` lines 349, 466, 528). `GITHUB_TOKEN` and `BitcoinAddress` use
  this path because long repeats under `SOM_LEFTMOST` grow the Vectorscan database.
- A `Check` is `Any` or `With(fn(&str) -> bool)`. It sees the matched text only, not the text
  around it.
- `AWS_ACCESS_KEY` is a Vectorscan pattern with `Check::Any`. `AWS_SECRET_KEY` is a
  keyword-context pattern with `Check::Any`.
- Configuration names a kind by its Rust variant name (`detect = ["Email"]`). The 403,
  `/v1/scan`, and metrics use its label (`EMAIL`).
- `crc32fast` 1.5.0 is already in `Cargo.lock` as a transitive dependency.

## Goals / Non-Goals

**Goals:**

- Add the 20 kinds with the existing `PatternDef` and `Check` mechanism. No new detector.
- Keep the false-positive filters (deny list, test keys, placeholders, checksums) in
  validators, so `has_piis` and `mark_piis` cannot disagree.

**Non-Goals:**

- Checking the `GITHUB_TOKEN` CRC32. It uses the same scheme as npm, but it is outside item B.
- Correcting the stale "use short prefix for detection" comments on the existing fallback
  patterns.
- A secret-specific metric, response field, or configuration field.

## Decisions

### D1. Variant and label names

| Variant (config) | Label (403, `/v1/scan`, metrics) |
|---|---|
| `OpenAiApiKey` | `OPENAI_API_KEY` |
| `AnthropicApiKey` | `ANTHROPIC_API_KEY` |
| `SlackToken` | `SLACK_TOKEN` |
| `StripeSecretKey` | `STRIPE_SECRET_KEY` |
| `GoogleApiKey` | `GOOGLE_API_KEY` |
| `GitlabToken` | `GITLAB_TOKEN` |
| `HuggingFaceToken` | `HUGGINGFACE_TOKEN` |
| `NpmToken` | `NPM_TOKEN` |
| `PypiToken` | `PYPI_TOKEN` |
| `AzureAdClientSecret` | `AZURE_AD_CLIENT_SECRET` |
| `SupabaseSecretKey` | `SUPABASE_SECRET_KEY` |
| `OpenRouterApiKey` | `OPENROUTER_API_KEY` |
| `PerplexityApiKey` | `PERPLEXITY_API_KEY` |
| `XaiApiKey` | `XAI_API_KEY` |
| `FirecrawlApiKey` | `FIRECRAWL_API_KEY` |
| `GroqApiKey` | `GROQ_API_KEY` |
| `ReplicateApiToken` | `REPLICATE_API_TOKEN` |
| `PrivateKey` | `PRIVATE_KEY` |
| `Jwt` | `JWT` |
| `UrlCredentials` | `URL_CREDENTIALS` |

The labels follow `AWS_ACCESS_KEY` and `GITHUB_TOKEN`: provider, then the provider's own
word for the credential. `GitlabToken` follows `GithubToken`. All are
`Country::International`.

### D2. Engine per kind

Every new kind is a `som_fallback: true` pattern (Rust `regex`). D3 needs a greedy,
leftmost-first match of the maximal run. Rust `regex` gives that. Vectorscan reports every
match end instead.

Alternative: put the short fixed shapes (`AIza<35>`, `r8_<37>`, `pplx-<48>`) into
Vectorscan, like `AwsAccessKey`. Rejected: `EthereumAddress` already moved to the fallback
path at `{40}`, and one path for all 20 kinds keeps D3 uniform.

### D3. Match the maximal run, then check its structure

A pattern matches the prefix and then the maximal run of the token's alphabet, for example
`\bsk-proj-[A-Za-z0-9_-]+`. Its validator then checks the structure: the length, the
position of a marker such as `T3BlbkFJ`, a suffix such as `AA`, and the checksum.

The regex consumes the whole run, so a match cannot end inside a longer run, which the
spec requires. That matters for alphabets that hold `-` or `_`, where `\b` is true between
two characters of one token. It also keeps the minimum-only kinds simple: the validator
checks `len >= min`, and nothing caps the run.

Alternative: encode exact lengths in the regex, as gitleaks does. Rejected because a
fixed-length regex followed by `\b` can stop inside a token whose alphabet holds `-`, and
because the minimum-only kinds have no fixed length.

### D4. Minimum lengths

The four kinds with no documented length use the lowest body length any source reports:

| Kind | Minimum body | Source |
|---|---|---|
| `ANTHROPIC_API_KEY` | 80 before `AA` | keyhog uses 80–120 after real keys failed gitleaks' 93; trufflehog uses 93 |
| `XAI_API_KEY` | 40 | one scanner uses 40–120; trufflehog uses 80 |
| `GROQ_API_KEY` | 48 | one scanner uses 48–64; trufflehog uses 52 |
| `SUPABASE_SECRET_KEY` | 31 | Supabase's self-hosting generator (`docker/utils/add-new-auth-keys.sh`): 22 base64url characters, `_`, an 8-character checksum |

The Supabase checksum is a SHA-256 over the project ref, so it cannot be checked offline.

### D5. Test keys and publishable keys

The Stripe pattern matches `sk_live_`, `rk_live_`, and `sk_org_` only, so test and
publishable keys never match. Supabase matches `sb_secret_` only. The PyPI anchor
`AgEIcHlwaS5vcmc` is base64 of a macaroon header that names `pypi.org`, so a TestPyPI token
(which names `test.pypi.org`) does not match. No validator is needed for these.

### D6. Checksums

- GitLab routable token, from GitLab's
  `lib/authn/token_field/generator/routable_token.rb`:
  `prefix + base64url(payload) + "." + "01" + "." + <2 base36 length> + <crc>`, where
  `<crc>` is `Zlib.crc32` of everything before it, as lowercase base36, left-padded with
  `0` to 7 characters. The validator recomputes it with `crc32fast`. A legacy token
  (`glpat-<20>`, `gldt-<20>`, `glptt-<40 hex>`) has no checksum.
- npm token: the last 6 characters are a CRC32 in base62 (GitHub changelog, 2021-09-23).
  The changelog does not state the hashed input or the base62 alphabet order. Task 2.1
  confirmed both against a real revoked token on 2026-11-04: the CRC32 (IEEE) is over the
  30 characters between `npm_` and the checksum, without the prefix, and the alphabet is
  `0-9A-Za-z`, left-padded with `0`. Of the 8 rules tested (prefix in or out, 4 alphabet
  orders), only this one matched.

`crc32fast` becomes a direct dependency of `voidwall-pii`. It is already in the lock file,
so `cargo deny check licenses` sees no new license.

Alternative: a hand-written CRC32 table. Rejected because the crate is already built.

### D7. Known-sample deny list

The deny list is a `const` slice in `validators.rs`, checked by exact string equality. The
AWS kinds change from `Check::Any` to `Check::With`, and `JWT` uses the same check. The
list holds the AWS docs access key ID, the AWS docs secret access key, and the jwt.io
sample token. Task 1.3 confirms the current jwt.io sample.

Alternative: a separate filter after the scan. Rejected because a `Check` already runs in
both `has_piis` and `mark_piis`, so one place covers both.

### D8. `URL_CREDENTIALS`

The pattern matches `scheme://user:password@host`, where the user and password hold no
whitespace, `/`, or `@`. The validator splits off the password and rejects it when it is a
placeholder by the spec's three rules. A URL-encoded password is checked as written.

An email address inside the URL (`password@host.tld`) is a contained or shorter
overlapping span, so `resolve_overlaps` keeps `URL_CREDENTIALS`. No priority group is
needed.

### D9. Overlap

No new kind shares an exact span with another kind by construction: the prefixes are
distinct, and the collision check in the research note found no prefix that matches two
OpenAI-family shapes. A secret inside a larger secret (for example a JWT payload inside a
URL) is a contained span, which the existing containment rule resolves. Task 1.4 runs the
mixed benchmark corpus through `resolve_overlaps` to confirm that no equal-span pair
appears.

## Risks / Trade-offs

- [Each fallback pattern adds one full Rust-regex pass per unit] → Every pattern but Azure
  starts with a literal, which the regex crate uses as a prefilter. The benchmark tasks
  measure the mixed corpus before and after.
- [`AZURE_AD_CLIENT_SECRET` has no leading literal: its marker `Q~` sits at offset 4] →
  Benchmark it alone. If it costs too much, match from `Q~` with a keyword-context-style
  capture of the 4 characters before it.
- [A Check sees no context, so Azure's 3-character lead can start inside a longer run] →
  Accepted. The `\dQ~` marker and the 31–34 character tail keep false positives rare.
- [Minimum-only kinds accept any longer run after the prefix] → Accepted. The prefixes are
  unique to their providers.
- [The deny list blocks only exact sample values] → A sample with one changed character is
  reported. This is intended: such a value has a real key's shape.
- [Coding-assistant answers that hold example keys are blocked] → Accepted. Coding
  assistants are not a supported use case yet.

## Migration Plan

An operator whose custom entry uses one of the 20 new labels gets a startup validation
error that names the collision, and renames the entry. An operator who relied on the AWS
docs sample keys being reported (for example in a smoke test) switches to a real-shaped
test value. There is no rollback step beyond the previous image.

## Open Questions

None. The npm checksum (task 2.1) is answered in D6. The current jwt.io HS256 sample (task
1.3) comes from jwt.io's source, `src/features/common/values/default-tokens.values.ts`.
