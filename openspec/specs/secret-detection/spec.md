## Purpose

Defines the secret kinds the regex `pii` guard reports: which credential shapes each kind
matches, and which look-alike values (test keys, publishable keys, placeholders, documented
samples) it does not report.

## Requirements

### Requirement: Each provider secret is reported under its own kind

The `pii` guard SHALL report a value of one of the shapes below under the kind on its row.
One kind SHALL cover every listed token type of its provider. `<n>` stands for exactly `n`
characters of the shape's alphabet. `<n+>` stands for at least `n` of them, with no upper
bound. `<n to m>` stands for `n` to `m` of them. A match SHALL NOT start or end inside a longer run of the shape's alphabet.

| Kind | Shapes |
|---|---|
| `OPENAI_API_KEY` | `sk-proj-`, `sk-svcacct-`, or `sk-admin-`, then `<58>` or `<74>`, `T3BlbkFJ`, `<58>` or `<74>`; legacy `sk-<20>T3BlbkFJ<20>` |
| `ANTHROPIC_API_KEY` | `sk-ant-api03-<80+>` or `sk-ant-admin01-<80+>`, ending in `AA` |
| `SLACK_TOKEN` | `xoxb-`, `xoxp-`, `xapp-`, `xoxe.xapp-`, `xwfp-`, `xoxe.xoxb-`, `xoxe.xoxp-`, `xoxe-`, `xoxa-`, `xoxr-`, `xoxo-`, `xoxs-` tokens; `hooks.slack.com/services/`, `/workflows/`, or `/triggers/` webhook URLs |
| `STRIPE_SECRET_KEY` | `sk_live_`, `rk_live_`, or `sk_org_`, then `<10 to 99>` |
| `GOOGLE_API_KEY` | `AIza<35>` |
| `GITLAB_TOKEN` | legacy `glpat-<20>`, `gldt-<20>`, `glptt-<40 hex>`; routable tokens with any GitLab token prefix |
| `HUGGINGFACE_TOKEN` | `hf_<34 letters>`, `api_org_<34 letters>` |
| `NPM_TOKEN` | `npm_<36>` |
| `PYPI_TOKEN` | `pypi-AgEIcHlwaS5vcmc<50 to 1000>` |
| `AZURE_AD_CLIENT_SECRET` | `<3>`, a digit, `Q~`, `<31 to 34>` |
| `SUPABASE_SECRET_KEY` | `sb_secret_<31+>` |
| `OPENROUTER_API_KEY` | `sk-or-v1-<64 hex>` |
| `PERPLEXITY_API_KEY` | `pplx-<48>` |
| `XAI_API_KEY` | `xai-<40+>` |
| `FIRECRAWL_API_KEY` | `fc-<32 hex>` |
| `GROQ_API_KEY` | `gsk_<48+>` |
| `REPLICATE_API_TOKEN` | `r8_<37>` |

#### Scenario: A provider key is reported

- **WHEN** a unit holds `sk-proj-<58>T3BlbkFJ<58>`
- **THEN** the `pii` guard reports one `OPENAI_API_KEY` finding over that span

#### Scenario: Two token types of one provider share a kind

- **WHEN** a unit holds a Slack bot token and a Slack webhook URL
- **THEN** the `pii` guard reports two `SLACK_TOKEN` findings

#### Scenario: A shape inside a longer run is not reported

- **WHEN** a unit holds `AIza<35>` followed directly by more characters of its alphabet
- **THEN** the `pii` guard reports no `GOOGLE_API_KEY` finding

#### Scenario: A prefix with too short a body is not reported

- **WHEN** a unit holds `pplx-` followed by 20 alphanumerics
- **THEN** the `pii` guard reports no `PERPLEXITY_API_KEY` finding

### Requirement: A key with no documented length checks a minimum only

`ANTHROPIC_API_KEY`, `XAI_API_KEY`, `GROQ_API_KEY`, and `SUPABASE_SECRET_KEY` SHALL accept a
body of any length at or above the minimum in their shape. They SHALL reject a body below
it.

#### Scenario: A long body is reported

- **WHEN** a unit holds `gsk_` followed by 120 alphanumerics
- **THEN** the `pii` guard reports one `GROQ_API_KEY` finding over the whole token

#### Scenario: A body below the minimum is not reported

- **WHEN** a unit holds `xai-` followed by 39 alphanumerics
- **THEN** the `pii` guard reports no `XAI_API_KEY` finding

### Requirement: Test, sandbox, and publishable keys are not secrets

The `pii` guard SHALL NOT report a test, sandbox, or publishable key as a secret. This
covers Stripe `sk_test_`, `rk_test_`, `pk_test_`, and `pk_live_` keys, Supabase
`sb_publishable_` keys, and TestPyPI tokens. A Stripe `sk_org_` key SHALL be reported in
every mode, because its prefix does not show the mode.

#### Scenario: A Stripe test key is not reported

- **WHEN** a unit holds `sk_test_<24>`
- **THEN** the `pii` guard reports no finding over that span

#### Scenario: A Stripe live key is reported

- **WHEN** a unit holds `sk_live_<24>`
- **THEN** the `pii` guard reports one `STRIPE_SECRET_KEY` finding

#### Scenario: A Stripe organization key is reported

- **WHEN** a unit holds `sk_org_<24>`
- **THEN** the `pii` guard reports one `STRIPE_SECRET_KEY` finding

#### Scenario: A Supabase publishable key is not reported

- **WHEN** a unit holds `sb_publishable_<31>`
- **THEN** the `pii` guard reports no finding over that span

### Requirement: A token with a checksum must pass it

An `NPM_TOKEN` SHALL be reported only when its last 6 characters are the CRC32 checksum of
the token that npm defines. A routable `GITLAB_TOKEN` SHALL be reported only when its last
7 characters are the lowercase base36 CRC32 (IEEE) of everything before them, left-padded
with `0`.

#### Scenario: A GitLab routable token with a valid checksum is reported

- **WHEN** a unit holds a `glpat-` routable token whose checksum matches
- **THEN** the `pii` guard reports one `GITLAB_TOKEN` finding

#### Scenario: A GitLab routable token with a wrong checksum is not reported

- **WHEN** a unit holds the same token with one checksum character changed
- **THEN** the `pii` guard reports no `GITLAB_TOKEN` finding

#### Scenario: An npm token with a wrong checksum is not reported

- **WHEN** a unit holds `npm_<36>` whose last 6 characters are not its checksum
- **THEN** the `pii` guard reports no `NPM_TOKEN` finding

### Requirement: A private key is reported by its PEM header

The `pii` guard SHALL report a `PRIVATE_KEY` finding for a PEM header that names a private
key: `-----BEGIN `, optional words such as `RSA`, `EC`, `OPENSSH`, `DSA`, `ENCRYPTED`, or
`PGP`, then `PRIVATE KEY-----` or `PRIVATE KEY BLOCK-----`. A public key or certificate
header SHALL NOT be reported.

#### Scenario: An OpenSSH private key header is reported

- **WHEN** a unit holds `-----BEGIN OPENSSH PRIVATE KEY-----`
- **THEN** the `pii` guard reports one `PRIVATE_KEY` finding

#### Scenario: A certificate is not reported

- **WHEN** a unit holds `-----BEGIN CERTIFICATE-----`
- **THEN** the `pii` guard reports no `PRIVATE_KEY` finding

### Requirement: A JSON Web Token is reported

The `pii` guard SHALL report a `JWT` finding for three dot-separated base64url segments
where the first two start with `ey`.

#### Scenario: A JWT is reported

- **WHEN** a unit holds `eyJ<header>.eyJ<payload>.<signature>`
- **THEN** the `pii` guard reports one `JWT` finding over the three segments

### Requirement: Credentials in a URL are reported unless the password is a placeholder

The `pii` guard SHALL report a `URL_CREDENTIALS` finding for `scheme://user:password@host`.
It SHALL NOT report the URL when the password part is a placeholder:

- template syntax: `${...}`, `$NAME`, `{{...}}`, `{...}`, `<...>`, or `[...]`
- a mask: only `*`, only `x` or `X`, `...`, or `…`
- a placeholder word, case-insensitive: `password`, `pass`, `passwd`, `pwd`, `secret`,
  `changeme`, `your_password`, `your-password`, `yourpassword`, `mypassword`

printf-style `%s` and `%(name)s` SHALL NOT count as placeholders. A default credential such
as `postgres` or `root` is not a placeholder.

#### Scenario: A connection string with a password is reported

- **WHEN** a unit holds `postgres://<user>:<password>@<host>/<db>` with a real password
- **THEN** the `pii` guard reports one `URL_CREDENTIALS` finding

#### Scenario: A template password is not reported

- **WHEN** a unit holds `postgres://app:${DB_PASSWORD}@db/app`
- **THEN** the `pii` guard reports no `URL_CREDENTIALS` finding

#### Scenario: A placeholder word is not reported

- **WHEN** a unit holds `mysql://user:password@localhost/app`
- **THEN** the `pii` guard reports no `URL_CREDENTIALS` finding

#### Scenario: A URL with an empty user is not reported

- **WHEN** a unit holds `redis://:<password>@cache:6379`
- **THEN** the `pii` guard reports no `URL_CREDENTIALS` finding

#### Scenario: A printf placeholder is reported

- **WHEN** a unit holds `postgres://app:%s@db/app`
- **THEN** the `pii` guard reports one `URL_CREDENTIALS` finding

### Requirement: Documented sample values are not reported

The `pii` guard SHALL NOT report a value on the known-sample deny list. The list SHALL hold
the AWS docs sample access key ID, the AWS docs sample secret access key, and the jwt.io
sample token. It SHALL apply to `AWS_ACCESS_KEY`, `AWS_SECRET_KEY`, and `JWT`.

#### Scenario: The AWS docs sample key is not reported

- **WHEN** a unit holds the AWS docs sample access key ID
- **THEN** the `pii` guard reports no `AWS_ACCESS_KEY` finding

#### Scenario: A real-shaped AWS key is still reported

- **WHEN** a unit holds `AKIA<16>` that is not on the deny list
- **THEN** the `pii` guard reports one `AWS_ACCESS_KEY` finding

#### Scenario: The jwt.io sample token is not reported

- **WHEN** a unit holds the jwt.io sample token
- **THEN** the `pii` guard reports no `JWT` finding

### Requirement: The secret kinds are on by default and selectable

Every kind in this capability SHALL be an international kind: the `pii` guard SHALL report
it with no `countries` or `languages` setting. `builtin_guards.pii.detect` and
`builtin_guards.pii.ignore` SHALL accept each kind by its variant name, such as `Jwt` for
`JWT`.

#### Scenario: A default guard reports a new kind

- **WHEN** `[builtin_guards.pii]` sets `countries = []` and a unit holds `r8_<37>`
- **THEN** the `pii` guard reports one `REPLICATE_API_TOKEN` finding

#### Scenario: One provider is ignored

- **WHEN** `builtin_guards.pii.ignore = ["Jwt"]` and a unit holds a JWT
- **THEN** the `pii` guard reports no `JWT` finding
