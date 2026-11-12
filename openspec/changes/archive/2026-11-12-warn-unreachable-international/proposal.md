## Why

An operator who writes `countries = ["Us"]` silently loses every kind of the
`International` group: e-mail addresses, card numbers, IBANs, IP addresses, cloud keys,
and also `US_PHONE_NUMBER`, `PERSON_NAME`, and the US street address. Custom rules default
to `International`, so they stop running too. The docs say this, but the proxy says
nothing at startup.

## What Changes

- At startup, when the enabled `pii` guard lists countries without `International` and
  `detect` is not set, the proxy logs one warning. The warning names the built-in kinds
  of `International` that `ignore` does not already remove, and the custom rules whose
  country is `International`. The proxy still starts.
- No warning when `countries` is empty or absent, when it lists `International`, when
  `detect` is set, or when the guard is disabled.
- `--validate` does not log it, as it logs no other startup warning.
- `docs/guards/pii-regex.md` states the warning.

## Capabilities

### New Capabilities

None.

### Modified Capabilities

- `guard-configuration`: a new requirement for the warning about kinds that `countries`
  makes unreachable.

## Impact

- Code: `crates/voidwall/src/config.rs` (`AppConfig::load` calls the new warning).
- Docs: `docs/guards/pii-regex.md`.
- Image: no change. Its config sets `countries = []`, which selects every country.
- Metrics, endpoints, config keys: none.
