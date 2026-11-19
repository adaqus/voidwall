## Why

With the default config, the regex `pii` guard reports common text as `PERSON_NAME`. On
2026-11-18, `Every Monday at 8am` from the description of Open WebUI's built-in
`create_automation` tool was blocked, which can block every chat of an Open WebUI admin
on a default install. Calendar words are in the dictionary detector's name lists, and
they match in two ways. A capitalized given-name form beside a capitalized surname form
promotes both (`Every Monday`, `Monday Morning`). A calendar word without the
common-word flag matches alone (German `Montag`, `Juni`). On benign Dolly prompts, regex
`PERSON_NAME` blocks 34.2% of prompts, and 11 of 25 sampled names are not names. The
`pii_ml` `PERSON_NAME` label blocks 16.0% at its default threshold of 0.4, and finds more
names on Gretel (span recall 0.817 against 0.786).

## What Changes

- **BREAKING**: `docker/voidwall.toml` and `docker/voidwall-image.toml` set
  `ignore = ["PersonName"]` in `[builtin_guards.pii]`. With the default config, only the
  `pii_ml` guard reports `PERSON_NAME`.
- With the default config, a name in a URL path or a query string is no longer
  detected, because the `pii_ml` surface is the body alone. The keyword-context name
  rules of the regex guard (for example `Name: X`) are off too.
- `docker/anythingllm-to-lmstudio.toml` already sets the same `ignore` and does not
  change.
- Only the config files directly in `docker/` are in scope. Config files elsewhere, such
  as the load-test configs in `crates/voidwall/benches/configs/`, do not change.
- `docker/smoke-test.sh` checks that `/v1/scan` on `Every Monday at 8am` reports no
  `PERSON_NAME`, and that `/v1/scan` on a text with a real name reports `PERSON_NAME`
  from the `pii_ml` guard and none from the `pii` guard.
- The dictionary detector does not change. Its calendar-word false positive goes to
  `docs/dev/backlog.md`.

## Capabilities

### New Capabilities

None.

### Modified Capabilities

- `distribution`: the requirement "The image starts with a default configuration"
  states that the regex `pii` guard ignores `PERSON_NAME`, and its scenario checks the
  two name scans.

## Impact

- Config: `docker/voidwall.toml`, `docker/voidwall-image.toml`.
- Release check: `docker/smoke-test.sh`.
- No Rust code changes. The `voidwall-pii` dictionary detector stays as it is for
  operators who turn `PERSON_NAME` back on in the regex guard.
- User docs that show or describe the default config (updated with `docs-sync`).
- Backlog: `docs/dev/backlog.md` gets the dictionary-detector entry.
