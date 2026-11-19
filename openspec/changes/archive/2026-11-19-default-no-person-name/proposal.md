## Why

With the default config, the `pii_ml` guard still reports `PERSON_NAME`, and names block too
much ordinary traffic. On 2026-11-19, in an end-to-end test of Open WebUI 0.13.4, a public
web page that the model fetched with `fetch_url` (blog.rust-lang.org) was blocked as
`PERSON_NAME`. Sent again through the proxy, the captured request answers 400
`PERSON_NAME` with the current default and passes the scan with `PERSON_NAME` removed from
`pii_ml`. The `pii_ml` `PERSON_NAME` label also blocks
16.0% of benign Dolly prompts at its default threshold of 0.4 (measured for
`default-names-from-pii-ml`). The user decided that `PERSON_NAME` is too problematic to
detect by default.

## What Changes

- **BREAKING**: `docker/voidwall.toml`, `docker/voidwall-image.toml` and
  `docker/anythingllm-to-lmstudio.toml` remove `"PERSON_NAME"` from the `labels` of
  `[guards.pii_ml]` and remove its line from `[guards.pii_ml.thresholds]`. No comment is
  added in its place.
- The regex `pii` guard keeps `ignore = ["PersonName"]`. With the default config, no guard
  reports `PERSON_NAME`.
- `docker/smoke-test.sh` turns its full-name check around: `/v1/scan` on the full-name
  text gives no `PERSON_NAME` finding from any guard. The weekday check stays.
- `docker/smoke-test.sh` adds a check that `pii_ml` still finds PII: `/v1/scan` on a text
  with an email address gives an `EMAIL_ADDRESS` finding from the `pii_ml` guard.
- `docker/anythingllm-to-lmstudio.toml` is a config for a manual test. No requirement
  covers it, and the `image_config` test compares only the two default configs, so only
  `voidwall --validate` checks it.
- The calendar-word entry in `docs/dev/backlog.md` says that the default config also
  turns off `PERSON_NAME` in `pii_ml`.
- Only the config files directly in `docker/` are in scope. Config files elsewhere, such as
  the load-test configs in `crates/voidwall/benches/configs/`, do not change.

## Capabilities

### New Capabilities

None.

### Modified Capabilities

- `distribution`: the requirement "The image starts with a default configuration" states
  that no guard reports `PERSON_NAME` with the default config, and its scenario checks that
  a text with a person's name gives no `PERSON_NAME` finding, and that a text with an
  email address gives an `EMAIL_ADDRESS` finding from the `pii_ml` guard.

## Impact

- Config: `docker/voidwall.toml`, `docker/voidwall-image.toml`,
  `docker/anythingllm-to-lmstudio.toml`.
- Release check: `docker/smoke-test.sh`.
- No Rust code changes. The `pii_ml` model and the regex dictionary detector stay as they
  are, so an operator can turn `PERSON_NAME` back on in either guard.
- User docs that show or describe the default config (updated with `docs-sync`), for
  example `docs/quick-start.md` and `docs/guards/README.md`.
- Backlog: the calendar-word entry in `docs/dev/backlog.md`.
