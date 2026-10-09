## Why

TLS termination is not built, but the config accepts `tls.enabled = true` and then
ignores it. An operator who sets it gets a proxy that serves plaintext while the config
says TLS. This must be fixed before the repository becomes public.

## What Changes

- Startup validation fails when `reverse_proxy.tls.enabled` is true.
- Startup validation fails when `forward_proxy.tls.enabled` is true.
- The failure carries the `semantic` category and names the key.
- The `tls` tables stay in the schema. `enabled = false`, `cert_path`, and `key_path`
  still parse.
- **BREAKING**: a config that sets `tls.enabled = true` no longer starts. Before, it
  started and served plaintext.

## Capabilities

### New Capabilities

None.

### Modified Capabilities

- `configuration`: the `tls` tables still parse, but `enabled = true` fails validation.
- `reverse-proxy`: the requirement "The proxy serves plain HTTP only" no longer has a
  scenario where TLS is enabled and the listener still accepts plain HTTP. That config
  does not start.

## Impact

- `crates/voidwall/src/config.rs`: one new validation rule and its unit tests.
- `--validate` reports the new failure, because it runs the same validation.
- Docs that say the `tls` table "parses and validates, and nothing reads it":
  `ARCHITECTURE.md` § 7, `docs/backlog.md` § 1.1.
