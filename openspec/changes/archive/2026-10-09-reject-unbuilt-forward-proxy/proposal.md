## Why

The forward proxy is not built, but the config accepts `forward_proxy.enabled = true`.
The proxy then logs one warning and starts without it, and the README and `AGENTS.md`
describe it as a working mode. This must be fixed before the repository becomes public.

## What Changes

- Startup validation fails when `forward_proxy.enabled` is true. The failure carries the
  `semantic` category and names the key.
- This check runs before the at-least-one-mode check. A config that enables only the
  forward proxy reports the forward proxy failure, not the missing mode.
- The forward proxy no longer counts as a mode. The at-least-one-mode check and its
  message name `reverse_proxy` and `http_api` only.
- Code that can no longer run is removed: the startup warning for an enabled forward proxy,
  and the forward proxy branch of the listener port-conflict check.
- The `forward_proxy` table stays in the schema. Its keys still parse and the schema
  rules still apply to them.
- The README and `AGENTS.md` stop describing the forward proxy as a working mode.
- **BREAKING**: a config that sets `forward_proxy.enabled = true` no longer starts. Before,
  it started the other modes and logged a warning.

## Capabilities

### New Capabilities

None.

### Modified Capabilities

- `configuration`: "At least one mode must be enabled" no longer counts the forward proxy.
  "Forward proxy and TLS settings parse but the mode does not run" replaces the warning
  with a validation failure.

## Impact

- `crates/voidwall/src/config.rs`: the new rule, the changed mode and port-conflict
  checks, and the tests. About 40 tests use `forward_proxy.enabled = true` as their
  minimal mode and must use another mode.
- `crates/voidwall/src/engine/mod.rs`: one test config enables the forward proxy.
- `crates/voidwall/src/server.rs`: the warning is removed.
- `--validate` reports the new failure, because it runs the same validation.
- Docs: `README.md`, `AGENTS.md` (`CLAUDE.md` links to it), `ARCHITECTURE.md` § 7,
  `docs/backlog.md` § 1.2.
