## Why

Configuration describes one hard-coded detector, not a set of guards. `[pii]` and
`[scan]` are two sections for one thing: `[scan]`'s `url_path`, `query_params`, and
`body` flags are the config form of a guard's `Interest`, and they sit in a section that
knows nothing about guards. Its `headers` allowlist is not a guard setting at all — it
decides which header values a message is decoded into, and that depends on the route's
traffic rather than on any detector. A second guard has nowhere to go, and the per-route
`scan` override has nothing left to replace once scan surface belongs to a guard and
body limits belong to ingest.

The engine already takes a guard list. Configuration is the part that never caught up.
This change restructures it before the open-core release, while breaking the config
format is still free.

## What Changes

- **BREAKING** Remove `[pii]`. Its fields move into `[builtin_guards.pii]`, and
  `[[pii.custom]]` becomes `[[builtin_guards.pii.custom]]`.
- **BREAKING** Remove `[scan]`. `max_body_size`, `content_types`, and `on_error` become
  top-level keys that apply to every guard. `url_path`, `query_params`, and `body`
  become a per-guard `surface` table that maps to the guard's `Interest`. `headers`
  becomes a per-route list: which headers carry sensitive values is a property of the
  traffic, not of a detector.
- **BREAKING** Replace the per-route `scan` table with `route.guards`, a list of guard
  names. An omitted list selects every enabled guard; an empty list selects none, which
  is how a route opts out of inspection.
- Add `[builtin_guards.<name>]` for guards that ship with Voidwall. A built-in is a
  singleton with a fixed key and no `type` field. `pii` is the only one today.
- Add `enabled` to a built-in guard, defaulting to true when the section is present.
  An absent section means the guard is not built.
- Reserve built-in guard names. A configured guard may not take one.
- Warn at startup when no guard is enabled, rather than refusing to start. This matches
  how the modes behave: a proxy with nothing enabled starts and does nothing.
- Allow a guard name to be operator-supplied rather than a fixed string per guard type.
  Guard names are drawn from configuration, so cardinality is bounded at startup, exactly
  as the existing `route` label already is. No metric label is added yet: with one
  built-in guard every series would carry the same value, and a `guard` label would
  conflict with the rule that a kind increments once however many guards reported it.
  That conflict is decided when a second guard exists.

Out of scope, and tracked as the *Model Guard Configuration* roadmap phase: the
`[guards.<name>]` section for model-backed guards, thresholds, and model artifacts.
Trust classes stay out until the LiteLLM decoder produces one; the direction scan
switches are unchanged by this proposal.

## Capabilities

### New Capabilities

- `guard-configuration`: how a guard is named, enabled, given a scan surface, selected
  per route, and validated. Holds the built-in guard section, reserved names, the
  per-route header allowlist, the empty-guard-set warning, and the rule that a guard
  name reaches a metric label.

### Modified Capabilities

- `configuration`: `pii.scanner_threads`, `pii.detect`, `pii.ignore`, and
  `[[pii.custom]]` move under the built-in guard; the per-route `scan` override
  requirement is replaced by guard selection; validation categories gain the new
  rejections.
- `pii-scanning`: scan targets become a per-guard surface rather than one global `scan`
  table; the header allowlist leaves the surface for the route; the body size limit and
  the content type allowlist move to top-level keys; a guard name is operator-supplied
  rather than fixed.
- `reverse-proxy`: body and target scanning read the guard's surface instead of
  `scan.*`; a route selects guards instead of overriding a scan table, and names the
  headers it exposes to detection.
- `custom-pii`: custom entries are declared under `[[builtin_guards.pii.custom]]`, and
  `detect` and `ignore` are fields of that guard.
- `http-api`: the API honours the top-level `max_body_size` and `content_types` rather
  than `scan.*`.
- `security`: the invalid-configuration scenario names the new custom-entry path.

## Impact

- `crates/voidwall/src/config.rs`: `PiiConfig` and `ScanConfig` are replaced by
  top-level ingest keys, `BuiltinGuards`, and a guard surface. `Route.scan` becomes
  `Route.guards` and `Route.headers`.
- `crates/voidwall/src/validate.rs`: new rejections for a reserved name, an unknown
  guard in `route.guards`, and the new startup warning.
- `crates/voidwall/src/engine/`: `Guard::name` and `Finding::guard` become `Arc<str>`;
  the engine builds guards from the new config; `Interest` is built from `surface`.
- `crates/voidwall/src/reverse_proxy.rs`, `http_api.rs`, `scanner.rs`: read the new
  config paths.
- Every example config: `docker/voidwall.toml`, seven bench configs under
  `crates/voidwall/benches/configs/`, and `docs/custom-pii.md`.
- `CLAUDE.md`, `engine/guard.rs`, and `engine/finding.rs` state that a guard name is
  never operator-supplied. That rule is replaced by one bounded at startup.
