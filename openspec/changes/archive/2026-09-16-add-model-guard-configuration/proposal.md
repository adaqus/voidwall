## Why

Voidwall detects one class of finding through one built-in guard. Every further class —
prompt injection, jailbreak, hate speech — arrives as a model-backed guard, and none can be
declared today: `AppConfig` has `builtin_guards` and nothing else. This change defines the
configuration contract those guards need, so the schema is settled and validated before the
ONNX runtime phase writes the code that executes them.

The roadmap's *Model Guard Configuration* phase names this work. Its sequencing note asks
that the contract be adjacent to the runtime rather than several phases ahead of it.

## What Changes

- Add `[guards.<name>]`, the section for a model-backed guard. One section carries
  everything one guard needs: `adapter`, `model_path`, `tokenizer_path`, `max_tokens`,
  `labels`, `thresholds`, and `surface`. There is no separate model section and no model
  reference, so one guard owns one model structurally.
- `labels` is positional and maps output tensor positions to finding kinds. `thresholds`
  gives each kind its minimum score and has no default; a label with no threshold produces
  no finding.
- A model guard's `surface` defaults to the **body alone**, unlike the built-in PII guard,
  whose surface keeps its path/query/body default. Each unit is a separate inference.
- **BREAKING (spec-level, not user-level)**: `GuardSurface` gains a `headers` boolean. The
  `guard-configuration` spec currently requires the schema to *reject* `surface.headers`.
  The new key is an on/off switch, not the header allowlist that ban was written against;
  the route still decides which headers become units. The built-in PII guard defaults it to
  `true`, so no existing config changes meaning.
- Constrain a guard name to ASCII `[a-zA-Z0-9_-]` with a length cap, because the name
  reaches finding records and may reach a metric label. Wire up
  `validate_configured_guard_name`, which exists today with no caller.
- Model guard settings parse and validate, but no guard is built: the runtime does not
  exist. The proxy logs one warning at startup naming each configured model guard and
  continues, following the pattern already specified for `forward_proxy` and `tls`.

Deliberately **not** in this change: `on_error` stays top-level, there is no `timeout_ms`,
there is no `overflow` behaviour for input past `max_tokens`, and no metric is renamed.
Each is assigned to a later phase in `voidwall-internal/research/configurable-model-guards-design.md`.

## Capabilities

### New Capabilities

None. A model guard is a guard, and how a guard is declared, given a surface, and selected
per route is already `guard-configuration`.

### Modified Capabilities

- `guard-configuration`: adds the `[guards.<name>]` model guard section and its fields;
  adds `surface.headers` as a boolean and replaces the requirement that the schema reject
  it; gives a model guard a body-only default surface; states the guard name charset and
  length rule.
- `configuration`: adds the startup validation rules for a model guard — unknown adapter,
  a `thresholds` key absent from `labels`, an out-of-range threshold, a fully disabled
  surface, a missing artifact file — and the requirement that a model guard parses and
  validates while the guard does not run.

## Impact

- `crates/voidwall/src/config.rs`: new `ModelGuardConfig` and `ModelGuardSurface` types, a
  `guards` field on `AppConfig`, the name charset and length rule, and a caller for
  `validate_configured_guard_name`.
- `crates/voidwall/src/validate.rs`: the new startup checks and their failure categories.
- `crates/voidwall/src/engine/mod.rs`: the startup warning naming configured model guards
  that do not run. No guard is constructed and the `Guard` trait does not change.
- `crates/voidwall/src/main.rs`: warning emission alongside the existing empty-guard-set
  warning.
- No new dependency. `voidwall-ml` and the ONNX runtime arrive in the next phase.
- **Risk to note**: a route may select a model guard by name and validate, while that guard
  never runs — inspection that looks configured but is absent. The startup warning is the
  only signal. Rejecting such a route instead would be stricter; it was not chosen because
  it would make a config written for the next phase unusable in this one.
