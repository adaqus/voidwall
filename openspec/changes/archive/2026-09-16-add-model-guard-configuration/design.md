## Context

`AppConfig` holds `builtin_guards` and nothing else. The 2026-09-15 guard configuration
change built the parts a model guard reuses — a per-guard `surface`, a flat guard name
space with built-in names reserved, `route.guards` selection, and
`validate_configured_guard_name`, which has no caller because no configured guard exists.
`Finding` already carries an optional span and an optional confidence, and
`Finding::whole_unit` already builds the span-less classifier finding a model guard would
report.

The shape below comes from `voidwall-internal/research/configurable-model-guards-design.md`,
revised 2026-09-16. See proposal.md for motivation.

## Goals / Non-Goals

**Goals:**

- One TOML section describes one model guard completely.
- Every rule the schema cannot express is a named startup failure, with the guard and the
  cause in the message.
- The `Guard` trait, the `Engine`, and every existing config key keep their meaning.

**Non-Goals:**

- No `voidwall-ml` crate, no ONNX dependency, no inference. Nothing reads an artifact.
- No metric change. `voidwall_pii_detections_total{pii_kind}` does not fit a
  `PROMPT_INJECTION` finding, but renaming it is observable behaviour with no producer yet.
- No `on_error` per guard, no `timeout_ms`, no `overflow` behaviour past `max_tokens`.

## Decisions

### The guard section carries the model; there is no `[models.*]` table

A model section exists to let several guards share one loaded model. The design rejects
sharing, so every entry in that table would have exactly one referent — a table with one
row per guard, plus a validation rule to keep it that way.

Flattening makes the rule structural. "At most one guard per model" needs no check because
a guard's model is not addressable from anywhere else, which is the same move
`[builtin_guards.pii]` made for the singleton question.

*Alternative rejected*: `[models.<name>]` with `model = "<name>"` on the guard, as the
research doc originally proposed. It also left an open question — two model entries naming
the same artifacts — that the flat form does not pretend to answer.

### `adapter` names build-shipped code; there is no `model_profile`

A profile and an adapter are the same mechanism at different granularity: a profile is an
adapter plus baked-in defaults plus pinned artifacts. Since Voidwall ships as a Docker
image carrying both the artifacts and the configuration, the defaults live in the shipped
TOML and the artifacts live in the image. What is left that config cannot express is the
code path, which is `adapter`.

This gives up one thing: nothing marks a guard as one we evaluated, so an operator who
edits the shipped thresholds still has a guard that looks shipped. Accepted — the
alternative is a schema key recording a claim the schema cannot check.

`runtime` is rejected rather than ignored. ONNX is the only runtime, so the key can only be
written wrong.

### `labels` plus `thresholds`, and no `detect`

Three constructs naming kinds collapse to two. `labels` is the tensor contract, positional
and mandatory. `thresholds` is the per-kind cut-off, and since no evaluated default exists
for an arbitrary model, every reporting kind needs one — which makes the `thresholds` key
set identical to what `detect` would have listed.

Turning a kind off is a policy decision, and the policy phases precede the runtime. The
research doc also concedes `detect` saves nothing: it *"does not necessarily reduce the
model's inference cost."*

*Consequence*: because `labels` is positional it cannot be shortened, so threshold absence
is the only detection-layer off switch. A `thresholds` key absent from `labels` is rejected,
so a typo errors rather than silently disabling a kind.

### Two surface types, not one with two default functions

A serde field-level `#[serde(default = "...")]` on `surface` does not change the *inner*
per-field defaults, so a partially written model guard surface would silently take the
built-in's `true` defaults:

```toml
[guards.injection.surface]
url_path = true    # body/query/headers must fall back to MODEL defaults, not true
```

So `ModelGuardSurface` is its own type with its own per-field defaults (`body = true`, the
rest false), mirroring the built-in/configured split the archived design already accepted.

*Alternative rejected*: one struct with `Option<bool>` fields resolved after parse. It
works, but it moves a schema fact into imperative code and makes the defaults invisible in
the type.

### `surface.headers` is a boolean, and the existing ban is narrowed

The built spec rejects `surface.headers` outright. That ban was written to stop a header
*allowlist* leaking into the guard — the route owns which headers become units. A boolean
is an on/off switch over units the route already built, so the ban narrows to "not a list"
rather than disappearing.

A model guard needs it: `Interest::from_surface` always admits `HeaderValue`, so a route
naming two headers currently forces two extra inferences a guard cannot decline. The
built-in PII guard defaults it to `true`, so no existing config changes meaning.

### Parse and validate, but build no guard

This follows the pattern already specified for `forward_proxy` and `tls`
(`configuration/spec.md:183`): the schema accepts the table, validation runs in full, the
runtime is absent, and startup logs one warning. The roadmap's "no configuration parses a
model guard before a runtime can run one" is waived deliberately, so that the spec
describes behaviour that is built and tested and the change can be archived.

## Risks / Trade-offs

- **A route selects a model guard, validates, and that guard never runs** — traffic looks
  inspected and is not. → The startup warning names each configured model guard. Rejecting
  such a route was considered and not chosen: it would make a config written for the next
  phase unusable in this one. This is the sharpest edge in the change.
- **Narrowing the `surface.headers` ban touches a requirement that shipped last week.** →
  The MODIFIED block carries the whole requirement including the original scenario, whose
  meaning shifts from "any `headers` key is rejected" to "a list is rejected".
- **`labels` is positional, so a wrong order silently mislabels every finding.** → Nothing
  in this phase can detect it; validation cannot prove label semantics from shapes. The
  runtime phase owns artifact compatibility. Documented, not mitigated.
- **A guard name reaching a metric label is bounded by config, not by traffic** — but an
  operator could still declare many guards. → The charset and 64-character cap bound the
  shape; the count is bounded by the file. Accepted as safe for Prometheus.
- **Two guards may point at the same artifacts and load the model twice.** → Specified as
  the operator's choice, not an error. Detecting copied or aliased artifacts was an open
  question under the reference design too.

## Migration Plan

No migration. `guards` is a new optional key, so every existing config keeps its meaning,
and `surface.headers` defaults to `true` for the built-in PII guard, which is what the
engine does today. Rollback is a revert: no state, no stored data, no wire format change.

## Open Questions

- Which adapter names ship first. The schema needs a non-empty set to validate against, so
  the first adapter name is chosen during implementation; it does not change the specs.
- Whether the score range is per adapter or fixed to `0.0..=1.0`. The spec says "the range
  the adapter declares", which admits both; a sigmoid classifier makes `0.0..=1.0` the
  obvious first case.
