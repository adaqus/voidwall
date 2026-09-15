## Context

See `proposal.md` — Why. The constraints that shape the approach:

- `engine::Interest` already exists and already carries exactly the axis `[scan]`'s
  `url_path`, `query_params`, and `body` flags express. The engine applies it; the guard
  does not. Configuration is what never caught up. `[scan]`'s `headers` allowlist is not
  on that axis: a `Unit` carries its kind, not a header name, so an interest cannot
  express "this header and no other".
- `Guard::name()` returns `&'static str` and `Finding::guard` stores one. `FindingKind`
  in the same module already uses `Arc<str>`, so the pattern is in place.
- `AppConfig.pii` has no `serde(default)`, so `[pii]` is required today. Every section
  uses `deny_unknown_fields`.
- Open-core release has not happened. No operator config exists outside this repository,
  so a clean break costs nothing beyond the example files.
- `engine::Interest` has one axis by design: `guard.rs` records that a trust class is not
  added until a producer exists. This change adds no axis.

## Goals / Non-Goals

**Goals:**

- One place in configuration answers "which detections run", and one answers "how a
  message is admitted".
- Scan surface belongs to the guard that uses it, so a second guard needs no new section
  shape.
- A built-in guard is distinguishable from a configured one by section, not by
  convention.
- Every removed config path fails loudly at startup, never silently.

**Non-Goals:**

- `[guards.<name>]` for model-backed guards. That is the *Model Guard Configuration*
  roadmap phase, placed immediately before the ONNX runtime so a validated schema never
  waits several phases for the code that runs it.
- The `guard` metric label. See Decisions.
- Trust classes, thresholds, deadlines, and guard ordering.

## Configuration Shape

The format is the deliverable, so it is stated once here in full. Every decision below
refers to this shape rather than describing it again.

`docker/voidwall.toml` today:

```toml
[pii]
countries = []
languages = []
scanner_threads = 6

[reverse_proxy]
enabled = true
listen = "0.0.0.0:8082"

[reverse_proxy.request]
scan = true

[reverse_proxy.response]
scan = false

[[reverse_proxy.routes]]
path_prefix = "/"
upstream = "http://echo-server:8090"

[http_api]
enabled = true
listen = "0.0.0.0:8083"

[admin]
listen = "0.0.0.0:9090"
```

The same deployment after this change:

```toml
# Ingest keys come first. TOML binds a bare key to the table above it, so one
# written after a [section] parses as that section's field and is rejected.
max_body_size = 1048576
on_error = "fail_close"

[builtin_guards.pii]
countries = []
languages = []
scanner_threads = 6

[reverse_proxy]
enabled = true
listen = "0.0.0.0:8082"

[reverse_proxy.request]
scan = true

[reverse_proxy.response]
scan = false

[[reverse_proxy.routes]]
path_prefix = "/"
upstream = "http://echo-server:8090"

[http_api]
enabled = true
listen = "0.0.0.0:8083"

[admin]
listen = "0.0.0.0:9090"
```

`[pii]` becomes `[builtin_guards.pii]` and the ingest keys become explicit. Nothing else
in a simple deployment moves, and both `max_body_size` and `on_error` could be omitted
for their defaults.

A config exercising every part of the new surface:

```toml
max_body_size = 2097152
content_types = ["application/json", "text/plain"]
on_error = "fail_close"

[builtin_guards.pii]
enabled = true
countries = ["US", "PL"]
languages = ["en"]
scanner_threads = 6
ignore = ["PersonName"]

# The guard's scan surface. This is what the engine turns into its Interest.
[builtin_guards.pii.surface]
body = true
url_path = true
query_params = true

[[builtin_guards.pii.custom]]
label = "EMPLOYEE_ID"
pattern = "EMP-[0-9]{6}"
keywords = ["employee", "badge"]

[reverse_proxy]
enabled = true
listen = "0.0.0.0:8082"

# Inspected by every enabled guard: no guards key.
[[reverse_proxy.routes]]
path_prefix = "/api"
upstream = "http://api:8080"

# Named explicitly. Equivalent today, and the form model guards will use. The header
# allowlist is the route's: this traffic carries a user id, the /api traffic does not.
[[reverse_proxy.routes]]
path_prefix = "/api/chat"
upstream = "http://chat:8080"
guards = ["pii"]
headers = ["x-user-id"]

# Opted out. This replaces what a route-level scan table used to switch off.
[[reverse_proxy.routes]]
path_prefix = "/static"
upstream = "http://cdn:8080"
guards = []

[admin]
listen = "0.0.0.0:9090"
```

Every key the old format had now lives in exactly one of three places:

| Old | New | Reason |
|---|---|---|
| `pii.*` | `builtin_guards.pii.*` | belongs to the guard that uses it |
| `[[pii.custom]]` | `[[builtin_guards.pii.custom]]` | same |
| `scan.max_body_size`, `scan.content_types`, `scan.on_error` | top level | governs admission before any guard runs |
| `scan.url_path`, `scan.query_params`, `scan.body` | `<guard>.surface.*` | is the guard's Interest |
| `scan.headers` | `route.headers` | names traffic, not a detector; a unit has no header name to filter on |
| `route.scan` | `route.guards` | nothing left to override; selection replaces it |

## Decisions

### Two sections, not one: `[builtin_guards.*]` and a deferred `[guards.*]`

A built-in guard and a configured guard have almost disjoint fields. A built-in has no
model, no artifacts, and no thresholds; a configured one requires all three. Holding both
in one `[guards.*]` table would need a tagged enum fighting `deny_unknown_fields` for no
gain.

The split also decides the singleton question structurally. `[builtin_guards.pii]` admits
one instance per fixed key, so two built-in PII guards — and two `ScannerPool`s sizing
themselves off the same core count — are not expressible. No validation rule is needed to
forbid what the shape cannot say.

*Alternative rejected*: one `[guards.<name>]` table with `type = "pii"` for the built-in.
Uniform, and it makes route selection read from one namespace — but it reintroduces the
instance question and needs a runtime rule to answer it.

### Guard names live in one flat namespace, with built-in names reserved

`route.guards` names guards, so the two sections must resolve into one name space.
Reserving the built-in names and rejecting a collision keeps `guards = ["pii",
"injection"]` readable.

*Alternative rejected*: namespace-qualified references, `guards = ["builtin:pii"]`.
Unambiguous without a reserved list, but noisy at every call site to solve a collision
that validation catches once at startup.

### `enabled` defaults to true when the section is present

The modes set `enabled` false by default, and an absent mode section means disabled. The
first half transfers; the second does not. A mode table holding only `listen` is visibly
incomplete, so defaulting it off surprises nobody. A `[builtin_guards.pii]` block naming
countries, languages, and twenty lines of custom patterns is *not* visibly incomplete, and
an operator who wrote it and got no detection has a silent failure of exactly the kind
`fail_close` exists to prevent.

An absent section still means no guard, which keeps the "nothing configured, nothing
built" property.

*Alternatives rejected*: copying the modes exactly (the footgun above); making `enabled`
mandatory with no default (most explicit, but it puts boilerplate in every example config
to guard against a mistake the default already prevents).

### No enabled guard warns; it does not stop the start

`validate.rs` has no check that any mode is enabled, and `main.rs` starts a proxy with
none. Guards follow that precedent: a warning, not a refusal. It also leaves a deliberate
bypass available during a rollout.

*Alternative rejected*: refusing to start. A transparent unscanned proxy is a bigger
posture change than an idle daemon, so this is arguable — but introducing the first
"something must be enabled" check in this change would apply one rule to guards and not to
modes.

### `Guard::name()` becomes `Arc<str>`; no metric label yet

The name must come from configuration, so `&'static str` cannot hold it without leaking.
`Arc<str>` matches `FindingKind` in the same module.

The `guard` metric label is deliberately *not* added. `metrics/spec.md` states that
`voidwall_pii_detections_total` increments once per kind "however many guards" reported
it. A `guard` label contradicts that: two guards reporting one kind would produce two
series summing to two. With one built-in guard every series would carry `guard="pii"`
anyway, so the label would buy nothing while forcing a metric-contract decision that
nothing exercises. It is decided when a second guard exists.

The rule the code states — that a guard name is never operator-supplied because
cardinality would be unbounded — is replaced by: **bounded by startup configuration,
never by request content.** The `route` label already follows that rule, so the old
wording was inconsistent with existing practice.

### Ingest keys sit at the top level, not in a section

`max_body_size`, `content_types`, and `on_error` govern admission and decoding before any
guard runs, so they are not guard settings. They join `shutdown_timeout_secs` as
top-level keys, matching what is already there.

*Alternative considered*: an `[ingest]` table. Better TOML hygiene — a table is
position-independent, while bare top-level keys must precede the first `[section]` or TOML
binds them to it. See Risks.

### Surface is per guard; the decoder builds the union

The engine already filters units by each guard's `Interest`. Configuration builds that
`Interest` from `surface`, and the handler builds the union of the selected guards'
surfaces so a unit no selected guard wants is never constructed. This keeps the existing
property that decoding cost follows what is actually inspected.

### The header allowlist belongs to the route, not to the surface

A guard's interest is expressed over `UnitKind`, and a `Unit` carries its kind and not a
header name. So a per-guard header allowlist is not enforceable: two guards naming
different headers would both be handed both header units, because the only filter
available is "is this a header value". Configuration would promise a selection the
engine cannot make.

The allowlist is also not really a guard setting. Which headers carry sensitive values
depends on the traffic — `authorization` on an auth route, `x-user-id` on a chat one —
and a regex PII guard scans whatever text it is handed either way. So the route names
them: the route decides which header values become units at all, and every guard it
selected sees them.

The cost is that `surface` no longer fully determines a guard's interest:
`Interest::from_surface` admits `HeaderValue` unconditionally. That is harmless, because
a route that names no header builds no header unit, and it is the honest shape — the
guard is filtered on exactly the three axes the engine can filter on.

*Alternatives rejected*: a `surface.headers` bool, so a guard can opt out of header
values while the route names them — enforceable, but it splits one setting across two
places to solve a problem no guard has yet. A header name on `Unit`, making the per-guard
allowlist real — the right answer if a guard ever needs it, and deferred until one does.

## Risks / Trade-offs

- **Bare top-level keys are position-sensitive in TOML.** `max_body_size` written *after*
  `[builtin_guards.pii]` parses as `builtin_guards.pii.max_body_size`. → `deny_unknown_fields`
  rejects it at startup with the offending path named, and the example configs put the
  ingest keys first. An `[ingest]` table would remove the hazard; it was not chosen
  because the keys are deployment-wide, like `shutdown_timeout_secs`.
- **Every existing config breaks at once.** → Intended, and cheap before the open-core
  release. `deny_unknown_fields` means an old config fails at startup naming `pii` or
  `scan`, never starting with the old settings ignored.
- **Route guard selection is thin with one guard available.** `guards` can only include or
  exclude `pii`. → It still replaces a capability the removed `route.scan` table had — a
  per-route opt-out — and the shape is what model guards need. Accepted as thin, not
  speculative.
- **A route with `guards = []` forwards uninspected traffic and looks like a normal
  route.** → It is explicit in the file, unlike the absent-section case, and the empty
  guard set warning covers the global version of the same mistake.
- **Splitting built-in and configured guards means two schemas to keep aligned** when
  `[guards.*]` lands. → The shared parts, `surface` and the name space, are defined once
  in this change and reused rather than re-declared.

## Migration Plan

1. Land the config types, validation, and the engine changes together. There is no
   intermediate state where both formats parse: `deny_unknown_fields` makes the old keys
   a startup error, which is the intended migration signal.
2. Update the example configs in the same change — `docker/voidwall.toml`, the seven bench
   configs under `crates/voidwall/benches/configs/`, and `docs/custom-pii.md`. A stale
   bench config fails the load-test run rather than scanning with defaults.
3. Rewrite the guard-name rule in `CLAUDE.md`, `engine/guard.rs`, and
   `engine/finding.rs`.

Rollback is a revert: no state, no stored data, and no wire format changes.

## Open Questions

- Whether `on_error` eventually becomes per-guard. It stays top-level here because one
  guard cannot show the difference. `detection-architecture.md` flags it for the phase
  that adds model execution.
