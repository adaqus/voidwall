## Why

GA4 and Matomo are the old product. Voidwall is becoming an AI guardrails engine, and the
traffic it inspects shifts from web analytics beacons to agent calls against LLM APIs. The
two analytics specializations carry 3,643 lines of decoder, a config field, a metric family,
two metric labels, an HTTP query parameter, and a response header — all serving a traffic
shape the product no longer targets.

The removal also unblocks the Engine and guard contract that follows it.
`ScanHandle::scan` submits one scanner-pool round trip **per field**: a GA4 hit carrying 50
parameters costs 50 `spawn_blocking` calls and 50 oneshot channels. That is a third scan
granularity — neither one request nor one unit list — that the next change would otherwise
have to design around. Batching it would mean restructuring `Specialization::process`, which
interleaves decode, scan, and re-encode in a single trait method.

## What Changes

- **BREAKING** Remove the `specializations` capability entirely: the `Specialization` trait,
  the GA4 and Matomo adapters, the dispatch and aggregation layer, and the four dedicated
  integration test files.
- **BREAKING** Remove the `specialization` field from a reverse-proxy route. A configuration
  that still names one now fails at startup.
- **BREAKING** Add `deny_unknown_fields` to every configuration struct. Any key the schema
  does not define fails validation at startup instead of being ignored in silence. This is
  what makes the removed `specialization` key a loud failure rather than a quiet
  degradation, and it applies to every other stray or misspelled key with it.
- **BREAKING** Remove the `?specialization=` query parameter from `/v1/scan` and
  `/v1/redact`. The parameter is no longer read, so a request that still carries it is
  scanned by the content-type router and answered `200`. A request naming an unknown
  specialization was answered `400` before this change and is answered `200` after it.
- **BREAKING** Remove the `X-PII-Specialization` response header from `/v1/scan` and
  `/v1/redact`.
- **BREAKING** Remove the `voidwall_specialization_errors_total` metric family, and remove
  the `specialization` label from `voidwall_pii_detections_total` and
  `voidwall_pii_redacted_total`.
- Delete `docs/specializations.md`, the GA4 and Matomo load-test scenarios, the two bench
  configurations, and the analytics examples in the demo page.
- Keep `crates/voidwall/src/structured/` untouched. Per-field scanning that carries a key
  path in `context` is what the LLM decoders need later, and it has no reference to the
  specialization module.

## Capabilities

### New Capabilities

None.

### Modified Capabilities

- `specializations`: removed in full. Every requirement in the capability is deleted and the
  capability file goes with it.
- `configuration`: the requirement that a named specialization must match a built-in one is
  removed. A new requirement states that an unknown configuration key fails validation at
  startup.
- `http-api`: the requirement that a specialization can be selected per request is removed,
  together with the `X-PII-Specialization` response header and the `400` answer for an
  unknown specialization name.
- `metrics`: the registered family count drops from seven to six, the `specialization` label
  leaves the detection and redaction counters, and the label-value requirement and the
  no-specialization scenario go with it.
- `reverse-proxy`: the requirement that a route may name a specialization is removed.
- `security`: the specialization decode-failure logging scenario is removed, and
  `specialization` leaves the list of label values a metric may hold. Both parent
  requirements survive.

## Impact

**Deleted outright** — 8,561 lines across nine files: `crates/voidwall/src/specialization/`
(`ga4.rs`, `matomo.rs`, `mod.rs`), the `ga4_integration`, `ga4_spec_integration`,
`matomo_integration`, and `matomo_spec_integration` test files, `docs/specializations.md`,
and `openspec/specs/specializations/spec.md`.

**Source edited** — `lib.rs` (module declaration), `config.rs` (the route field, its startup
validation, three unit tests, and `deny_unknown_fields` on ten structs), `metrics.rs` (one
family, two labels, and their tests), `action.rs` (`ActionContext.specialization` and two
call sites), `reverse_proxy.rs` (the dispatch branch in both directions, the route
resolution, and roughly 300 lines of in-file pipeline tests with three test doubles), and
`http_api.rs` (the query parameter, the resolver, both aggregate response builders, the
header, and two OpenAPI declarations).

**Tests edited** — `http_api_integration.rs` (about 15 of its 41 tests),
`reverse_proxy_integration.rs` and `structured_scanning_integration.rs` (route literals
only).

**Other surfaces** — `crates/voidwall/benches/` (three k6 scripts, two configurations, the
scenario list in `run.sh` in two places, the `README.md` table, and a comment in
`echo_server.rs`), `docker/voidwall.toml`, `docker/demo/index.html`, `ARCHITECTURE.md`
(§ 4.4 and four other references), and `docs/backlog.md` (§ 1.4, § 1.5, and a documentation
bullet).

**Unaffected, and verified so** — the Grafana dashboard has no reference to the
`specialization` label and every panel aggregates it away, so no panel breaks.
`crates/voidwall/src/structured/` has no reference to the specialization module.
`AGENTS.md` no longer mentions specializations.

**Operator impact** — a configuration that still names a specialization, or that carries any
key the schema does not define, fails at startup with a validation error. Ten TOML files in
this repository must re-validate after the strictness lands.
