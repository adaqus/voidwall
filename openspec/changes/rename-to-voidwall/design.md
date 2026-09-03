## Context

See `proposal.md` — Why. Two constraints shape the approach.

The rename is wide but shallow. It touches 18 Rust source files, both manifests, six
delta specs, the whole Docker stack, four skills, and two instruction files, yet it
changes no control flow. Nothing in the change should require reasoning about behavior.

The only deployment is the local Docker Compose stack. There are no external consumers of
the metrics, the environment variable, or the library crate. That removes the usual
reason to ship compatibility aliases, and it is why the roadmap puts this change before
Phase 31 makes the repository public.

## Goals / Non-Goals

**Goals:**

- Leave no `pii_proxy_`, `PII_PROXY_CONFIG`, `pii-proxy`, or bare `pii::` token in any
  live file.
- Keep git history readable across the two directory moves.
- Draw one defensible line between a *project* name, which changes, and an *entity* name,
  which does not, and apply it everywhere.
- Leave `openspec/config.yaml` describing the workspace that exists after the change, so
  every later OpenSpec artifact inherits correct context.

**Non-Goals:**

- No compatibility shims. No `PII_PROXY_CONFIG` fallback, no duplicate metric families
  under both names, no `pub use pii` re-export.
- No behavior change of any kind. No new config key, no new metric, no new endpoint.
- No re-framing of spec prose. The specs describe a PII detector because that is what is
  built. Phase 23's `Finding` type is what makes that description wrong, and Phase 23
  will correct it.
- No rename of the `pii-scanning`, `custom-pii`, or `dictionary-detection` capability
  directories.

## Decisions

### 1. `voidwall-pii`, not `voidwall-core`

The roadmap named the renamed library `voidwall-core` in 12 places. We reject that name.

`core` claims the crate is the centre of the system. It is not. After Phase 27 the
workspace holds three crates — `voidwall` (the binary), `voidwall-pii` (regex PII
detection), and `voidwall-ml` (model tiers) — and the PII crate is one detection tier
beside another, not a foundation under both. `voidwall-pii` says what the crate contains
and stays true when `voidwall-ml` arrives.

*Alternative considered:* keep `voidwall-core` for consistency with the written plan.
Rejected — the plan is a draft that this change is the first to execute against, and a
wrong name is cheaper to fix now than after Phase 23 builds on it.

*Consequence:* the roadmap is stale in 12 places and needs an amendment before Phase 23
starts. That amendment is a task in this change, because the file lives in another repo
and nothing else will catch it.

### 2. Metric names are tier-scoped where the metric is tier-specific

Three families count PII events; four describe the engine. The three get `voidwall_pii_`,
the four get `voidwall_`.

The rule comes from the roadmap's own later phases. Phase 24 names its metric
`voidwall_gate_passthrough_ratio` — tier-scoped. A generic scheme would have called it
`voidwall_passthrough_ratio`. Each tier that lands after this change (the L1 gate, the
verdict cache, injection detection) adds its own families, so PII should name itself too.

*Alternative considered:* generic `voidwall_detections_total`, so Phase 28's injection
detections could share the family and only add a label. Rejected — that assumed injection
emits the same event shape as PII detection, which the plan does not support: Phase 28
adds its own metrics and its own capability. A shared family would also leave the
`pii_kind` label wrong for half its series.

### 3. The line between a project name and an entity name

A token changes only if it names *the product*. A token that names *the thing detected*
stays.

| Changes | Stays |
|---|---|
| package, binary, crate, directories | `[pii]` config table and its six keys |
| `PII_PROXY_CONFIG` | `pii_kind` metric label |
| metric family names | `PiiKind`, `PiiMatch`, `PiiError`, `PiiConfig`, `UserPiiDefinition` |
| Docker artifact names | `X-PII-Detected` header |
| | capability directory names |

This is why the change touches six capabilities rather than the nine an earlier scoping
listed. `custom-pii`, `security`, and `http-api` cite only `pii_kind` and `pii.custom`,
and both stay.

*Alternative considered:* rename `[pii]` to `[detection]`. Rejected — five of its six keys
are genuinely PII-scoped (`countries` and `languages` select ID formats and keyword
lists), so `detection.countries` would read wrong, and injection can take a sibling
`[injection]` table without nesting. The sixth, `scanner_threads`, is engine-wide and sits
in the wrong table today; moving it is a separate change and belongs with the phase that
gives the pool more than one tier to schedule.

### 4. Directory moves use `git mv`, and the rename runs mechanically

Two moves: `crates/pii` → `crates/voidwall-pii`, `crates/proxy` → `crates/voidwall`. Use
`git mv` so history follows the files.

The identifier rewrite is a scripted substitution, not hand editing. Order matters, and
the longest token must go first, or a shorter pattern eats a prefix of a longer one:

```
pii_proxy_detections_total  -> voidwall_pii_detections_total   (before pii_proxy_*)
pii_proxy_redacted_total    -> voidwall_pii_redacted_total
pii_proxy_blocked_total     -> voidwall_pii_blocked_total
pii_proxy_                  -> voidwall_                        (the other four)
PII_PROXY_CONFIG            -> VOIDWALL_CONFIG
pii-proxy                   -> voidwall
\bpii_proxy\b               -> voidwall                        (the lib self-reference)
\bpii::                     -> voidwall_pii::
```

Every pattern is anchored so it cannot match `pii_kind`, `PiiKind`, `[pii]`, `pii.custom`,
or `X-PII-Detected`. A `\bpii::` word boundary is required — an unanchored `pii` would
rewrite all five.

### 5. The Compose service rename is the one non-mechanical edit

Renaming the Compose service `proxy` to `voidwall` cascades into three `depends_on` blocks
and the Prometheus scrape target `["proxy:9090"]`. A sed pass over `proxy` in
`docker-compose.yml` would also corrupt the unrelated `reverse_proxy` and `forward_proxy`
config references. Edit that file and `prometheus.yml` by hand.

### 6. Framing states the destination and the current reality

The binary's `about` string becomes `"AI guardrails engine — PII detection today"` and the
library description becomes `"PII detection library for Voidwall"`.

*Alternative considered:* claim the full AI-firewall position now. Rejected — the product
only becomes one when the Phase 24 L1 gate ships, and `--help` should not describe
software that does not exist. *Alternative considered:* change `name` only and defer the
description. Rejected — it leaves the binary calling itself a PII proxy through open core,
and the phase is titled "Identity and framing".

## Risks / Trade-offs

- **A scripted substitution over-matches and silently renames an entity token** → every
  pattern in Decision 4 is anchored, and a verification task greps for the five protected
  tokens after the sweep to prove they survive at their original counts.

- **The Grafana dashboard breaks silently.** A dashboard with stale PromQL renders empty
  panels rather than an error → the dashboard is verified by loading it against a running
  stack, not by grepping the JSON.

- **Five integration test files assert on metric names.** A missed one fails the build,
  which is the desired outcome, but a missed *assertion inside a passing test* does not →
  `cargo test --workspace` plus a repo-wide grep for the retired prefix, both required.

- **Later pivot phases reference a crate this change does not create.** Phase 23 step 1
  says "add a `Finding` type to `voidwall-core`" → the plan amendment is a task here, not
  a follow-up, because no later phase will notice the gap before it builds on it.

- **The rename lands in one commit and cannot be partially reverted.** Rollback is
  `git revert` of the whole change → accepted; the change has no data migration and no
  deployed consumer, so a full revert costs nothing.

## Migration Plan

There is no production deployment and no external consumer, so there is no live migration.

1. Land the rename in one change.
2. Rebuild the Docker stack. `docker/ctl start` is the acceptance gate: it exercises the
   renamed binary, the renamed Dockerfile, the renamed config file, the renamed Compose
   service, and the Prometheus target in one command.
3. Load the Grafana dashboard against the running stack and confirm every panel draws.

**Rollback:** `git revert` the change and rebuild. No state is written, no schema changes,
and no external system holds the old names.

## Open Questions

None. The one question this design carried — whether `openspec/config.yaml` keyed its
spec rules under the wrong id — is resolved. The key was `spec:` where the artifact id is
`specs`, so both rules were silently inactive, and the fix restored them.
