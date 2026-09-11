## Context

See `proposal.md` — Why. Two structural facts shape the approach.

First, the action layer is not a module. It is a seam running through six files.
`config.rs` parses the action list, `action.rs` interprets it, `reverse_proxy.rs` applies
the result, `http_api.rs` bypasses the action set and calls the redactor directly,
`scanner.rs` holds the redaction strategy type, and `metrics.rs` counts redactions.
Removing it is one diff or a broken build.

Second, redaction reaches further down than it looks. `Unit.label`,
`UnitContent::source`, `UnitContent::source_str`, and the `raw` bytes inside
`UnitContent::Structured` exist so replacement bytes can be mapped back to the field they
came from. Nothing else reads them. They are dead the moment the redactor is.

`crates/voidwall-pii/` is not in scope. Redaction left that crate in `aa59392`, and its
`AGENTS.md` states a detection-only contract.

## Goals / Non-Goals

**Goals:**

- Leave one outcome for a detection, and make it non-negotiable.
- Leave the engine and guard contract intact. The next roadmap phase builds policy on it.
- Delete the machinery that only redaction used, so the next phase does not inherit it.
- Fail loudly on an old configuration rather than reinterpret it.

**Non-Goals:**

- Designing the policy model that replaces actions. That is the *Configurable Guard and
  Policy Design* phase. This change deliberately ships no replacement.
- Preserving a redaction capability anywhere, including as an internal helper.
- Replacing the evaluation harness. Detection quality is unmeasurable until the *Model
  Evaluation Framework* phase.
- Building the forward proxy. Its configuration keeps parsing and keeps not running.

## Decisions

### Delete `action.rs` rather than shrink it

Once block is the only outcome, `execute` is: return early on no detection, count the
kinds, count the block, build a fixed body. That is a dozen lines with one caller. A
module boundary around it would name a thing that no longer exists — there is no engine
of actions when there is one action.

*Alternative considered:* keep a thin `action.rs` so the *Policy, Errors, and Deadlines*
phase refills it instead of recreating it. Rejected, because an empty seam invites the next
phase to fit policy into the old shape. The whole reason for this change is to stop that.
`ARCHITECTURE.md` and `AGENTS.md` lose the module from their module lists.

### `DirectionConfig` keeps its table and loses everything but `scan`

An operator needs a way to say "do not inspect responses". Today an empty action list says
it. A single `scan` boolean says the same thing and nothing more.

*Alternative considered:* fold it into `[scan]` as a `directions` list, which routes could
then override for free — routes already override `scan`. Rejected for this change: it moves
a mode-level setting to a route-level one, which the `configuration` capability currently
forbids, and that is a policy decision belonging to the next phase.

*Alternative considered:* booleans on the mode (`scan_request`, `scan_response`) and delete
`DirectionConfig` outright. Rejected: the next phase reintroduces per-direction settings,
and the table is the natural place for them.

### The block response is fixed, not defaulted

`block_status`, `block_body`, and `block_headers` are removed rather than given
non-overridable defaults. A configuration key that exists but cannot vary is a lie the
schema tells. Under `deny_unknown_fields` a file that still carries one fails at startup,
which is the migration signal.

The body stays the JSON object it is today — `error` plus a sorted `kinds` array. The array
comes from `ScanResult::kinds()`, so the sort and the deduplication are the engine's, not
the proxy's. That is why the deleted requirement about deterministic kind lists needs no
replacement: `pii-scanning` already requires it of the scan result.

### `BlockPolicy` keeps both variants

`AnyFinding` short-circuits the engine when a finding is enough to stop the message.
`Never` runs every guard to completion. It would be easy to read this change as making
`Never` dead, since the proxy always blocks. It does not: `/v1/scan` reports without
blocking and passes `Never`. Both variants keep a production caller, so the enum stays and
the engine's short-circuit contract is unchanged.

### A direction table loses its last semantic rule, so validation must be re-anchored

`validate_direction_config` held the only semantic rules a direction table had: block and
header exclusivity, header direction, and the redact strategy pairing. All three go, and
`validate_forward_proxy` and `validate_http_api` exist only to call it and to check the one
redaction rule. All four disappear, and a direction table is then validated by the serde
schema alone.

Two tests are anchored to those rules. `validate.rs::semantic_error_categorised_as_semantic`
uses block-plus-header as its semantic failure, and `docs/config-validation.md` cites the
same pair as the canonical `[semantic]` diagnostic. Neither has a replacement unless one is
chosen deliberately: use a duplicate `path_prefix`, which is a surviving semantic rule in
`validate_reverse_proxy` and is the closest analogue. `schema_error_categorised_as_schema`
switches to `actions = ["redact"]`, which is now a schema error and doubles as a migration
test.

### Structured parsing keeps its offsets, and loses its document

`OwnedContextFragment.offset` and the two position-recovery passes look like redaction
machinery — they exist to point at bytes in the original document. They stay. Overlap
resolution is defined over spans, and fragment-local offsets would make two fragments look
like they overlap when they do not.

What goes is `UnitContent::Structured.raw`: the retained copy of the document. Only
redaction read it. Dropping it releases the body at the end of parsing rather than the end
of the request, which the PII safety rules already ask for. This is the one place where the
change improves behaviour rather than only removing it.

### The evaluation harness dies with the endpoint, and is not ported

The harness recovers spans by diffing `type_label` output against the original text.
`/v1/scan` cannot substitute — it answers with a deduplicated kind set carrying no offsets.

*Alternative considered:* add a `spans` array to `/v1/scan` and port the harness onto it.
It would be a better harness: exact spans instead of reconstructed ones. Rejected here
because it is new API surface inside a removal, and because the *Model Evaluation
Framework* phase owns that decision. It is the obvious first move for that phase and is
recorded as such.

*Alternative considered:* port the harness to link `voidwall_pii` directly. Rejected: it
contradicts the evaluation capability's own reason for going over HTTP — scoring what the
proxy does, not what the library does.

### Integration tests are rewritten to assert detection, not deleted

`structured_scanning_integration.rs` asserts redacted output in all nine of its tests, so
it reads as a redaction test file. It is not. It is the only coverage that a JSON key path
and a CSV column header reach the scanner as context. Deleting it would silently drop that
coverage. Each test keeps its input and swaps its assertion from redacted bytes to a 403
naming the expected kinds.

## Risks / Trade-offs

**Every existing configuration stops the proxy at startup** → Intended, and loud.
`deny_unknown_fields` turns `actions` and its companions into named errors. The alternative
— accepting and ignoring them — would silently change what a deployment does. The change
must ship with a migration note, and `--validate` on an old file is a task-level check.

**A configuration that omits a direction table changes outcome silently** → The one quiet
case. An omitted table means `["redact"]` today and `scan = true` after, so PII goes from
redacted-and-forwarded to 403 with no startup error. Mitigation: call it out in the
proposal and the migration note, and write both tables explicitly in
`docker/voidwall.toml`.

*This is the weakest point in the design, and there is a stronger alternative:* make `scan`
required whenever the mode is enabled, with no serde default. That converts the last silent
path into a named startup error and matches the argument `ARCHITECTURE.md` §4.6 already
makes for custom PII definitions — a silent weakening of detection is worse than a loud
refusal to start. The cost is that a minimal reverse-proxy config must now state two
booleans. This design keeps the default because the silent case needs a config that
declares no direction table at all, which is rare; the alternative is a one-line change to
the `configuration` spec if that trade reads differently.

**A response-direction block discards work the upstream already did** → A 403 on the
response direction replaces a response the upstream produced, after its side effects have
happened. The client sees a rejection for a request that succeeded, and cannot tell the
difference from a request that was never forwarded. Redaction returned a sanitised 200 in
that position, so this is a new failure mode rather than a stricter version of an old one.
Mitigation: it is documented, and `response.scan = false` turns it off. It is not fixable
inside this change — inspecting a response after forwarding is inherent to the proxy shape,
and the only alternative outcome for a response is the redaction being removed.

**Every PII-carrying benchmark now terminates at the proxy** → `body_size_scaling`,
`scanner_thread_scaling`, and `structured_scanning` drive PII payloads, which now answer 403
without reaching the upstream. The forward path stops being measured and historical numbers
stop being comparable. Mitigation: switch the payload to clean content where the scenario
measures proxying cost, and re-baseline `structured_scanning`, whose subject is parse cost
and still runs.

**Detection quality becomes unmeasurable** → Accepted, with a known end date. No regression
gate is lost, because the evaluation capability already forbade the harness acting as one.
`.cache/ai4privacy*` stays on disk so the datasets do not need refetching.

**Redaction is a feature some deployments rely on** → It leaves with no replacement, and
this is a deliberate product decision, not an oversight. A deployment that needs a message
rewritten must do it upstream of the proxy. The proposal states this plainly rather than
implying a workaround exists.

**The next phase may want the deleted seam back** → Likely, and cheap. What returns is a
policy model keyed on guards and finding kinds, which shares no code with `ActionSet`. The
cost of recreating a module is far below the cost of designing policy around a shape that
was about to be deleted.

## Migration Plan

1. Remove `actions`, `redact_strategy`, `mask_char`, `block_status`, `block_body`, and
   `block_headers` from every direction table, and `redact_strategy` and `mask_char` from
   `[http_api]`.
2. Where a direction previously carried `actions = []`, write `scan = false`. Where it
   carried any non-empty list, write `scan = true` or omit the key.
3. Write both direction tables explicitly for any deployment that previously relied on the
   defaults, so the response direction does not silently begin blocking.
4. Drop any dashboard panel or alert reading `voidwall_pii_redacted_total`.
5. Stop calling `POST /v1/redact`. `POST /v1/scan` reports what a body carries.
6. Run `--validate` on the rewritten file before deploying. An old file exits non-zero with
   the offending key named.

Rollback is a revert of the whole change and the old configuration file. There is no
forward-compatible configuration that both versions accept, because the old schema rejects
`scan` and the new one rejects `actions`.
