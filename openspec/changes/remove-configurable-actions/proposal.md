## Why

The engine and guard contract landed. The next roadmap phase, Configurable Guard and Policy
Design, must decide how policy attaches to a guard and to a finding kind. The action layer
that exists today is in the way of that decision, not a foundation for it.

Actions are configured as a per-direction list of `block`, `redact`, and `header`, with two
redaction strategies and a configurable block response. That model has no place for a guard,
a finding kind, a threshold, or a confidence. The policy work replaces it rather than
extending it. Designing the replacement on top of machinery that is about to be deleted
means designing it twice, and every migration path drawn through the old shape is wasted.

Removing it now also removes a false claim. `redact` implies the message is safe to forward
after a rewrite. That holds for a regex PII span and does not generalise: a classifier that
reports prompt injection over a whole unit has no span to rewrite, so the only honest
outcome for an unfamiliar detection is to stop the message. Detection blocks. Actions return
in the Policy, Errors, and Deadlines phase, defined against guards instead of directions.

## What Changes

- **BREAKING** Remove the `redact` action. The proxy no longer rewrites a body, a URL path,
  a query string, or a header value. `RedactWith`, `to_redact_with`, `redact_units`, and both
  redaction strategies are deleted.
- **BREAKING** Remove the `header` action and the `X-PII-Detected` response header.
- **BREAKING** Remove the action list itself. `DirectionConfig` collapses to a single
  `scan` boolean. A detection blocks; there is no action to choose. `actions`,
  `redact_strategy`, `mask_char`, `block_status`, `block_body`, and `block_headers` are no
  longer configuration keys, and a file that still carries one fails at startup under the
  existing `deny_unknown_fields` rule.
- **BREAKING** Fix the block response. Status is 403 and the body is a JSON object holding
  an `error` field and a sorted `kinds` array. Neither is configurable.
- **BREAKING** Remove `POST /v1/redact`, together with the `X-PII-Redacted-Count` header and
  the `X-PII-Detected` header it carried. The HTTP API serves three routes.
- **BREAKING** Remove the `voidwall_pii_redacted_total` metric. Five application metrics
  remain. `voidwall_pii_detections_total` and `voidwall_pii_blocked_total` are unchanged.
- **BREAKING** Remove the AI4Privacy evaluation harness. It reaches the proxy only through
  `POST /v1/redact` and recovers spans by diffing `type_label` output against the original
  text, so it cannot outlive the endpoint. The `ai4privacy-eval` binary, the `eval` cargo
  feature, its optional `reqwest` dependency, `docker/ctl eval`, and the four `ai4privacy-*`
  skills go with it. PII detection quality is unmeasurable until the roadmap's Model
  Evaluation Framework phase ships its replacement.
- Delete `crates/voidwall/src/action.rs`. One action does not need an action engine; the
  block decision moves into the reverse proxy beside the scan that produces it.
- Remove the machinery that existed only to carry replacement bytes back to a source field:
  `Unit.label`, `UnitContent::source`, `UnitContent::source_str`, and the `raw` bytes held by
  `UnitContent::Structured`. Dropping the last one releases the body buffer at the end of
  parsing instead of at the end of the request, which the PII safety rules already ask for.
- Keep document-absolute fragment offsets and `Finding.span`. `resolve_overlaps` and
  `matches_count` are defined over spans, and fragment-local offsets would make two
  fragments look like they overlap. Spans stay for the ML PII guard.
- Keep `BlockPolicy` with both variants. `/v1/scan` reports without blocking and passes
  `Never`; the proxy passes `AnyFinding`.

## Capabilities

### New Capabilities

None.

### Modified Capabilities

- `actions`: removed in full. Every requirement describes redaction, the header action, or a
  configurable block response. Two survivors move rather than die — detection metrics
  increment unconditionally moves to `metrics`, and the `on_error` policy requirement moves
  to `pii-scanning`, which already owns scanner failure behaviour.
- `evaluation`: removed in full. The capability describes a harness that talks to
  `/v1/redact` and scores spans recovered from redacted text.
- `configuration`: the block-and-header exclusivity rule, the header direction rule, and the
  redact-strategy rule are removed. The mode-level actions requirement becomes a mode-level
  `scan` requirement. The forward-proxy parse-but-do-not-run requirement keeps its subject
  and loses its header scenario.
- `http-api`: the route count drops from four to three. The `/v1/redact` requirement and the
  redaction-metadata header requirement are removed. The `on_error` requirement loses its
  redact arm, and the custom-label requirement loses its `type_label` clause.
- `metrics`: the registered family count drops from six to five and
  `voidwall_pii_redacted_total` leaves the list. The detection-counting requirement loses its
  reference to a configured action list.
- `pii-scanning`: the document-structure redaction requirement is removed. The guard
  contract and engine aggregation requirements lose their references to redact and header
  outcomes.
- `reverse-proxy`: independent request and response scanning is now expressed with `scan`
  rather than an empty action list. The requirement that redaction rewrites the forwarded
  request is removed.
- `security`: the block-response and buffer-release requirements survive with wording that no
  longer names actions or redaction inputs.
- `custom-pii`: an operator label still surfaces in `pii_kind`, in the block `kinds` list, and
  in `/v1/scan`. It no longer surfaces in `X-PII-Detected` or as a `type_label` replacement.
- `dictionary-detection`: the proxy-surface requirement keeps its subject and loses its
  redaction scenario.

## Impact

**Deleted outright** — `crates/voidwall/src/action.rs` (788 lines),
`crates/voidwall/benches/ai4privacy_eval.rs` (2,000 lines),
`crates/voidwall/benches/k6/action_comparison.js`, three bench configurations
(`reverse_proxy_header.toml`, `reverse_proxy_redact.toml`, `reverse_proxy_no_actions.toml`),
`openspec/specs/actions/spec.md`, `openspec/specs/evaluation/spec.md`, the four
`ai4privacy-{audit,eval,merge,sweep}` skills — one real directory under `.agents/skills/`
and one symlink to it under `.claude/skills/`, so eight paths — and the three
`scripts/*_ai4privacy_*.py` helpers those skills are the only callers of.

**Source edited** — `config.rs` (the `Action` and `RedactStrategy` enums, `DirectionConfig`,
four default constructors, two `HttpApiConfig` fields, `DirectionKind`,
`validate_direction_config`, and the now-empty `validate_forward_proxy` and
`validate_http_api`), `scanner.rs` (`RedactWith` and `to_redact_with`), `engine/unit.rs`
(`Unit.label`, `UnitContent::source`, `source_str`, and `Structured.raw`),
`reverse_proxy.rs` (four state fields, both direction guards, the `Forward` arm of
`PipelineResult`, `pipeline_result_from_outcome`, `apply_redacted_headers`, `rebuild_uri`,
`string_of`, and the stale `content-length` removal that existed because redaction changed
body size), `http_api.rs` (the route, the handler, its OpenAPI block, `build_redact_response`,
the `Mode` enum, and the redact arm of the scanner-failure path), `metrics.rs`
(`REDACTED_TOTAL` and `inc_redacted`), and `lib.rs` (one module declaration).

**Tests edited** — `reverse_proxy_integration.rs` (two fixtures deleted, eleven tests deleted,
four rewritten against a block outcome), `http_api_integration.rs` (every `redact_*` test and
the header assertions inside the OpenAPI test), `structured_scanning_integration.rs` (all nine
tests rewritten to assert detection rather than redacted output — this file is the only
coverage that nested JSON keys and CSV column headers reach the scanner, so it is kept),
`validate_cli_integration.rs` (fixture schema, and the unknown-action case becomes an
unknown-key case).

**Other surfaces** — `crates/voidwall/Cargo.toml` (the `eval` feature, the optional
`reqwest` dependency, and the `ai4privacy-eval` binary; the dev-dependency `reqwest` stays,
because integration tests use it unconditionally), `docker/ctl` (`cmd_eval`, its dispatch,
its usage line, and the eval environment documentation), `docker/voidwall.toml`,
`docker/grafana/dashboards/voidwall.json` (one panel series),
`docker/demo/index.html` (the endpoint option and the redacted-count display),
four `scanner_threads_*.toml` and `http_api.toml` bench configurations, four k6 scripts,
`benches/run.sh` and `benches/README.md`, `ARCHITECTURE.md`, `AGENTS.md`,
`openspec/config.yaml`, `.agents/skills/code-review/SKILL.md` — whose checklist asserts the
old action precedence, so left unedited it would flag this very change as a regression —
`docs/load-testing.md`, `docs/api-docs.md`, `docs/custom-pii.md`,
`docs/config-validation.md`, `docs/backlog.md`, and `docs/roadmap.md`.

**Unaffected, and verified so** — `crates/voidwall-pii/` has no redaction API. It was moved
out of that crate in `aa59392` and the crate's `AGENTS.md` states a detection-only contract.
`crates/voidwall/src/structured/` keeps every parser and every offset: detection needs the
context and the value, and overlap resolution needs the offsets. `.cache/ai4privacy*` is
gitignored and stays on disk.

**Operator impact** — every existing configuration that names an action fails at startup,
because `actions` and its companions are unknown keys under `deny_unknown_fields`. That is
the intended failure: it is loud. Three consequences are not caught by that failure and
belong in the migration note.

A configuration that declares no direction table at all inherits the old defaults —
`["redact", "header"]` on the request and `["redact"]` on the response — and inherits
`scan = true` after this change. A message carrying PII goes from redacted and forwarded to
a 403, with no startup error. `docker/voidwall.toml` is one table away from this shape: its
`[reverse_proxy.response]` body is entirely commented out.

A 403 on the response direction replaces a response the upstream already produced. The
upstream has run and its side effects have happened; the client sees a rejection for a
request that succeeded. Redaction returned a sanitised 200 in that position. Many
deployments will want `response.scan = false`.

`voidwall_pii_blocked_total` changes volume, not just meaning. Blocking is opt-in and rare
today; afterwards every detection in a scanned direction increments it. An alert threshold
tuned against today's rate fires immediately.
