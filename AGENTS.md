# Project Instructions

Voidwall is an AI guardrails engine: an HTTP proxy and REST API that inspects traffic
and acts on what it finds. A guard reports findings; the engine merges them. A detection
blocks the message with a fixed 403 naming the kinds that were found — there is no
action to choose. Personally identifiable information (PII) is the class of finding it
detects today, and each further class arrives as another guard.

## Communication

Be concise and use simple words. Keep explanations short unless the user asks for detail.

## Before Coding

- State assumptions. Ask when material requirements are unclear.
- Present meaningful alternatives instead of silently choosing one.
- Prefer the simplest correct approach.
- Define a verifiable outcome before implementation.

## Changes

- Touch only what the task requires.
- Do not refactor unrelated code.
- Match the existing style.
- Remove only dead code created by the current change.
- Do not revert or modify changes made by someone else.
- Do not commit finished work.

For multi-step work, state a brief plan with a verification check for each step.

## Project Layout

- Architecture and rationale: `ARCHITECTURE.md`
- Built behavior: `openspec/specs/`
- Active work: `openspec/changes/`
- Unbuilt work: `docs/backlog.md`
- Load testing: `docs/load-testing.md`
- History for Phases 1 to 20: `docs/history/tasks-phases-1-20.md`

Start coding agents from the workspace root. Commands below assume that location.

The Cargo workspace has two members:

- `crates/voidwall/`: binary package `voidwall`. Integration tests, k6 load tests, and
  benchmark scripts live under `crates/voidwall/tests/` and `crates/voidwall/benches/`.
- `crates/voidwall-pii/`: detection library. Read `crates/voidwall-pii/AGENTS.md` before editing anything
  under this crate.

Proxy documentation lives under `docs/`.

## Platform

Only Linux is supported. Do not add platform-conditional code for other operating systems.

## Distribution

Voidwall ships as a Docker image that starts the guardrails proxy out of the box. The image
carries the configuration and the model artifacts every shipped guard needs, so an operator
runs the service without supplying either.

## Writing code in Rust

Always use Rust's type system to make undesired states (e.g. invalid configuration, code dependencies)
irrepresentable.

## Build

Run commands from the workspace root:

```bash
cargo check --workspace
cargo test --workspace
cargo test -p voidwall <name>
cargo test -p voidwall-pii <name>
cargo clippy --workspace --all-targets
```

Treat Clippy warnings as errors. The workspace uses Rust edition 2024.

## Architecture

One binary provides four independently enabled modes that share one detection engine:

- Reverse proxy on `:8082`
- Forward proxy on `:8084`
- REST API on `:8083`
- Admin server on `:9090`

Configuration is TOML loaded with `--config` or `VOIDWALL_CONFIG`.

Main modules: `config`, `engine`, `scanner`, `reverse_proxy`, `forward_proxy`,
`http_api`, `admin`, `metrics`, `tls`, and `error`.

## Detection Engine

`engine` holds the detection contract. A handler decodes a message into `Unit`s — one per
body, URL path, query string, and scanned header value — and calls `Engine::guard`.

A `Guard` is one detection concern: `name`, `interest`, `detect`. It returns `Finding`s and
does nothing else. It never blocks the message, changes it, or writes a metric. A guard
owns whatever it needs to detect; the regex PII guard owns the `ScannerPool`, which is
reachable from nowhere else.

- Add a detector by adding a guard, never by branching inside a handler.
- `name()` returns the name configuration gave the guard. It reaches finding
  records and can reach a metric label, so the set of names is bounded by startup
  configuration, never by request content. A name is never taken from a request,
  a response, or a detected value.
- A guard declares its interest; the `Engine` applies it. A guard no selected unit
  interests is not called.
- Findings come back in canonical order — unit, span start, span end, guard, kind, with
  span-less findings last — so arrival order is invisible and a kind list is stable.
- The engine short-circuits for a block and nothing else. A guard still running is
  abandoned. A caller that reports rather than blocks waits for every guard.
- Shutdown is `Drop`-only. `Engine::shutdown` releases the guards and then logs.

## Detection Safety

These rules are mandatory. They cover every value a guard detects, whatever its class.
PII is the class that exists today; nothing below is scoped to it.

- Never log a detected value. Log kind names and match counts only.
- Never expose a detected value in metrics. Labels use kind names only.
- Never include a detected value in an error response. A 403 lists kinds, not matched text.
- Drop request and response body buffers promptly after scanning.

## Match Resolution

The regex PII guard passes every `Scanner::mark_piis(_structured)` result through
`voidwall_pii::resolve_overlaps`, once per unit, before it returns a finding. The proxy uses
only the resolved, non-overlapping set:

- `/v1/scan` `matches_count` equals `resolve_overlaps(raw).len()`.
- API and 403 `kinds` lists derive from the resolved set.
- `voidwall_pii_detections_total{pii_kind=...}` increments once per kind in the resolved
  match set.
- The same value at different byte offsets remains separate PII instances.

The policy lives in `crates/voidwall-pii/src/overlap.rs` and `crates/voidwall-pii/AGENTS.md`. Do not
reimplement it in the proxy.

Resolution is scoped to a kind vocabulary, and it runs once. `resolve_overlaps` is a
greedy pairwise pass, so resolving each guard's findings and then resolving the union is
not the same as resolving the union. While one guard is the only producer of a
vocabulary, that guard resolves and the engine adds nothing. When a second producer of
the same vocabulary appears, move resolution to the engine over the union and delete the
per-guard pass. Never run both.

## Threading

The PII scanner is CPU-bound and must not run on the Tokio async runtime. `ScannerPool`,
inside the regex PII guard, spawns dedicated OS threads, each owning one
`voidwall_pii::Scanner`. A bounded channel carries requests and `tokio::sync::oneshot` carries
responses. Never call `voidwall_pii::Scanner` directly from an async context.

A guard's `detect` is `async` but does almost no work of its own: it hands the units to
its own workers and awaits the reply. Keep it that way.

## Errors

- Use the unified `Error` enum from `error.rs` for fallible proxy operations.
- Scanner failures and limit violations follow the configured `on_error` policy:
  `fail_open` or `fail_close`. `fail_close` is the default, so an operator who writes no
  `on_error` gets blocking.
- A blocking error answers the status that names the party at fault: 413 for an oversize
  body, 400 for a body that does not parse as its declared content type, 500 for a scanner
  failure. 502 is reserved for a failure of the upstream itself.
- Always increment `voidwall_errors_total` with the outcome.
- Propagate proxy and I/O errors with context instead of turning all failures into generic
  500 responses.

## Configuration

- Validation runs at startup and invalid configuration prevents startup.
- A per-route scan override fully replaces the defaults. It does not merge.
- New fields require validation and unit tests for valid and invalid values.

## Testing

- Put unit tests in the same file under `#[cfg(test)] mod tests`.
- Prefer `#[test_case]` where it removes duplicated test code.
- Integration tests under `crates/voidwall/tests/` start real servers and make real HTTP
  requests.
- Load tests live in `crates/voidwall/benches/`; see `docs/load-testing.md`.

## Outcomes

A detection blocks. The proxy answers a fixed 403 carrying an `error` field and a sorted
`kinds` array, and short-circuits forwarding. The status, the body, and the response
headers are not configurable. There is no redact action, no header action, and no `warn`
action, and nothing anywhere rewrites a message.

`reverse_proxy.request.scan` and `reverse_proxy.response.scan` turn inspection on or off
for one direction; both default to true. Detection and blocked metrics increment whenever
the corresponding event occurs.

Actions return in the roadmap's *Policy, Errors, and Deadlines* phase, defined against
guards and finding kinds rather than directions. Do not reintroduce a per-direction
action list.

## OpenSpec

`openspec/specs/` states built behavior. `openspec/changes/` holds work in progress. A
spec must describe behavior that is built and tested. Unbuilt work belongs in
`docs/backlog.md` until a change starts.

Use OpenSpec when any of these apply:

- The change alters observable behavior such as an endpoint, config field, action, metric,
  error code, or detector output.
- The change touches more than one crate.
- The change is one step of a planned engine tier and it ships code.
- The change implements a feature listed in `docs/backlog.md`.
- A decision must be recorded for later work.
- The change cannot be reviewed in one diff.

Do not use OpenSpec when any of these apply:

- A bug fix restores behavior already specified.
- A country or language is added through the `add-pii` skill. That skill is the spec.
- A performance change preserves the match set.
- Work affects only documentation, research, or evaluation datasets.
- The work takes about an hour and one diff shows all of it.

The test is: would somebody disagree about what done means? If yes, write a proposal.

Workflow:

1. Use the `openspec-propose` workflow to create `proposal.md`, `design.md`, `tasks.md`,
   and spec deltas.
2. Run `openspec validate <name> --strict`.
3. Use the `openspec-apply-change` workflow. Mark tasks only in the change's `tasks.md`.
4. Run workspace tests and Clippy.
5. Review the diff against the spec deltas with the `code-review` skill.
6. Run `openspec archive <name>` to merge deltas into the main specs.

Rules:

- A tracked change lives in `openspec/changes/<name>/`.
- Do not edit `openspec/specs/` by hand. `openspec archive` writes it, and the
  `openspec-sync-specs` workflow can write it before archive when a change lands in parts.
- Do not edit checkboxes in `docs/history/tasks-phases-1-20.md`; it is history.
- Verify implementation against the change's spec deltas and then `ARCHITECTURE.md`.
- In proposal.md, design.md and changes/ write only stuff explicitly agreed on - do not
  infer requirements that seem implicit - in such case ask whether your suspicion is correct.
