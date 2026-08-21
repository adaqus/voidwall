# Project Instructions

Voidwall is an HTTP proxy and REST API for detecting personally identifiable information
(PII). It can redact or block HTTP requests and report detected PII kinds.

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

- `crates/proxy/`: binary package `pii-proxy`. Integration tests, k6 load tests, and
  benchmark scripts live under `crates/proxy/tests/` and `crates/proxy/benches/`.
- `crates/pii/`: detection library. Read `crates/pii/AGENTS.md` before editing anything
  under this crate.

Proxy documentation lives under `docs/`.

## Platform

Only Linux is supported. Do not add platform-conditional code for other operating systems.

## Build

Run commands from the workspace root:

```bash
cargo check --workspace
cargo test --workspace
cargo test -p pii-proxy <name>
cargo test -p pii <name>
cargo clippy --workspace --all-targets
```

Treat Clippy warnings as errors. The workspace uses Rust edition 2024.

## Architecture

One binary provides four independently enabled modes that share one `ScannerPool`:

- Reverse proxy on `:8082`
- Forward proxy on `:8084`
- REST API on `:8083`
- Admin server on `:9090`

Configuration is TOML loaded with `--config` or `PII_PROXY_CONFIG`.

Main modules: `config`, `scanner`, `action`, `reverse_proxy`, `forward_proxy`, `http_api`,
`admin`, `metrics`, `tls`, and `error`.

## PII Safety

These rules are mandatory:

- Never log PII values. Log kind names and match counts only.
- Never expose PII values in metrics. Labels use kind names only.
- Never include PII values in error responses. A 403 lists kinds, not matched text.
- Drop request and response body buffers promptly after scanning.

## Match Resolution

`execute_scan` passes every `Scanner::mark_piis(_structured)` result through
`pii::resolve_overlaps` before counting, redacting, or reporting matches. The proxy uses
only the resolved, non-overlapping set:

- `/v1/scan` and `/v1/redact` `matches_count` equals `resolve_overlaps(raw).len()`.
- API and 403 `kinds` lists derive from the resolved set.
- `pii_detections_total{kind=...}` increments once per resolved match.
- The same value at different byte offsets remains separate PII instances.

The policy lives in `crates/pii/src/overlap.rs` and `crates/pii/AGENTS.md`. Do not
reimplement it in the proxy.

## Threading

The PII scanner is CPU-bound and must not run on the Tokio async runtime. `ScannerPool`
spawns dedicated OS threads, each owning one `pii::Scanner`. A bounded channel carries
requests and `tokio::sync::oneshot` carries responses. Never call `pii::Scanner` directly
from an async context.

## Errors

- Use the unified `Error` enum from `error.rs` for fallible proxy operations.
- Scanner failures and limit violations follow the configured `on_error` policy:
  `fail_open` or `fail_close`.
- Always increment `pii_proxy_errors_total` with the outcome.
- Propagate proxy and I/O errors with context instead of turning all failures into generic
  500 responses.

## Configuration

- Validation runs at startup and invalid configuration prevents startup.
- Per-route scan and action overrides fully replace defaults. They do not merge.
- New fields require validation and unit tests for valid and invalid values.

## Testing

- Put unit tests in the same file under `#[cfg(test)] mod tests`.
- Prefer `#[test_case]` where it removes duplicated test code.
- Integration tests under `crates/proxy/tests/` start real servers and make real HTTP
  requests.
- Load tests live in `crates/proxy/benches/`; see `docs/load-testing.md`.

## Action Precedence

Actions run in this order: block, redact, header. Block short-circuits forwarding. There
is no `warn` action. Detection, blocked, and redacted metrics increment whenever the
corresponding event occurs. Request and response actions are configured separately.

## OpenSpec

`openspec/specs/` states built behavior. `openspec/changes/` holds work in progress. A
spec must describe behavior that is built and tested. Unbuilt work belongs in
`docs/backlog.md` until a change starts.

Use OpenSpec when any of these apply:

- The change alters observable behavior such as an endpoint, config field, action, metric,
  error code, or detector output.
- The change touches more than one crate.
- The change is a pivot phase from Phase 21 through Phase 31.
- The change implements a feature listed in `docs/backlog.md`.
- A decision must be recorded for later work.
- The change cannot be reviewed in one diff.

Do not use OpenSpec when any of these apply:

- A bug fix restores behavior already specified.
- A country or language is added through the `add-pii` skill. That skill is the spec.
- A performance change preserves the match set.
- Work affects only documentation, research, the landing page, or evaluation datasets.
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
