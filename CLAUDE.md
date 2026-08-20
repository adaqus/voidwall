# CLAUDE.md

This is Voidwall, HTTP Proxy/API for detecting PIIs (Personally Identifiable Data). It is able
to redact or block HTTP requests and alert about detected PIIs in HTTP request.

## 0. Communication style

Wen communicating with the user, be concise, use simple words. Make your communication fast
and easy to read.

Constraint: Output should be succinct and direct. Avoid explanations unless specifically asked. Only short explanations allowed.

## 1. Think Before Coding

**Don't assume. Don't hide confusion. Surface tradeoffs.**

Before implementing:
- State your assumptions explicitly. If uncertain, ask.
- If multiple interpretations exist, present them - don't pick silently.
- If a simpler approach exists, say so. Push back when warranted.
- If something is unclear, stop. Name what's confusing. Ask.

## 2. Simplicity First

**Minimum code that solves the problem. Nothing speculative.**

- No features beyond what was asked.
- No abstractions for single-use code.
- No "flexibility" or "configurability" that wasn't requested.
- No error handling for impossible scenarios.
- If you write 200 lines and it could be 50, rewrite it.

Ask yourself: "Would a senior engineer say this is overcomplicated?" If yes, simplify.

## 3. Surgical Changes

**Touch only what you must. Clean up only your own mess.**

When editing existing code:
- Don't "improve" adjacent code, comments, or formatting.
- Don't refactor things that aren't broken.
- Match existing style, even if you'd do it differently.
- If you notice unrelated dead code, mention it - don't delete it.

When your changes create orphans:
- Remove imports/variables/functions that YOUR changes made unused.
- Don't remove pre-existing dead code unless asked.

The test: Every changed line should trace directly to the user's request.

## 4. Goal-Driven Execution

**Define success criteria. Loop until verified.**

Transform tasks into verifiable goals:
- "Add validation" → "Write tests for invalid inputs, then make them pass"
- "Fix the bug" → "Write a test that reproduces it, then make it pass"
- "Refactor X" → "Ensure tests pass before and after"

For multi-step tasks, state a brief plan:
```
1. [Step] → verify: [check]
2. [Step] → verify: [check]
3. [Step] → verify: [check]
```

Strong success criteria let you loop independently. Weak criteria ("make it work") require constant clarification.

## Project

PII Proxy — a multi-mode HTTP proxy that inspects HTTP traffic for PII using the `pii` crate. Except proxy, it also offers REST API to check/redact data in terms if PII presence.
Where things live:
- Architecture and rationale: `ARCHITECTURE.md`
- Built behaviour, one file per capability: `openspec/specs/`
- Active work: `openspec/changes/`
- Unbuilt work: `docs/backlog.md`
- Load testing: `docs/load-testing.md`
- History, Phases 1 to 20: `docs/history/tasks-phases-1-20.md`

## Workspace

Cargo workspace with two members:
- `crates/proxy/` — this binary (package `pii-proxy`). Integration tests, k6 load tests, and bench scripts live under `crates/proxy/tests/` and `crates/proxy/benches/`.
- `crates/pii/` — the detection library. Library-internal rules (Vectorscan, detector chain, keyword-context patterns, overlap resolution, adding a new language/country) live in `crates/pii/CLAUDE.md`. Read it before editing anything under `crates/pii/`.

Proxy docs are under `docs/`.

## Platform

Only Linux is supported. Do not add platform-conditional code for other OSes.

## Build

Commands run from the workspace root. `--workspace` covers both crates; `-p <name>` scopes to one.

```bash
cargo check --workspace 2>&1 | tail -n 20m
cargo test --workspace 2>&1 | tail -n 20m
cargo test -p pii-proxy <name> 2>&1 | tail -n 20m      # single proxy test
cargo test -p pii <name> 2>&1 | tail -n 20m            # single pii test
cargo clippy --workspace --all-targets 2>&1 | tail -n 20m  # lint — treat warnings as errors
```

Rust edition: 2024.

## Architecture

Single binary, four independently-enabled modes sharing one `ScannerPool`:
- Reverse Proxy (:8082), Forward Proxy (:8084), REST API (:8083), Admin (:9090)
- Config is TOML, loaded via `--config` or `PII_PROXY_CONFIG` env var

Modules: `config`, `scanner`, `action`, `reverse_proxy`, `forward_proxy`, `api`, `admin`, `metrics`, `tls`, `error`.

## PII Safety Rules

These are non-negotiable and apply everywhere:
- **Never log PII values.** Log PII kind names and match counts only.
- **Never expose PII in metrics.** Metric labels use kind names, never values.
- **Never include PII in error responses.** 403 responses list detected kinds, not matched text.
- **Drop body buffers promptly** after scanning. Do not hold request bodies longer than needed.

## Match Resolution

`execute_scan` runs every `Scanner::mark_piis(_structured)` result through `pii::resolve_overlaps` before counting, redacting, or surfacing matches. The proxy operates exclusively on the resolved (non-overlapping) set:

- `/v1/scan` and `/v1/redact` `matches_count` = `resolve_overlaps(raw).len()`.
- `kinds` lists in API responses and 403 errors derive from the resolved set.
- Prometheus `pii_detections_total{kind=…}` increments per resolved match.
- Same value at distinct byte offsets stays as distinct matches — those are separate PII instances.

Policy and priority groups live in the `pii` crate (`crates/pii/src/overlap.rs` + `crates/pii/CLAUDE.md`). Don't reimplement resolution here.

## Threading Model

The PII scanner is CPU-bound and **must not run on the tokio async runtime**.
`ScannerPool` spawns dedicated OS threads (`std::thread::spawn`), each owning its own
`pii::Scanner` instance. Communication: bounded channel inbound, `tokio::sync::oneshot`
for responses. Never call `pii::Scanner` from an async context.

## Error Handling

- Use the unified `Error` enum from `error.rs` for all fallible operations.
- Scanner failures and limit violations (body too large, unsupported content type) follow
  the `on_error` policy (`fail_open` or `fail_close`) — never silently swallow these.
  Always increment `pii_proxy_errors_total` with the outcome.
- Proxy and I/O errors should propagate with context, not be converted to generic 500s
  where a more specific response is appropriate.

## Configuration

- Validation runs at startup; the proxy refuses to start on invalid config.
- Per-route overrides (scan settings, actions) **fully replace** defaults — no merging.
- When adding new config fields, add corresponding validation rules and unit tests
  for both valid and invalid cases.

## Testing

- Unit tests go in the same file as the code they test (`#[cfg(test)] mod tests`).
- Integration tests (in `crates/proxy/tests/`) start from Phase 4 (Admin server) onward.
  They spin up actual servers and make real HTTP requests.
- use #[test_case()] wherever applicable to reduce amount of testing code and save tokens
- Load tests live in `crates/proxy/benches/` — see `docs/load-testing.md` for scenario design.

## Action Precedence

When multiple actions are configured: block → redact → header.
Block short-circuits (no forwarding). There is no `warn` action — Prometheus
metrics (detections, blocked, redacted) are always incremented unconditionally
when PII is detected. Actions are configured separately for requests and
responses in reverse proxy and forward proxy modes.

## Spec-Driven Development (OpenSpec)

The project tracks work with OpenSpec. `openspec/specs/` states what the system does
today. `openspec/changes/` holds the work in flight.

**A spec describes built behaviour only.** Never write a spec for something unbuilt.
Unbuilt work goes to `docs/backlog.md` until a change starts it.

### When to use OpenSpec

Use it when one of these is true:
- The change alters observable behaviour: an endpoint, a config field, an action, a
  metric name, an error code, or a detector output.
- The change touches more than one crate.
- The change is a pivot phase, that is Phase 21 to Phase 30.
- The change builds something `docs/backlog.md` lists, such as the forward proxy, TLS,
  or the checksum toggle.
- The change needs a decision recorded, because a later change depends on it.
- You cannot review the change in one diff.

Do not use it when:
- The change fixes a bug and restores already-specified behaviour.
- The change adds a country or a language through the `add-pii` skill. The skill is the
  spec.
- The change optimizes performance and the match set stays the same.
- The change touches documentation, research notes, the landing page, or eval datasets.
- The work takes about an hour and one diff shows all of it.

The test: **would somebody disagree about what "done" means?** Yes — write a proposal
first. No — write the code.

### The workflow

1. Run `/opsx:propose <description>`. It creates `openspec/changes/<name>/` with
   `proposal.md`, `design.md`, `tasks.md`, and the spec deltas.
2. Run `openspec validate <name> --strict` → verify: it exits zero.
3. Run `/opsx:apply`. Mark each task done in the change's `tasks.md`, never elsewhere.
4. Verify with `cargo test --workspace` and `cargo clippy --workspace --all-targets`.
5. Review the diff against the change's spec deltas with the `code-review` skill.
6. Run `openspec archive <name>`. It merges the deltas into `openspec/specs/`.

Rules:
- A tracked change lives in `openspec/changes/<name>/`. Do not add tasks anywhere else.
- Do not edit `openspec/specs/` by hand. `openspec archive` writes it, and
  `/opsx:sync` writes it early when a change lands in parts. The one exception was the
  initial migration, which seeded the twelve capabilities from `DESIGN.md` and the code.
  That is done. Every later change goes through a delta.
- Do not tick a box in `docs/history/tasks-phases-1-20.md`. It is history.

## Implementation verification

Verify every implementation against the change's spec deltas, then against
`ARCHITECTURE.md`.

## Commiting

Do NOT commit finished task.
