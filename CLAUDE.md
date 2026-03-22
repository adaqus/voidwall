# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project

PII Proxy — a multi-mode HTTP proxy that inspects HTTP traffic for PII using the `pii` crate.
Design: `DESIGN.md`. Tasks: `TASKS.md`. Load testing: `docs/load-testing.md`.

## Build

```bash
cargo check 2>&1 | tail -n 20m
cargo test 2>&1 | tail -n 20m
cargo test <name> 2>&1 | tail -n 20m        # single test
cargo clippy 2>&1 | tail -n 20m             # lint — treat warnings as errors
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
- Integration tests (in `tests/`) start from Phase 4 (Admin server) onward.
  They spin up actual servers and make real HTTP requests.
- use #[test_case()] wherever applicable to reduce amount of testing code and save tokens
- Load tests live in `benches/` — see `docs/load-testing.md` for scenario design.

## Action Precedence

When multiple actions are configured: block → redact → header.
Block short-circuits (no forwarding). There is no `warn` action — Prometheus
metrics (detections, blocked, redacted) are always incremented unconditionally
when PII is detected. Actions are configured separately for requests and
responses in reverse proxy and forward proxy modes.

## Implementation verification

After implementing a task from TASKS.md, always verify the implementation with DESIGN.md file.

## Commiting

Do not ask for commiting finished task.

## Task Tracking

After completing each task from `TASKS.md`, mark its checkbox as done (`- [x]`).
