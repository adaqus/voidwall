# Contributing to Voidwall

Voidwall is in early development. The configuration format, the REST API, the metrics,
and the Rust APIs of the workspace crates can change in any commit, without a
deprecation period.

## Before You Start

- Report a security problem in private. See [SECURITY.md](SECURITY.md).
- Open an issue before you start large work, so that we can agree on the approach first.
- The terms for outside contributions (a CLA or a DCO sign-off) are not decided yet.

## Development Setup

Only Linux on x86-64 is supported, with a CPU of x86-64-v3 or later. Install the tools in
[Development Requirements](README.md#development-requirements), then run from the
workspace root:

```bash
docker/fetch-ort.sh
cargo test --workspace
cargo clippy --workspace --all-targets
cargo deny check licenses
```

A pull request must pass all of them. Clippy warnings count as errors.

## Pull Requests

- Keep a pull request to one concern.
- Add tests for the behavior you change. Unit tests go in the same file, under
  `#[cfg(test)] mod tests`.
- `ARCHITECTURE.md` explains the design. `AGENTS.md` lists the project rules, for people
  and for coding agents.
- A change to observable behavior (an endpoint, a configuration field, a metric, an error
  code, or a detector's output) needs an OpenSpec proposal under `openspec/changes/`.
  `AGENTS.md` describes when one is needed and the workflow.
- Never put real personal data or a live credential in a test, a log, or an issue. Use a
  placeholder or a published test value.
- A pull request never adds model files to the image. An operator mounts a model that is
  not a default one as a volume.
