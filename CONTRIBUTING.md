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
[Requirements](DEVELOPMENT.md#requirements), then run from the
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

## Commit Messages

Commit messages follow [Conventional Commits 1.0.0](https://www.conventionalcommits.org/en/v1.0.0/).
CI checks each commit of a push or a pull request, except merge commits, with
[`committed`](https://github.com/crate-ci/committed) and `committed.toml`. Commits made
before the format was adopted are not checked.

```text
<type>(<scope>)!: <description>
```

- Type: `feat`, `fix`, `perf`, `refactor`, `test`, `docs`, `build`, `ci`, `chore`,
  `style`, or `revert`.
- Scope: optional and free-form. Name the area the commit changes, for example `pii`,
  `proxy`, or `grafana`.
- Description: use the imperative mood (`add`, not `added`) and start with a lower-case
  letter. Do not end it with a full stop. The subject line is at most 100 characters.
- `!`: marks a break that an operator sees: a configuration field, an endpoint, a metric,
  a status code, or a response body. A change to the Rust API of a workspace crate does
  not need `!`.

```text
feat(proxy): support SSE for OpenAI-compatible APIs
fix(pii): stop validators panicking on input no pattern produces
feat(config)!: rename on_error to error_policy
docs: update TODO
```

To check a message before you commit it, enable the hook in
[DEVELOPMENT.md](DEVELOPMENT.md#commit-message-hook).
