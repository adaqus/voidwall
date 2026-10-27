## Context

`docker/Dockerfile.voidwall` copies a binary built on the host (`docker/ctl compile`) into
`debian:trixie-slim`, with the notices. `.dockerignore` admits only the binary, the
notices, `licenses/`, `docker/`, `LICENSE`, and `NOTICE`. The dev stack mounts its config
and `models/wolf-small`, `models/bards-v2` into the container at `/etc/voidwall/` and
`/opt/voidwall/models/`.

`Cli` has an `ArgGroup` that requires exactly one of `--config` (also read from
`VOIDWALL_CONFIG`) and `--validate`. clap counts an env value as a given argument, so
with `VOIDWALL_CONFIG` set, `--validate` fails with a conflict and an empty value fails
with "a value is required". `docker run` cannot unset an `ENV` of the image.

`--validate` checks that each model file exists, so the image config validates only
where `/opt/voidwall/models/` holds the models: inside the image.

CI (`ci.yml`) runs on every push, tags included, and has a `check` job and a `commits`
job. See proposal.md for why.

## Goals / Non-Goals

**Goals:**

- One Dockerfile for the dev stack and the release.
- Every check of the release runs before anything is published.
- The release steps can be tried by hand without a publish.

**Non-Goals:**

- GPU images and images without models.
- Rejecting `reverse_proxy.enabled = true` with no route. It stays valid, as today.
- Docker Hub, and any platform other than `linux/amd64`.
- Env overrides of config values, such as the upstream.

## Decisions

### D1: One workspace version

`[workspace.package]` gets `version = "0.1.0"`, and each of the four crates takes
`version.workspace = true`. `voidwall-eval` follows too, so no crate carries a version of
its own. `--version` reads `CARGO_PKG_VERSION` through clap's `#[command(version)]`, so
it prints `voidwall 0.1.0`.

### D2: `--print-config` is a flag that needs `--config`

`print_config: bool` with `#[arg(long, requires = "config")]`. clap counts
`VOIDWALL_CONFIG` toward `requires`, so `docker run image --print-config` works, and a
missing path is a clap usage error, exit 2. `main.rs` reads the file with `fs::read` and
writes the bytes with `write_all` on stdout, before any config load, tracing setup, or
runtime start. A read error prints `cannot read config file <path>: <error>` on stderr
and exits 1, as `run_validate` reports its failures.

Alternative: print the parsed config. Rejected by the operator: it drops the comments,
and the commented route blocks are the point.

### D3: `--validate` wins over `VOIDWALL_CONFIG`

The group's `.multiple(false)` goes, so clap no longer rejects the pair. `main.rs`
parses with `Cli::command().get_matches()`, reads `value_source("config")`, and, when
`validate` is set and the config came from `ValueSource::CommandLine`, exits through
`Cli::command().error(ErrorKind::ArgumentConflict, ...)`, so the message and exit 2 match
clap's own. A config from `ValueSource::EnvVariable` beside `--validate` is ignored. The
group stays `required(true)`, so a run with neither still exits 2.

A small `fn mode(&Cli, Option<ValueSource>) -> Result<Mode, ...>` holds the rule, so a
unit test covers each case without a process. `Mode` is an enum (`Run(PathBuf)`,
`Validate(PathBuf)`, `PrintConfig(PathBuf)`), so `main` cannot act on two at once.

Alternative: remove `VOIDWALL_CONFIG` from the environment before parsing when
`--validate` is in the arguments. Rejected: `std::env::remove_var` is `unsafe` in edition
2024, and scanning raw arguments duplicates clap.

### D4: The image config is its own file, checked against the dev config

`docker/voidwall-image.toml` is the default config. Its guard sections are copies of
those in `docker/voidwall.toml`. A test in `crates/voidwall/tests/` parses both files as
`toml::Value` and asserts that `builtin_guards` and `guards` are equal, so the two cannot
drift. The test also asserts that the image file enables `http_api` and does not enable
`reverse_proxy`.

The two route blocks sit between marker lines, `# >>> lmstudio` / `# <<< lmstudio` and
`# >>> ollama` / `# <<< ollama`, with every line inside commented by `# `. The smoke test
uncomments one block by those markers, sets `enabled = true`, and validates the result
inside the image (D7).

Alternative: one file for both uses. Rejected: the dev config sends traffic to
`echo-server:8090` and has the reverse proxy on.

### D5: One Dockerfile, models first

`Dockerfile.voidwall` copies `models/wolf-small/` and `models/bards-v2/` to
`/opt/voidwall/models/` first, then the config to `/etc/voidwall/voidwall.toml`, then the
binary and the notices, and sets `ENV VOIDWALL_CONFIG=/etc/voidwall/voidwall.toml`. The
model layer comes first, so a dev rebuild with the same models reuses it. `.dockerignore`
admits the two model directories by name, so any other model a developer keeps in
`models/` stays out. The OCI labels come from `--build-arg VERSION` and `REVISION`, with
`source` fixed in the file.

The dev compose file keeps its mounts. They shadow the copies in the image, and its
`command: --config ...` beats the `ENV`.

Alternative: a separate release Dockerfile. Rejected: two files that must ship the same
binary and notices would drift.

### D6: The binary is built on the runner

The release job runs `docker/ctl compile` on `ubuntu-24.04` (glibc 2.39), and the image
base is `debian:trixie-slim` (glibc 2.41), the same split as the dev stack.

Alternative: a multi-stage Dockerfile that builds inside a Rust image. It is more
reproducible, but the build then needs `gh` and a token for the ONNX Runtime attestation,
and its own Cargo cache. Rejected for now.

### D7: The release workflow

`.github/workflows/release.yml` runs on `push: tags: ['v*.*.*']` and on
`workflow_dispatch`. `ci.yml` gains `on: workflow_call`, and its `push` trigger is limited
to `branches: ['**']`, so a tag push runs CI once, through the release workflow.

```
 version ──────────▶ check (uses ci.yml) ──▶ image ─────────────────────────────▶ publish (tag only)
   read workspace      license, clippy,       cache .ort, models/ (by hash)        ghcr login (GITHUB_TOKEN)
   version             test, commits          fetch-ort, fetch-models, compile     push X.Y.Z, X.Y, latest
   tag == version                             docker build --label ...             attest-build-provenance
   (tag only)                                 docker/smoke-test.sh IMAGE VERSION   gh release create
                                              extract CHANGELOG section (printed)    --notes-file <section>
```

- The tag check compares `vX.Y.Z` with `[workspace.package] version` in the `version`
  job, which runs before `check`, so a wrong tag fails first. A manual run skips it.
- The model cache key is `hashFiles('docker/fetch-models.sh')`, which holds the pinned
  hashes. `fetch-models.sh` still verifies every restored file, as `fetch-ort.sh` does.
  The `.ort` cache key is `hashFiles('docker/fetch-ort.sh')`, in `ci.yml` and
  `release.yml` both, so a new ONNX Runtime pin is a new key in both.
- `publish` is a separate job with `if: github.ref_type == 'tag'` and the write
  permissions (`packages`, `id-token`, `attestations`, `contents`). `check` and `image`
  keep read-only permissions. The image passes between jobs as a `docker save` artifact,
  so `publish` pushes exactly the image that was tested.
- The release notes are the `## [X.Y.Z]` section of `CHANGELOG.md`, cut with `awk`. The
  `image` job cuts and prints it on every run, so a dry run shows the notes too.

### D8: The smoke test is a script

`docker/smoke-test.sh IMAGE VERSION` runs the image with no argument, waits for `/readyz`
200 with a deadline, posts a known prompt injection to `/v1/scan` and expects a
`PROMPT_INJECTION` finding, checks that the reverse proxy port is closed, runs
`--version` and compares it with `VERSION`, and runs `--print-config` and compares it
with `docker/voidwall-image.toml`. Then, for each route block, it uncomments the block,
sets `enabled = true`, mounts the result, and runs `--validate` in the image. It stops
the container on exit. A developer can run it on a local build.

### D9: `docker/ctl release`

The subcommand needs `git-cliff` on the host and checks for it first. In order:

1. Refuse when `git status --porcelain` is not empty, or the branch is not `main`.
2. `git fetch origin`; refuse when `origin/main` is not an ancestor of `main`.
3. `git cliff --bumped-version` gives the version. With no tag it gives the
   `initial_tag` of `cliff.toml`, `0.1.0`.
4. Refuse when `v<version>` exists locally or in `git ls-remote --tags origin`.
5. Write the version to `[workspace.package]`, run `cargo update --workspace` for
   `Cargo.lock`, and run `git cliff --bump -o CHANGELOG.md`.
6. Commit as `chore(release): <version>`, and make an annotated tag `v<version>`.
7. Ask `Push main and v<version> to origin? [y/N]`. On yes, push the commit, then the
   tag. On anything else, push nothing, and print the push command and the commands that
   undo the commit and the tag.

`cliff.toml` sets `conventional_commits = true`, `filter_unconventional = true`, one group
per commit type, and skips `chore(release)` commits. A `!` commit is marked as breaking.

### D10: Operator docs

The README "No prebuilt image" section becomes: pull, run with
`--add-host=host.docker.internal:host-gateway`, copy the config out with `--print-config`,
uncomment a block and set `enabled = true`, mount it back, and validate it with
`--validate`. It notes that LM Studio needs "Serve on Local Network" and Ollama needs
`OLLAMA_HOST=0.0.0.0` so the container can reach them. The comments in
`docker-compose.yml`, `docker/voidwall.toml`, and `fetch-models.sh` that say the image
ships no model change to say the dev stack mounts its own copies.

## Risks / Trade-offs

- [The image is about 1 GB, mostly the fp32 wolf-small export] → Accepted. A smaller
  model would change detection.
- [bards-v2 has no LICENSE file upstream; the image redistributes it on the strength of
  the model card] → The shipped `LICENSE` names the source, the revision, and that the
  model card declares Apache-2.0, as `fetch-models.sh` writes it today.
- [A newer runner glibc than trixie's would build a binary that does not start] → The
  runner is pinned to `ubuntu-24.04`, and the smoke test runs the binary in the image.
- [The guard sections are copied between two files] → The D4 test fails on any
  difference.
- [Hugging Face is down at release time] → The model cache, keyed by the pinned hashes.
- [A failure after the push, such as in `gh release create`, leaves a pushed image with
  no release] → The steps run in the order push, attest, release, and each can be rerun
  by hand. Accepted for one maintainer.
- [CI no longer runs on its own for a tag push] → The release workflow calls it, and a
  release cannot publish without it.

## Migration Plan

None for operators: there is no earlier release. A release is undone by deleting the
GHCR version, the GitHub Release, and the tag.
