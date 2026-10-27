## 1. Workspace version

- [x] 1.1 Add `version = "0.1.0"` to `[workspace.package]` and set `version.workspace =
  true` in the four crate manifests (D1). Verify: `cargo metadata --format-version 1
  --no-deps` lists `0.1.0` for all four packages, and `cargo check --workspace` passes.

## 2. CLI

- [x] 2.1 Add `#[command(version)]` to `Cli` (D1). Verify: a unit test with
  `Cli::try_parse_from(["voidwall", "--version"])` returns a `DisplayVersion` error whose
  text is `voidwall 0.1.0`.
- [x] 2.2 Add `print_config` with `requires = "config"`, drop `.multiple(false)` from the
  group, and add `Mode` and `fn mode` (D2, D3). Verify: `#[test_case]` unit tests in
  `config.rs` cover `--config` alone, `--validate` alone, `--validate` with a config from
  the env (gives `Validate`), `--config` and `--validate` on the command line (conflict),
  `--print-config` with `--config`, `--print-config` with the env, and `--print-config`
  with neither (usage error).
- [x] 2.3 Dispatch on `Mode` in `main.rs`: print the file bytes for `PrintConfig` before
  any load, and keep `run_validate` and the run path (D2, D3). Verify: `cargo clippy
  --workspace --all-targets -- -D warnings` passes.
- [x] 2.4 Add integration tests that run the binary: `--version` prints `voidwall 0.1.0`
  and exits 0 with no config; `--print-config` writes a commented file byte for byte and
  exits 0; it writes a file that is not TOML byte for byte and exits 0; it exits non-zero
  naming the path for a missing file; it exits 2 with no path; `--validate` on a valid
  file with `VOIDWALL_CONFIG` naming a missing file exits 0; `--config` with `--validate`
  exits 2. Verify: `cargo test -p voidwall` passes.

## 3. Image contents

- [x] 3.1 Write `docker/voidwall-image.toml`: the guard sections of `docker/voidwall.toml`,
  `http_api` on, `reverse_proxy.enabled = false`, the admin listener, and the LM Studio
  and Ollama blocks between their marker lines (D4). Verify: the file has both marker
  pairs, and every line between them starts with `#`.
- [x] 3.2 Add the test of D4 in `crates/voidwall/tests/`: `builtin_guards` and `guards`
  are equal in both files, `http_api.enabled` is true, and `reverse_proxy.enabled` is
  false. Verify: `cargo test -p voidwall` passes, and changing one threshold in either
  file makes it fail.
- [x] 3.3 Update `Dockerfile.voidwall` and `.dockerignore` (D5): models first, then the
  config, the binary, the notices, `ENV VOIDWALL_CONFIG`, and the three OCI labels.
  Verify: after `docker/ctl compile` and `docker/fetch-models.sh`, `docker build` passes;
  `sha256sum` of each model file in the image equals the hash in `fetch-models.sh`; and
  `docker inspect` shows the labels.
- [x] 3.4 Check that the dev stack still works with the new image. Verify: `docker/ctl
  start` brings up the stack, and `/readyz` on `:9090` answers 200.

## 4. Smoke test

- [x] 4.1 Write `docker/smoke-test.sh IMAGE VERSION` (D8). Verify: it passes on the image
  of 3.3 with `0.1.0`, and fails with `0.0.0`.
- [x] 4.2 Check that the script catches a broken route block. Verify: with a typo in one
  key of the Ollama block of a scratch copy of the config built into an image, the script
  fails on that block's `--validate`.

## 5. Release script and changelog

- [x] 5.1 Write `cliff.toml` (D9). Verify: `git cliff --bumped-version` prints `0.1.0` or
  `v0.1.0` on the repository with no tag, and `git cliff --bump` prints a `0.1.0` section
  with only conventional commits, grouped by type.
- [x] 5.2 Add `docker/ctl release` and its usage line (D9). Verify, in a scratch clone with
  a local bare repository as `origin`: an uncommitted change, a branch other than `main`,
  `main` behind `origin/main`, and an existing `v0.1.0` tag each exit non-zero and leave
  `git status`, `git log`, and `git tag` unchanged.
- [x] 5.3 Run `docker/ctl release` to the end in the same scratch clone. Verify: answering
  `n` pushes nothing and leaves one `chore(release): 0.1.0` commit and tag `v0.1.0`
  locally; answering `y` in a fresh clone puts both on the bare `origin`.

## 6. Release workflow

- [x] 6.1 Add `workflow_call` to `ci.yml` and limit its `push` trigger to branches (D7).
  Verify: `actionlint` passes, and a branch push still runs CI.
- [x] 6.2 Write `.github/workflows/release.yml` with the `check`, `image`, and `publish`
  jobs (D7). Pin each action to a commit SHA with the ref in a comment, as `ci.yml` does.
  Verify: `actionlint` passes.
- [x] 6.3 Run the workflow by hand on a branch. Verify: `check` and `image` pass, the log
  of `image` warns that `CHANGELOG.md` has no section for `0.1.0` (before the first
  release there is no `CHANGELOG.md`; 8.3 checks the notes), `publish` is skipped, and no
  package version appears under `ghcr.io/adaqus/voidwall`.
- [x] 6.4 Run it by hand a second time. Verify: the log of `image` shows a cache hit for
  `models/` and `.ort`.
- [x] 6.5 Remove the temporary `release-dry-run` push trigger from `release.yml` after
  6.3 and 6.4, before the change is merged. Verify: `grep -rn release-dry-run
  .github/workflows/` finds no match, and `actionlint` passes.

## 7. Docs

- [x] 7.1 Update the README section and the comments in `docker-compose.yml`,
  `docker/voidwall.toml`, and `fetch-models.sh` (D10). Add `git-cliff` to the tools in
  `DEVELOPMENT.md`, and a short release section that names `docker/ctl release`. Verify:
  `grep -rn "ships no model" docker/ README.md` finds no match, and each README command
  runs as written against the image of 3.3.

## 8. Checks and first release

- [x] 8.1 Run the workspace checks. Verify: `cargo test --workspace`, `cargo clippy
  --workspace --all-targets -- -D warnings`, and `cargo deny check licenses` pass.
- [x] 8.2 Review the diff against the spec deltas with the `code-review` skill. Verify:
  no finding is left open.
- [x] 8.3 After the change is merged, run `docker/ctl release` on `main`. Verify:
  `ghcr.io/adaqus/voidwall:0.1.0`, `:0.1`, and `:latest` name one digest; `gh attestation
  verify oci://ghcr.io/adaqus/voidwall:0.1.0 --owner adaqus` passes; and the GitHub
  Release `v0.1.0` carries the `0.1.0` section of `CHANGELOG.md`.
