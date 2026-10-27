## Why

Voidwall has no release. The crates say `0.1.0`, the repository has no tag, and no image
is published, so an operator must clone the repository and build the dev stack. The
image that `docker/Dockerfile.voidwall` builds also holds only the binary and the
notices: it ships no model and no configuration, so it does not start on its own, which
`CLAUDE.md` and the README say the released image does.

## What Changes

- One version for the workspace: `[workspace.package] version`, which every crate takes.
  The first release keeps `0.1.0`.
- `voidwall --version` prints the version.
- `voidwall --print-config` writes the bytes of the config file that `--config` or
  `VOIDWALL_CONFIG` names to stdout, unchanged and without validation, and exits.
- An explicit `--validate <PATH>` wins over a config path that comes only from
  `VOIDWALL_CONFIG`, so it works inside the image. `--config` and `--validate` on the
  command line together still conflict.
- The image ships the default models, wolf-small and bards-v2, with their `LICENSE`
  files, at the paths the dev stack mounts them on today.
- The image ships a default configuration and starts with it: `VOIDWALL_CONFIG` points
  at it. The REST API is on, with the guards and settings of `docker/voidwall.toml`. The
  reverse proxy is off. The file
  holds two commented blocks, one for an LM Studio server and one for an Ollama server,
  each with a `/v1/chat/completions` route with `format = "openai-chat"` and a generic
  `/` route.
- `docker/ctl release` makes a release locally: git-cliff computes the next version from
  the conventional commits, the script writes it to `[workspace.package] version`,
  writes `CHANGELOG.md`, commits, and tags `v<version>`. It asks for confirmation before
  it pushes. It refuses, and changes nothing, when the tree is not clean, the branch is
  not `main`, local `main` is behind or has diverged from `origin/main`, or the tag
  already exists.
- `CHANGELOG.md` holds conventional commits only. The other commits are left out.
- A tag push runs a GitHub Actions release workflow: the checks of CI, the image build,
  a smoke test, a push to `ghcr.io/adaqus/voidwall` with the tags `X.Y.Z`, `X.Y`, and
  `latest`, a build provenance attestation, and a GitHub Release whose notes are the
  version's section of `CHANGELOG.md`.
- The workflow can also run by hand as a dry run: it builds and smoke-tests the image and
  publishes nothing.
- The workflow caches the model files, keyed by their pinned hashes.
- The image is built for `linux/amd64` only.
- A README section tells the operator how to pull and run the image, copy the default
  config out with `--print-config`, and mount an edited copy.
- The dev stack keeps mounting `models/` from the host.

## Capabilities

### New Capabilities

None.

### Modified Capabilities

- `distribution`: the image ships the default models, their licenses, and a default
  configuration it starts with; a release is cut from a version tag and published to
  GHCR with provenance and release notes.
- `configuration`: `--version` and `--print-config` are added, and "Pre-flight
  validation runs offline" lets `--validate` win over `VOIDWALL_CONFIG`.

## Impact

- `Cargo.toml` and the four crate manifests: the version moves to `[workspace.package]`.
- `crates/voidwall/src/config.rs`, `crates/voidwall/src/main.rs`: the two flags.
- `docker/Dockerfile.voidwall`: the models, the default config, `VOIDWALL_CONFIG`.
- A new default config file for the image.
- `docker/ctl`: a `release` subcommand. New `cliff.toml` and `CHANGELOG.md`.
- `.github/workflows/`: a release workflow.
- README, and the comments in `docker/docker-compose.yml`, `docker/voidwall.toml`, and
  `docker/fetch-models.sh` that say the image ships no model.
- Release tooling: git-cliff on the machine that cuts a release.
- Operators: a published image that starts with no mounted file.
