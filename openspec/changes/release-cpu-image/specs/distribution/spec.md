## ADDED Requirements

### Requirement: The image ships the default models and their licenses

The image SHALL ship, under `/opt/voidwall/models/`, the model files that
`docker/fetch-models.sh` pins, each with the SHA-256 hash that script pins:

- `wolf-small/model.onnx`, `wolf-small/tokenizer.json`, and `wolf-small/LICENSE`
- `bards-v2/onnx/model_quantized.onnx`, `bards-v2/tokenizer.json`,
  `bards-v2/config.json`, and `bards-v2/LICENSE`

#### Scenario: The model files are in the image

- **WHEN** the image is built
- **THEN** each file above exists under `/opt/voidwall/models/` and has the hash that
  `docker/fetch-models.sh` pins for it, and `bards-v2/LICENSE` is the file that script
  writes

### Requirement: The image starts with a default configuration

The image SHALL ship a config file at `/etc/voidwall/voidwall.toml` and SHALL set
`VOIDWALL_CONFIG` to that path, so the image starts with no argument and no mounted
file. The file SHALL enable the REST API and SHALL NOT enable the reverse proxy. It
SHALL declare the guards of `docker/voidwall.toml` with the same settings: the regex
`pii` guard, the `prompt_injection` guard on wolf-small, and the `pii_ml` guard on
bards-v2, with their model paths under `/opt/voidwall/models/`.

The file SHALL hold two commented blocks of reverse proxy routes. The LM Studio block
SHALL name the upstream `http://host.docker.internal:1234`, and the Ollama block SHALL
name the upstream `http://host.docker.internal:11434`. Each block SHALL hold a
`/v1/chat/completions` route with `format = "openai-chat"` and a `/` route with the
generic format, both to its upstream.

#### Scenario: The image starts with no argument

- **WHEN** the image runs with no argument and no mounted file
- **THEN** `/readyz` answers 200 once the guards have loaded
- **AND** a `/v1/scan` request whose text is a known prompt injection answers with a
  `PROMPT_INJECTION` finding
- **AND** nothing listens on the reverse proxy port

#### Scenario: The operator turns on the LM Studio block

- **WHEN** the default config has `reverse_proxy.enabled = true` and the LM Studio block
  uncommented
- **THEN** `voidwall --validate` on the file passes

#### Scenario: The operator turns on the Ollama block

- **WHEN** the default config has `reverse_proxy.enabled = true` and the Ollama block
  uncommented
- **THEN** `voidwall --validate` on the file passes

#### Scenario: The operator copies the default config out

- **WHEN** the operator runs the image with `--print-config`
- **THEN** stdout is byte for byte `/etc/voidwall/voidwall.toml`

### Requirement: The image names its version

The image SHALL carry the OCI labels `org.opencontainers.image.version`, set to the
version, `org.opencontainers.image.revision`, set to the commit the image was built
from, and `org.opencontainers.image.source`, set to the repository URL.

#### Scenario: A released image is inspected

- **WHEN** the operator inspects the image of release `X.Y.Z`
- **THEN** its version label is `X.Y.Z` and its revision label is the commit that tag
  `vX.Y.Z` points to

### Requirement: A release is cut locally from main

`docker/ctl release` SHALL refuse, and change nothing, when the working tree has
uncommitted changes, the current branch is not `main`, local `main` is behind or has
diverged from `origin/main`, or the tag of the next version already exists locally or on
`origin`.

Otherwise it SHALL compute the next version from the conventional commits since the last
version tag, or take `0.1.0` when there is no version tag. It SHALL write that version to
`[workspace.package] version` and `Cargo.lock`, write `CHANGELOG.md`, commit, and tag
`v<version>`. It SHALL push the commit and the tag only after the operator confirms.

`CHANGELOG.md` SHALL hold one section per version, with its conventional commits grouped
by type. It SHALL leave out the commits that are not conventional.

#### Scenario: The tree is not clean

- **WHEN** the operator runs `docker/ctl release` with an uncommitted change
- **THEN** the script exits non-zero, and no file, commit, or tag is changed

#### Scenario: Local main is behind origin

- **WHEN** `origin/main` has a commit that local `main` does not have
- **THEN** the script exits non-zero, and no file, commit, or tag is changed

#### Scenario: The first release

- **WHEN** the operator runs `docker/ctl release` on a repository with no version tag
- **THEN** the version is `0.1.0`, and the tag is `v0.1.0`

#### Scenario: The operator declines the push

- **WHEN** the script asks for confirmation and the operator declines
- **THEN** nothing is pushed

### Requirement: A version tag publishes the image

When a tag `vX.Y.Z` is pushed, the release workflow SHALL run the license gate, Clippy,
and the workspace tests, build the image for `linux/amd64` only, and run a smoke test on
it: `/readyz` answers 200, `voidwall --version` prints `X.Y.Z`, and a `/v1/scan` request
with a known prompt injection answers with a `PROMPT_INJECTION` finding. A failure of any
of these steps SHALL publish nothing.

When every step passes, the workflow SHALL push the image to `ghcr.io/adaqus/voidwall`
with the tags `X.Y.Z`, `X.Y`, and `latest`, attest the build provenance of the pushed
digest, and create a GitHub Release named `vX.Y.Z` whose notes are the `X.Y.Z` section of
`CHANGELOG.md`.

#### Scenario: A release tag is pushed

- **WHEN** tag `vX.Y.Z` is pushed and every step passes
- **THEN** `ghcr.io/adaqus/voidwall:X.Y.Z`, `:X.Y`, and `:latest` name one digest for
  `linux/amd64`
- **AND** a provenance attestation for that digest verifies for the repository
- **AND** the GitHub Release `vX.Y.Z` carries the `X.Y.Z` section of `CHANGELOG.md`

#### Scenario: The smoke test fails

- **WHEN** the image built from the tag does not pass the smoke test
- **THEN** no image is pushed, no attestation is made, and no GitHub Release is created

### Requirement: A manual dry run publishes nothing

The release workflow SHALL also run on a manual trigger. A manual run SHALL run the
checks, the build, and the smoke test, and SHALL NOT push an image, make an attestation,
or create a GitHub Release.

#### Scenario: A dry run on main

- **WHEN** the operator starts the workflow by hand on `main`
- **THEN** the image is built and smoke-tested, and nothing is published
