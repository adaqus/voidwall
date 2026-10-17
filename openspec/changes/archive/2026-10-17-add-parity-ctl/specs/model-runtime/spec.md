## ADDED Requirements

### Requirement: The parity runner is docker/ctl parity

`docker/ctl parity` SHALL run the parity check for the wolf-small model from start to end,
with no manual step: it SHALL get the model files, make the Python reference, and run the
ignored Rust parity test against that reference. It SHALL exit with status zero only when
the parity test passes. It SHALL run on the host, not in a container. It SHALL check no
model other than wolf-small.

#### Scenario: The check passes

- **WHEN** `docker/ctl parity` runs on a host that meets its requirements, and the worker
  matches the reference
- **THEN** the command prints the parity test result and exits with status zero

#### Scenario: The check fails

- **WHEN** `docker/ctl parity` runs and the parity test fails
- **THEN** the command exits with a non-zero status

### Requirement: The parity runner uses pinned model files

The runner SHALL use the wolf-small files at revision
`bcab2eff97bcabd7227849639e2d0d7a61b46c92` only. It SHALL get `model.onnx` and
`tokenizer.json` through `docker/fetch-models.sh`. It SHALL get `config.json` and
`model.safetensors` at the same revision into `.cache/parity/`, and SHALL verify each file
against a pinned SHA-256 before it uses the file. A file whose SHA-256 is not the pinned
value SHALL stop the run with a non-zero exit status, before the reference is made.

#### Scenario: A downloaded file does not match its pin

- **WHEN** a fetched `config.json` or `model.safetensors` has a SHA-256 that is not its
  pinned value
- **THEN** the run stops with a non-zero exit status, names the file, and makes no
  reference

### Requirement: The parity reference is made again on every run

Every run of `docker/ctl parity` SHALL make a new `reference.json` with
`crates/voidwall-ml/parity/reference.py` before the parity test runs. The parity test
SHALL NOT use a reference from an earlier run.

#### Scenario: A pinned Python package changes

- **WHEN** a version in `crates/voidwall-ml/parity/requirements.txt` changes and
  `docker/ctl parity` runs
- **THEN** the reference that the parity test uses was made with the new version

### Requirement: The parity runner has default window settings

The runner SHALL make the reference with a window of 2048 tokens and an overlap of 64
tokens, the values of the wolf-small guard in `docker/voidwall.toml`.
`PARITY_MAX_TOKENS` SHALL override the window length and `PARITY_OVERLAP` SHALL override
the overlap.

#### Scenario: Default run

- **WHEN** `docker/ctl parity` runs with `PARITY_MAX_TOKENS` and `PARITY_OVERLAP` unset
- **THEN** the reference records a window of 2048 tokens and an overlap of 64 tokens

#### Scenario: Overridden window

- **WHEN** `PARITY_MAX_TOKENS=512 PARITY_OVERLAP=128 docker/ctl parity` runs
- **THEN** the reference records a window of 512 tokens and an overlap of 128 tokens

### Requirement: The parity runner needs python3 3.11 or later

The runner SHALL stop with a non-zero exit status and a message that names the requirement
when the host has no `python3`, or has a `python3` older than 3.11. It SHALL install the
Python packages of `crates/voidwall-ml/parity/requirements.txt` into a virtual environment
under `.cache/parity/`, never into the host Python.

#### Scenario: No python3 on the host

- **WHEN** `docker/ctl parity` runs on a host with no `python3`
- **THEN** the command stops with a non-zero exit status and states that it needs
  `python3` 3.11 or later

#### Scenario: python3 is too old

- **WHEN** `docker/ctl parity` runs on a host whose `python3` is 3.10
- **THEN** the command stops with a non-zero exit status and names the version it found
