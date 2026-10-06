## Purpose

States how the ONNX Runtime that model guards run on is obtained, verified, and linked,
and the minimum CPU the binary needs because of it.

## ADDED Requirements

### Requirement: ONNX Runtime comes only from the verified pinned archive

The build SHALL link ONNX Runtime 1.28.0 statically from pyke's prebuilt archive for
`x86_64-unknown-linux-gnu`. Before Cargo sees the archive, the build SHALL check its
SHA-256 against the pinned value and SHALL verify its build attestation against the
`pykeio` owner. A mismatch in either check SHALL fail the build. Every build, including a
developer's `cargo test`, SHALL link this verified archive, and no build SHALL download
ONNX Runtime by itself.

#### Scenario: The archive matches

- **WHEN** the fetch step downloads the archive and both the hash and the attestation match
- **THEN** the archive is extracted and the workspace builds and links against it

#### Scenario: The archive is tampered with

- **WHEN** the fetch step is given a file whose SHA-256 differs from the pinned value
- **THEN** the step exits non-zero and nothing is extracted

#### Scenario: The archive is missing

- **WHEN** a Cargo build runs before the verified archive is extracted
- **THEN** the build fails instead of downloading ONNX Runtime

#### Scenario: The linked version is the pinned one

- **WHEN** the crate's tests ask the linked ONNX Runtime for its version
- **THEN** the version is `1.28.0`

### Requirement: The binary refuses to start below the minimum CPU

The binary SHALL check at startup, before it loads configuration, that the CPU supports
the x86-64-v3 feature set. On a CPU that lacks any of these features, the binary SHALL
NOT start: it SHALL print an error naming the minimum CPU level and each missing feature,
and SHALL exit non-zero. The check SHALL run whether or not a model guard is configured,
and in both `--config` and `--validate` modes.

#### Scenario: The CPU meets the floor

- **WHEN** the binary starts on a CPU with every x86-64-v3 feature
- **THEN** the check passes and startup continues

#### Scenario: The CPU lacks a feature

- **WHEN** the binary starts on a CPU that lacks one or more x86-64-v3 features
- **THEN** it prints an error naming x86-64-v3 and each missing feature
- **AND** it exits non-zero without loading the configuration
