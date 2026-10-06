## Purpose

States what the Voidwall image ships besides the binary, namely the license notices of
everything linked into it, and how a dependency license that is not allowed is stopped.

## ADDED Requirements

### Requirement: The image ships the license notices of what the binary links

The image SHALL ship, under `/usr/share/doc/voidwall/`:

- the license and copyright text of every third-party Rust crate linked into the
  `voidwall` binary, in one generated notices file
- ONNX Runtime's `LICENSE` and `ThirdPartyNotices.txt` from tag v1.28.0, unchanged
- the Apache-2.0 license text of `pykeio/ort-artifacts`, whose build patches are compiled
  into the ONNX Runtime archive
- a pointer to Eigen's upstream source, because Eigen inside ONNX Runtime is MPL-2.0

The crate notices file SHALL be generated from `Cargo.lock` at build time, so it cannot
drift from the crates that are linked.

#### Scenario: The notices are in the image

- **WHEN** the image is built
- **THEN** `/usr/share/doc/voidwall/` holds the crate notices file, ONNX Runtime's `LICENSE`
  and `ThirdPartyNotices.txt`, the pyke Apache-2.0 text, and the Eigen source pointer

#### Scenario: A new crate is added

- **WHEN** a dependency is added to the workspace and the image is rebuilt
- **THEN** the generated crate notices file contains that crate's license text

### Requirement: A dependency under a license that is not allowed fails the build

The release build and CI SHALL run a license check over every crate in the dependency
graph. A crate whose license is not on the allowlist SHALL fail the check, and the build
SHALL stop. The allowlist SHALL NOT block MIT or Apache-2.0, so either remains open for
Voidwall's own license.

#### Scenario: Every license is allowed

- **WHEN** the license check runs on the current dependency graph
- **THEN** it passes

#### Scenario: A license is not allowed

- **WHEN** a crate's license is not on the allowlist
- **THEN** the license check fails and names the crate and its license
