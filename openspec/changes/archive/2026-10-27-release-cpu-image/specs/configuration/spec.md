## ADDED Requirements

### Requirement: --version prints the version

The proxy SHALL accept `--version`. It SHALL print `voidwall <version>`, where
`<version>` is the workspace version, and exit 0. It SHALL need no config file and SHALL
bind nothing.

#### Scenario: The operator asks for the version

- **WHEN** the operator runs `voidwall --version` with neither `--config` nor
  `VOIDWALL_CONFIG`
- **THEN** the proxy prints `voidwall <version>` with the version of
  `[workspace.package]` and exits 0

### Requirement: --print-config prints the config file unchanged

The proxy SHALL accept `--print-config`. It SHALL write the bytes of the file that
`--config` or `VOIDWALL_CONFIG` names to stdout, unchanged, and exit 0. It SHALL NOT
parse or validate the file, SHALL NOT bind a listener, and SHALL NOT load a model. When
the file cannot be read, it SHALL print an error that names the path and exit non-zero.
When neither `--config` nor `VOIDWALL_CONFIG` is present, it SHALL exit with status 2.

#### Scenario: The file is printed with its comments

- **WHEN** the operator runs `voidwall --print-config` with `VOIDWALL_CONFIG` naming a
  file that holds comments
- **THEN** stdout is byte for byte the file, comments included, and the exit code is 0

#### Scenario: A file that is not valid is still printed

- **WHEN** the operator runs `voidwall --config <PATH> --print-config` and the file does
  not parse as TOML
- **THEN** stdout is byte for byte the file and the exit code is 0

#### Scenario: The file cannot be read

- **WHEN** the operator runs `voidwall --config <PATH> --print-config` and no file exists
  at the path
- **THEN** the proxy prints an error that names the path and exits non-zero

#### Scenario: No config path is given

- **WHEN** the operator runs `voidwall --print-config` with neither `--config` nor
  `VOIDWALL_CONFIG`
- **THEN** the proxy exits with status 2

## MODIFIED Requirements

### Requirement: Pre-flight validation runs offline

The proxy SHALL accept `--validate <PATH>`. It SHALL run the full pipeline and exit
without starting. `--validate` and `--config` SHALL be mutually exclusive on the command
line. A config path that comes only from `VOIDWALL_CONFIG` SHALL NOT conflict with
`--validate`: the proxy SHALL validate the `--validate` path and ignore the variable.
Exit code 0 SHALL mean valid, and a non-zero code SHALL mean invalid.

#### Scenario: Valid config file

- **WHEN** the operator runs `--validate` on a valid file
- **THEN** the proxy prints a success line and exits 0

#### Scenario: Invalid config file

- **WHEN** the operator runs `--validate` on an invalid file
- **THEN** the proxy prints a categorised diagnostic and exits non-zero

#### Scenario: VOIDWALL_CONFIG is set

- **WHEN** `VOIDWALL_CONFIG` names one file and the operator runs `--validate` on another
  file
- **THEN** the proxy validates the `--validate` file and exits by its result

#### Scenario: Both flags are given

- **WHEN** the operator runs `--config <PATH> --validate <PATH>`
- **THEN** the proxy prints an error that the two cannot be used together and exits with
  status 2
