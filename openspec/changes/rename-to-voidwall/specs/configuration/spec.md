## MODIFIED Requirements

### Requirement: Config is a TOML file named on the command line

The proxy SHALL read one TOML file. `--config <PATH>` SHALL name it. The environment
variable `VOIDWALL_CONFIG` SHALL provide the same value. The proxy SHALL exit with
status 2 when neither is present.

#### Scenario: No config path is given

- **WHEN** the proxy starts with neither `--config` nor `VOIDWALL_CONFIG`
- **THEN** it prints an error naming both options and exits with status 2

