## MODIFIED Requirements

### Requirement: A custom definition carries four fields

A `[[builtin_guards.pii.custom]]` entry SHALL carry a `label` and a `pattern`, both
required. It MAY carry `keywords` and a `country`. `country` SHALL default to
`International`.

A custom definition SHALL belong to the guard that runs it, so an entry declared outside
a guard section SHALL be rejected by the schema.

#### Scenario: Minimal definition

- **WHEN** an entry names a label and a pattern only
- **THEN** the entry is accepted with no keywords and the `International` country

#### Scenario: An entry sits outside the guard

- **WHEN** the config declares `[[pii.custom]]` at the top level
- **THEN** the schema rejects the file

### Requirement: Custom definitions are independent of detect and ignore

`builtin_guards.pii.detect` and `builtin_guards.pii.ignore` SHALL apply to built-in
kinds only. A custom entry SHALL run regardless of either list. The only way to disable
one SHALL be to remove it from the config, or to disable the guard that owns it.

#### Scenario: detect names a closed set

- **WHEN** `detect` names a closed set of built-in kinds
- **THEN** every configured custom definition still runs

#### Scenario: The owning guard is disabled

- **WHEN** `builtin_guards.pii` sets `enabled = false`
- **THEN** no custom definition declared under it runs
