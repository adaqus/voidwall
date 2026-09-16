## ADDED Requirements

### Requirement: Model guard settings are validated at startup

Validation SHALL reject a `[guards.<name>]` section that cannot describe a runnable guard,
and SHALL name the guard and the cause. The following SHALL each fail the start:

- an empty `labels` list
- a `labels` entry listed more than once
- a `max_tokens` below 10
- a `thresholds` key absent from that guard's `labels`
- a threshold outside the score range the adapter declares
- a `surface` that disables every target
- a guard name outside the permitted character set or over the length cap
- a guard name the build reserves for a built-in guard

An `adapter` the build does not ship SHALL fail the start through the schema rather than
through a semantic rule. The set of adapter names is fixed by the build, so the schema can
state it, and the diagnostic SHALL name the rejected value and the names the build ships.

A `labels` entry SHALL NOT be checked against a vocabulary of finding kinds. The build has
no closed set of kinds to check a label against, so a label is whatever the operator
writes.

Validation SHALL report a missing `model_path` or `tokenizer_path` file with the path that
was expected, so an operator can see which artifact the deployment lacks.

Validation SHALL NOT read, parse, or execute a model artifact. Checking a tensor contract
belongs to the phase that builds the runtime.

#### Scenario: The adapter is unknown

- **WHEN** a guard sets `adapter` to a value the build does not ship
- **THEN** the proxy refuses to start, naming the rejected value and the adapter names the
  build ships

#### Scenario: The labels list is empty

- **WHEN** a guard sets `labels = []`
- **THEN** the proxy refuses to start, naming the guard

#### Scenario: A label is listed twice

- **WHEN** a guard lists one label at two output positions
- **THEN** the proxy refuses to start, naming the guard and the repeated label

#### Scenario: The token window is too small

- **WHEN** a guard sets `max_tokens` below 10
- **THEN** the proxy refuses to start, naming the guard and the minimum

#### Scenario: A threshold names a kind the guard does not declare

- **WHEN** a guard sets a threshold for a kind absent from its `labels`
- **THEN** the proxy refuses to start, naming the guard and the kind

#### Scenario: An artifact file is missing

- **WHEN** a guard's `model_path` names a file that does not exist
- **THEN** the proxy refuses to start, naming the guard and the expected path

#### Scenario: A threshold is out of range

- **WHEN** a guard sets a threshold outside the range its adapter declares
- **THEN** the proxy refuses to start, naming the guard, the kind, and the range

#### Scenario: Validation does not open the model

- **WHEN** a guard names an artifact file that exists but holds no valid model
- **THEN** validation passes, because validation does not read the artifact

### Requirement: Model guard settings parse but no model guard runs

The config schema SHALL accept and validate `[guards.<name>]` sections. The model runtime
is not built, so no model guard SHALL be constructed. The proxy SHALL log one warning at
startup naming every configured model guard and SHALL continue with the modes and guards it
has.

A route that selects a configured model guard SHALL pass validation, because the name is
known. That route's traffic SHALL be inspected only by the guards that run.

#### Scenario: A model guard is configured

- **WHEN** the config declares a valid `[guards.<name>]` section
- **THEN** the proxy logs a warning naming that guard as configured but not executed
- **AND** the proxy starts every enabled mode

#### Scenario: Model guard schema rules still apply

- **WHEN** a `[guards.<name>]` section carries a key the schema does not define
- **THEN** validation fails, even though the guard does not run

## MODIFIED Requirements

### Requirement: A validation failure is categorised

A validation failure SHALL carry one of five categories: `file`, `toml parse`, `schema`,
`semantic`, or `scanner build`. The message SHALL name the category and the cause.

A reserved guard name, an unknown guard in a route's `guards` list, and an unknown
built-in guard name SHALL each carry the `semantic` category.

A guard name outside the permitted character set or over the length cap, an empty or
repeating `labels` list, a `max_tokens` below the floor, a threshold key absent from
`labels`, a threshold outside its adapter's range, and a surface that disables every
target SHALL each carry the `semantic` category. An unknown `adapter` SHALL carry the
`schema` category, because the build fixes the set of adapter names. A missing model or
tokenizer artifact SHALL carry the `file` category and SHALL name the expected path.

#### Scenario: The file is missing

- **WHEN** the named path does not exist
- **THEN** the failure carries the `file` category

#### Scenario: The TOML does not parse

- **WHEN** the file holds a TOML syntax error
- **THEN** the failure carries the `toml parse` category

#### Scenario: A field is missing or of the wrong type

- **WHEN** the TOML parses but does not match the schema
- **THEN** the failure carries the `schema` category

#### Scenario: A rule fails

- **WHEN** the schema matches but a validation rule fails
- **THEN** the failure carries the `semantic` category

#### Scenario: A route names an unknown guard

- **WHEN** a route's `guards` list names a guard that is not enabled
- **THEN** the failure carries the `semantic` category and names the guard

#### Scenario: A custom pattern does not compile

- **WHEN** a `[[builtin_guards.pii.custom]]` pattern fails to compile
- **THEN** the failure carries the `scanner build` category and names the label

#### Scenario: A guard name holds a character outside the set

- **WHEN** the config declares a guard named `injection.v2`
- **THEN** the failure carries the `semantic` category and names the guard

#### Scenario: An adapter is unknown

- **WHEN** a guard sets `adapter` to a value the build does not ship
- **THEN** the failure carries the `schema` category and names the rejected value

#### Scenario: A model artifact is missing

- **WHEN** a guard's `tokenizer_path` names a file that does not exist
- **THEN** the failure carries the `file` category and names the expected path
