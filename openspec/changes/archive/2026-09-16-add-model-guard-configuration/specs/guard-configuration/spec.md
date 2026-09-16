## ADDED Requirements

### Requirement: A model-backed guard is declared in its own named section

A guard an operator configures SHALL be declared under `[guards.<name>]`, where `<name>`
is operator-supplied. The section SHALL carry everything one guard needs to run one model:
`adapter`, `model_path`, `tokenizer_path`, `max_tokens`, `labels`, and `thresholds`.

There SHALL be no separate model section and no model reference. One guard SHALL own one
model, so two guards SHALL NOT be able to name one configured model.

`max_tokens` SHALL be the longest input the adapter feeds the model, and SHALL be at
least 10. A window smaller than that holds the adapter's special tokens and little else,
so it describes a guard configured to judge nothing. What happens to an input *past*
`max_tokens` is not settled here.

`adapter` SHALL name a code path the build ships. It SHALL own the runtime, the
preprocessing behaviour, the tensor contract, the output interpretation, and whether the
guard's findings carry spans. Configuration SHALL NOT name a runtime and SHALL NOT
override an adapter's contract.

#### Scenario: A model guard is declared

- **WHEN** the config holds a `[guards.injection]` table naming an adapter, a model path,
  a tokenizer path, `max_tokens`, `labels`, and thresholds
- **THEN** the file loads and the guard is known by the name `injection`

#### Scenario: The token window is too small to judge anything

- **WHEN** a guard sets `max_tokens` below 10
- **THEN** validation fails naming the guard and the minimum

#### Scenario: Two guards name the same artifacts

- **WHEN** two `[guards.<name>]` sections carry the same `model_path`
- **THEN** the file loads, because each guard owns its own model and loading the artifacts
  twice is the operator's choice

#### Scenario: A model guard names a runtime

- **WHEN** a `[guards.<name>]` section sets `runtime`
- **THEN** the schema rejects the file

### Requirement: Labels map output positions to finding kinds

`labels` SHALL be an ordered list whose position SHALL correspond to the model's output
position. It SHALL declare every finding kind the guard can report.

`labels` SHALL NOT be shortened to disable a kind, because its order is the tensor
contract.

A label SHALL NOT be checked against a vocabulary of finding kinds. The build has no closed
set of kinds, so a label is whatever the operator writes.

`labels` SHALL NOT be empty, because a guard that declares no label can report nothing.
Its entries SHALL be distinct, because one output position names one kind and two
positions naming one kind is a contract the tensor cannot mean.

#### Scenario: A multi-capability guard declares two kinds

- **WHEN** a guard sets `labels = ["PROMPT_INJECTION", "HATE_SPEECH"]`
- **THEN** the guard is declared able to report both kinds, in that output order

#### Scenario: A label names a kind the build has never heard of

- **WHEN** a guard lists a label matching no kind any shipped detector reports
- **THEN** the file loads, because the build has no closed set to check it against

#### Scenario: The labels list is empty

- **WHEN** a guard sets `labels = []`
- **THEN** validation fails naming the guard

#### Scenario: A label is listed twice

- **WHEN** a guard sets `labels = ["PROMPT_INJECTION", "PROMPT_INJECTION"]`
- **THEN** validation fails naming the guard and the repeated label

### Requirement: A threshold is required for every kind that reports

`thresholds` SHALL map a finding kind to the minimum score a detection must reach before
it becomes a finding. A threshold SHALL have no default, because the build has no
evaluated number for an arbitrary model.

A kind listed in `labels` and absent from `thresholds` SHALL produce no finding. That
absence SHALL be the only way configuration disables a kind the model emits.

A `thresholds` key absent from `labels` SHALL fail validation, so a misspelled kind is an
error rather than a silently disabled one.

#### Scenario: A label carries a threshold

- **WHEN** a guard lists `PROMPT_INJECTION` in `labels` and sets its threshold to 0.90
- **THEN** a detection scoring at or above 0.90 becomes a finding of that kind

#### Scenario: A label carries no threshold

- **WHEN** a guard lists `HATE_SPEECH` in `labels` and sets no threshold for it
- **THEN** that guard reports no `HATE_SPEECH` finding

#### Scenario: A threshold names an undeclared kind

- **WHEN** a guard sets a threshold for a kind absent from `labels`
- **THEN** validation fails naming the kind

### Requirement: A model guard's surface defaults to the body alone

A `[guards.<name>]` section's `surface` SHALL default `body` to true and SHALL default
`url_path`, `query_params`, and `headers` to false. Each unit a model guard admits SHALL
cost one model execution, so a default that admits the path and the query would turn one
message into three.

This default SHALL be separate from the built-in guard default. A partially written model
guard surface SHALL take the model guard defaults for the keys it omits.

#### Scenario: A model guard omits its surface

- **WHEN** a `[guards.<name>]` section declares no `surface`
- **THEN** that guard sees the body and no other unit

#### Scenario: A model guard names one extra target

- **WHEN** a model guard sets `surface.url_path = true` and sets no other surface key
- **THEN** that guard sees the body and the URL path, and does not see the query string or
  any header value

### Requirement: Model guard settings parse but the guard does not run

The config schema SHALL accept and validate `[guards.<name>]` sections. No model guard
SHALL be built, because the model runtime is not built. The proxy SHALL log one warning at
startup naming every configured model guard and SHALL continue with the guards it has.

A route SHALL be allowed to select a configured model guard by name. That guard SHALL
report no finding, so the route's traffic SHALL be inspected only by the guards that do
run.

#### Scenario: A model guard is configured

- **WHEN** the config declares a valid `[guards.<name>]` section
- **THEN** the proxy logs a warning naming that guard as configured but not executed
- **AND** the proxy starts every enabled mode

#### Scenario: Model guard schema rules still apply

- **WHEN** a `[guards.<name>]` section carries a key the schema does not define
- **THEN** validation fails, even though the guard does not run

#### Scenario: A route selects a model guard

- **WHEN** a route sets `guards = ["pii", "injection"]` and `injection` is a configured
  model guard
- **THEN** the file loads and the PII guard inspects that route's traffic

## MODIFIED Requirements

### Requirement: A guard declares its scan surface

Each guard SHALL carry a `surface` table holding `url_path`, `query_params`, `body`, and
`headers`. The surface SHALL be the configuration form of the guard's declared interest:
the engine SHALL pass a guard only the units its surface admits.

The surface SHALL be per guard, not global. A unit kind no enabled guard admits SHALL
NOT be built. A built-in guard's surface SHALL default `url_path`, `query_params`, `body`,
and `headers` to true.

`headers` SHALL be a boolean and SHALL NOT be a list of header names. Which header values a
message is decoded into is a property of the traffic rather than of a detector, so the set
SHALL be declared per route — see "A route names the headers it exposes to detection". The
guard's boolean SHALL decide only whether that guard sees the header units the route built.

A surface that disables every target SHALL fail validation, because it describes a guard
that can never be called.

#### Scenario: Default surface

- **WHEN** a built-in guard section omits `surface`
- **THEN** the guard inspects the URL path, the query string, the body, and every header
  value the route named

#### Scenario: A target is disabled for one guard

- **WHEN** a guard sets `surface.body = false`
- **THEN** that guard is not called with the body unit

#### Scenario: One guard declines header units and another admits them

- **WHEN** a route names a header, one selected guard sets `surface.headers = false`, and
  another selected guard admits them
- **THEN** that header value is decoded into a unit, the admitting guard is called with
  it, and the declining guard is not

#### Scenario: Every selected guard declines header units

- **WHEN** a route names a header and every guard it selected sets
  `surface.headers = false`
- **THEN** that header value is never decoded into a unit, because a unit kind no
  selected guard admits is not built

#### Scenario: The surface names a header

- **WHEN** a guard sets `surface.headers` to a list of header names
- **THEN** the schema rejects the file

#### Scenario: Every target is disabled

- **WHEN** a guard disables `url_path`, `query_params`, `body`, and `headers`
- **THEN** validation fails naming the guard

### Requirement: A guard name is operator-supplied and bounded by configuration

A guard SHALL carry a name that configuration supplies rather than a fixed string the
build defines. The set of guard names SHALL be fixed when configuration is loaded, so
it SHALL NOT grow with traffic.

A guard name SHALL NOT be derived from a request, a response, or any detected value.

A guard name SHALL be ASCII, SHALL hold only the characters `a-z`, `A-Z`, `0-9`, `_`, and
`-`, SHALL NOT be empty, and SHALL NOT exceed 64 characters. The name reaches finding
records and may reach a metric label, so its shape SHALL be bounded as well as its set.

#### Scenario: A finding names its guard

- **WHEN** a guard reports a finding
- **THEN** the finding names the guard by its configured name

#### Scenario: A guard name never comes from traffic

- **WHEN** the proxy scans a message
- **THEN** no guard name is taken from the message, its headers, or a matched value

#### Scenario: A guard name holds a character outside the set

- **WHEN** the config declares a guard named `injection.v2`
- **THEN** validation fails naming the guard

#### Scenario: A guard name is too long

- **WHEN** the config declares a guard whose name exceeds 64 characters
- **THEN** validation fails naming the limit
