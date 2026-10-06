## RENAMED Requirements

- FROM: `### Requirement: Labels map output positions to finding kinds`
- TO: `### Requirement: Labels name the finding kinds a guard reports`

## MODIFIED Requirements

### Requirement: A model-backed guard is declared in its own named section

A guard an operator configures SHALL be declared under `[guards.<name>]`, where `<name>`
is operator-supplied. The section SHALL carry everything one guard needs to run one model:
`adapter`, `model_path`, `tokenizer_path`, `max_tokens`, `labels`, and `thresholds`. It
MAY carry `threads` and `overlap_tokens`.

There SHALL be no separate model section and no model reference. One guard SHALL own one
model, so two guards SHALL NOT be able to name one configured model.

`max_tokens` SHALL be the longest input the adapter feeds the model, and SHALL be at
least 10. A window smaller than that holds the adapter's special tokens and little else,
so it describes a guard configured to judge nothing. An input past `max_tokens` SHALL be
split into overlapping windows, as the `model-runtime` capability states.

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

### Requirement: Labels name the finding kinds a guard reports

`labels` SHALL declare every finding kind the guard can report.

For `text_classifier`, `labels` SHALL hold exactly one entry. That entry SHALL name class
1 of the model's two outputs, the class whose `softmax` score the adapter reports. It
SHALL NOT name output position 0.

A label SHALL NOT be checked against a vocabulary of finding kinds. The build has no closed
set of kinds, so a label is whatever the operator writes.

`labels` SHALL NOT be empty, because a guard that declares no label can report nothing.
Its entries SHALL be distinct.

#### Scenario: A text classifier declares its kind

- **WHEN** a `text_classifier` guard sets `labels = ["PROMPT_INJECTION"]`
- **THEN** the file loads, and a finding of that guard is of kind `PROMPT_INJECTION`,
  scored from class 1

#### Scenario: A multi-capability guard declares two kinds

- **WHEN** a `text_classifier` guard sets `labels = ["PROMPT_INJECTION", "HATE_SPEECH"]`
- **THEN** validation fails naming the guard and stating that `text_classifier` takes
  exactly one label, because no built adapter reports two kinds

#### Scenario: A label names a kind the build has never heard of

- **WHEN** a guard lists a label matching no kind any shipped detector reports
- **THEN** the file loads, because the build has no closed set to check it against

#### Scenario: The labels list is empty

- **WHEN** a guard sets `labels = []`
- **THEN** validation fails naming the guard

#### Scenario: A label is listed twice

- **WHEN** a guard sets `labels = ["PROMPT_INJECTION", "PROMPT_INJECTION"]`
- **THEN** validation fails naming the guard and the repeated label

## ADDED Requirements

### Requirement: A configured model guard runs

Each valid `[guards.<name>]` section SHALL build one model guard at startup. The guard
SHALL load its model before the proxy serves traffic, and SHALL inspect every unit its
surface admits on every route that selects it.

#### Scenario: A route selects a model guard

- **WHEN** a route sets `guards = ["pii", "injection"]`, `injection` is a configured model
  guard, and a request body scores at or above its threshold
- **THEN** the proxy answers 403 naming the guard's kind

#### Scenario: A route omits the guard list

- **WHEN** a route declares no `guards` key and a model guard is configured
- **THEN** that model guard inspects the route's traffic

### Requirement: A model guard reports one finding per unit and kind

A model guard SHALL score each unit it is given. When a unit's score is at or above the
threshold of the guard's label, the guard SHALL report exactly one finding of that kind
for that unit. The finding SHALL carry no span and SHALL carry the unit score as its
confidence. A unit scoring below the threshold SHALL give no finding.

#### Scenario: A unit scores above the threshold

- **WHEN** a guard's threshold is 0.90 and a unit scores 0.97
- **THEN** the guard reports one finding of its kind for that unit, with no span

#### Scenario: A unit scores exactly the threshold

- **WHEN** a guard's threshold is 0.90 and a unit scores 0.90
- **THEN** the guard reports one finding

#### Scenario: Two units score above the threshold

- **WHEN** a guard sets `surface.url_path = true`, and the body and the URL path of one
  request each score above the threshold
- **THEN** the guard reports two findings, one per unit

#### Scenario: A unit scores below the threshold

- **WHEN** a guard's threshold is 0.90 and a unit scores 0.40
- **THEN** the guard reports no finding for that unit

### Requirement: A model guard scores the text of a unit

A model guard SHALL score one text per unit. For a plain-text unit, the text SHALL be the
unit's bytes decoded as UTF-8, with every invalid byte sequence replaced by U+FFFD. For a
unit parsed into fragments (a JSON body), the text SHALL be the fragments' values in
document order, joined with a newline; keys SHALL NOT be part of it.

#### Scenario: A plain-text unit holds an invalid byte

- **WHEN** a request body holds an attack prompt and one byte that is not valid UTF-8
- **THEN** the guard scores the decoded text and reports the attack

#### Scenario: A JSON body

- **WHEN** a JSON request body holds an attack prompt as one string value among others
- **THEN** the guard scores the values joined with newlines and reports one finding for
  the body

### Requirement: A model guard runs on its own worker threads

A model guard SHALL run its model on dedicated OS threads, never on the async runtime.
Each thread SHALL own one loaded worker. `threads` SHALL set the number of threads.

When `threads` is absent, the count SHALL be the available parallelism divided by the
number of configured model guards, rounded down, and at least 1. The PII scanner threads
SHALL NOT reduce it.

When the sum of every model guard's thread count is above the available parallelism, the
proxy SHALL log one warning at startup naming the sum and the CPU count, and SHALL
continue.

#### Scenario: Threads are set

- **WHEN** a model guard sets `threads = 3`
- **THEN** that guard loads 3 workers on 3 threads

#### Scenario: Threads are absent with two model guards

- **WHEN** the available parallelism is 8, two model guards are configured, and neither
  sets `threads`
- **THEN** each guard runs 4 threads

#### Scenario: More model guards than CPUs

- **WHEN** the available parallelism is 2, three model guards are configured, and none
  sets `threads`
- **THEN** each guard runs 1 thread, and the proxy logs a warning that the total of 3 is
  above 2 CPUs

#### Scenario: The total is above the CPU count

- **WHEN** the available parallelism is 4 and one model guard sets `threads = 6`
- **THEN** the proxy logs one warning naming 6 and 4, and starts

### Requirement: A model guard sets the overlap between windows

`overlap_tokens` SHALL set how many tokens neighbouring windows of one unit share. When it
is absent, the overlap SHALL be `min(128, max_tokens / 2)`. When it is set, it SHALL be at
most `max_tokens / 2`.

#### Scenario: Overlap is absent

- **WHEN** a model guard with `max_tokens = 512` omits `overlap_tokens`
- **THEN** its windows overlap by 128 tokens

#### Scenario: Overlap is set

- **WHEN** a model guard with `max_tokens = 512` sets `overlap_tokens = 64`
- **THEN** its windows overlap by 64 tokens

## REMOVED Requirements

### Requirement: Model guard settings parse but the guard does not run

**Reason**: The model runtime is built. A configured model guard now loads and runs.

**Migration**: None for the config file. A deployment that declared a `[guards.<name>]`
section now loads its model at startup and blocks on its findings. Remove the section, or
take the guard out of a route's `guards` list, to keep the old behaviour.
