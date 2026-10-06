## MODIFIED Requirements

### Requirement: Model guard settings are validated at startup

Validation SHALL reject a `[guards.<name>]` section that cannot describe a runnable guard,
and SHALL name the guard and the cause. The following SHALL each fail the start:

- an empty `labels` list
- a `labels` entry listed more than once
- a `text_classifier` guard whose `labels` does not hold exactly one entry
- a `max_tokens` below 10
- a `thresholds` key absent from that guard's `labels`
- a threshold outside the score range the adapter declares
- a `surface` that disables every target
- a guard name outside the permitted character set or over the length cap
- a guard name the build reserves for a built-in guard
- `threads = 0`
- an `overlap_tokens` above `max_tokens / 2`
- `adapter = "text_multilabel_classifier"`, because its run side is not built

An `adapter` the build does not ship SHALL fail the start through the schema rather than
through a semantic rule. The set of adapter names is fixed by the build, so the schema can
state it, and the diagnostic SHALL name the rejected value and the names the build ships.

A `labels` entry SHALL NOT be checked against a vocabulary of finding kinds. The build has
no closed set of kinds to check a label against, so a label is whatever the operator
writes.

Validation SHALL report a missing `model_path` or `tokenizer_path` file with the path that
was expected, so an operator can see which artifact the deployment lacks.

Validation SHALL NOT read, parse, or execute a model artifact. The tensor contract is
checked when the guard loads its model at startup.

#### Scenario: The adapter is unknown

- **WHEN** a guard sets `adapter` to a value the build does not ship
- **THEN** the proxy refuses to start, naming the rejected value and the adapter names the
  build ships

#### Scenario: The multilabel adapter is named

- **WHEN** a guard sets `adapter = "text_multilabel_classifier"`
- **THEN** validation fails naming the guard and the adapter as not built, also under
  `--validate`

#### Scenario: The labels list is empty

- **WHEN** a guard sets `labels = []`
- **THEN** the proxy refuses to start, naming the guard

#### Scenario: A label is listed twice

- **WHEN** a guard lists one label at two output positions
- **THEN** the proxy refuses to start, naming the guard and the repeated label

#### Scenario: A text classifier lists two labels

- **WHEN** a `text_classifier` guard lists two labels
- **THEN** the proxy refuses to start, naming the guard and the one-label rule

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

#### Scenario: Zero threads

- **WHEN** a guard sets `threads = 0`
- **THEN** the proxy refuses to start, naming the guard and `threads`

#### Scenario: Overlap above the bound

- **WHEN** a guard sets `max_tokens = 16` and `overlap_tokens = 9`
- **THEN** the proxy refuses to start, naming the guard, the overlap 9, and the bound 8

#### Scenario: Overlap at the bound

- **WHEN** a guard sets `max_tokens = 16` and `overlap_tokens = 8`
- **THEN** validation passes

#### Scenario: Validation does not open the model

- **WHEN** a guard names an artifact file that exists but holds no valid model
- **THEN** validation passes, because validation does not read the artifact

### Requirement: Validation binds nothing and starts nothing

In validate mode the proxy SHALL NOT bind a listener, SHALL NOT spawn a scanner thread,
SHALL NOT open TLS material, SHALL NOT build an upstream client, and SHALL NOT load a
model. It SHALL build a scanner once, to exercise regex and Vectorscan compilation, and
then discard it.

#### Scenario: Validate mode runs

- **WHEN** the proxy runs in validate mode
- **THEN** no socket is bound and no scanner thread is spawned
- **AND** a scanner is built and discarded, so a bad pattern is caught

#### Scenario: Validate mode with a model guard

- **WHEN** the proxy runs in validate mode on a config with a model guard whose model file
  exists but does not parse as ONNX
- **THEN** validation passes, and no model is loaded

## ADDED Requirements

### Requirement: A model guard that fails to load stops the start

At startup, every configured model guard SHALL load its model before any data-plane
listener binds. When one load fails, the proxy SHALL log the error with the guard's name
and SHALL exit non-zero. It SHALL NOT start without that guard.

#### Scenario: The model file is not ONNX

- **WHEN** a model guard's `model_path` names a file that does not parse as an ONNX model
- **THEN** the proxy logs an error naming the guard and the model path, and exits non-zero
- **AND** no data-plane listener binds

#### Scenario: The overlap leaves no room in the window

- **WHEN** a model guard's tokenizer adds so many special tokens that the window is not
  longer than the overlap
- **THEN** the proxy logs an error naming the guard, the window, and the overlap, and
  exits non-zero

## REMOVED Requirements

### Requirement: Model guard settings parse but no model guard runs

**Reason**: The model runtime is built. A configured model guard now loads and runs, and
the "configured but not executed" warning is gone.

**Migration**: None for the config file. A `[guards.<name>]` section now loads its model
at startup. Remove the section to keep the old behaviour.
