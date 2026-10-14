## ADDED Requirements

### Requirement: The piimb span exporter is a separate tool outside the image

The piimb span exporter SHALL be a binary named `piimb-spans` in the workspace crate
`voidwall-eval`. The Docker image SHALL NOT carry it.

#### Scenario: The image is built

- **WHEN** the Docker image is built
- **THEN** it holds no `piimb-spans` binary, no piimb data, and no piimb code

### Requirement: piimb predictions come from the English regex engine

For each benchmark sentence, `piimb-spans` SHALL call the `voidwall-pii` scanner
in-process, built as the `en` row of the scanner table: language en and countries
International, US, GB, AU, NZ, CA, IE, and ZA. It SHALL pass the matches through
`voidwall_pii::resolve_overlaps` and SHALL output the resolved spans only, as start and
end offsets in characters of the sentence text. Its output SHALL NOT hold text from the
sentence.

#### Scenario: Multi-byte characters precede a detected value

- **WHEN** a sentence holds multi-byte characters before a value the scanner detects
- **THEN** the span starts at the character offset of that value, not its byte offset

#### Scenario: Two matches overlap

- **WHEN** the scanner returns two overlapping matches for one sentence
- **THEN** the output holds only the spans `resolve_overlaps` keeps

### Requirement: piimb's own metric code scores the spans

The run SHALL score the spans with the benchmark's own masking metric code, unmodified,
taken from the same benchmark revision as the test data. For each task it SHALL report
the character-level precision, recall, F1, and F2 that the code computes on the
`sentences` subset.

#### Scenario: Perfect predictions

- **WHEN** the spans equal the ground-truth entities of every sentence of a task
- **THEN** that task's precision, recall, F1, and F2 are all 1.0

### Requirement: The run scores the four English tasks

By default, the run SHALL score the tasks `ai4privacy-en`, `gretel`, `nemotron-pii`, and
`privy`. The report SHALL then give, for F2, F1, precision, and recall, the simple mean of
the four task values. `PIIMB_TASK` SHALL limit the run to the one task it names; the report
SHALL then give no average and SHALL state that the run is not a full benchmark result. An
unknown `PIIMB_TASK` SHALL stop the run with a non-zero exit status and name the accepted
values.

#### Scenario: Default run

- **WHEN** `docker/ctl piimb-eval` runs with `PIIMB_TASK` unset
- **THEN** the report gives one row for each of the four tasks and one row of averages

#### Scenario: One task

- **WHEN** `PIIMB_TASK=privy docker/ctl piimb-eval` runs
- **THEN** the report gives the `privy` row only, no averages, and a line that says the run
  is not a full benchmark result

#### Scenario: Unknown task

- **WHEN** `PIIMB_TASK=mapa-eur-lex docker/ctl piimb-eval` runs
- **THEN** the run stops with a non-zero exit status and names the four accepted tasks

### Requirement: The benchmark revision is pinned

The run SHALL use benchmark revision `5f47fff823b3fd7138cfed39e25ca24af8549e25` for the
test data and the metric code. `PIIMB_REVISION` SHALL override it. The report SHALL state
the revision it used.

#### Scenario: Pinned revision

- **WHEN** `PIIMB_REVISION` is unset
- **THEN** the run uses revision `5f47fff823b3fd7138cfed39e25ca24af8549e25` and the report
  names it

#### Scenario: Overridden revision

- **WHEN** `PIIMB_REVISION` names another revision
- **THEN** the run uses the test data and the metric code of that revision

### Requirement: piimb data and code are fetched on demand and cached

`docker/ctl piimb-eval` SHALL fetch the test data and the metric code of the revision over
HTTPS into `.cache/`, with no token, and SHALL NOT fetch a file the cache already holds for
that revision. It SHALL install the Python packages the metric code needs into a virtual
environment under `.cache/`, never into the host Python. Nothing it fetches or installs
SHALL be committed. When `python3` is missing, the run SHALL stop with a non-zero exit
status and say that it needs `python3`.

#### Scenario: Second run

- **WHEN** `docker/ctl piimb-eval` runs again at the same revision
- **THEN** it fetches nothing and installs nothing

#### Scenario: No python3

- **WHEN** the host has no `python3`
- **THEN** the run stops with a non-zero exit status and a message that names `python3`

### Requirement: The piimb report holds no text and ends with a legend

The report SHALL hold task names, counts, and scores only, never text from the benchmark.
It SHALL end with a legend that explains F2, F1, precision, recall, the character-level
counting, and the average. The exit status SHALL NOT depend on the scores.

#### Scenario: A run finishes

- **WHEN** the run finishes
- **THEN** the report holds no sentence text and ends with the legend, and the exit status
  is 0
