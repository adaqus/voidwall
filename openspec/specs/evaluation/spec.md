## Purpose

The evaluation harness measures how well the proxy detects PII, scored against the
public AI4Privacy dataset. It reports precision, recall, and F1 per entity type and
overall, so the numbers compare with what other PII tools publish.

## Requirements

### Requirement: The harness is a separate tool, not part of the proxy

The harness SHALL be a binary named `ai4privacy-eval`, declared explicitly, and gated
behind the non-default `eval` cargo feature. A default build and the deployed image
SHALL carry none of its dependencies. It SHALL NOT act as a regression gate.

#### Scenario: Default build

- **WHEN** the proxy is built with default features
- **THEN** the eval binary and its HTTP client dependency are absent

### Requirement: The harness drives the running proxy over HTTP

The harness SHALL call `POST /v1/redact` on a running HTTP API. It SHALL NOT call
`/v1/scan`, because that response is a deduplicated kind set carrying no offsets.

#### Scenario: The harness scores a row

- **WHEN** the harness scores a dataset row
- **THEN** it posts the row text to `/v1/redact` and reads the redacted body

### Requirement: Spans are recovered by diffing the redacted body

With the `type_label` strategy the redacted body SHALL be the original text with each
detected span replaced by a bracketed kind token, and every other byte identical.
Aligning the original against the redacted text SHALL recover each predicted span as a
start offset, an end offset, and a kind.

#### Scenario: One span is redacted

- **WHEN** the proxy replaces one detected span with its kind token
- **THEN** the alignment recovers that span's offsets and kind

### Requirement: Scoring is span-level overlap

A predicted span that overlaps a ground-truth span SHALL count as a true positive. A
predicted span overlapping none SHALL count as a false positive. A ground-truth span
with no overlapping prediction SHALL count as a false negative. Precision SHALL be the
matched predictions over the total predictions. Recall SHALL be the hit ground truths
over the total ground truths. F1 SHALL be their harmonic mean.

#### Scenario: Prediction overlaps ground truth

- **WHEN** a predicted span overlaps an annotated span
- **THEN** the harness counts a true positive

#### Scenario: Prediction overlaps nothing

- **WHEN** a predicted span overlaps no annotated span
- **THEN** the harness counts a false positive

### Requirement: Two metric variants are reported

The harness SHALL report detection precision, recall, and F1, which ignore the kind. It
SHALL also report typed precision, recall, and F1, where the predicted kind must belong
to the family expected for the ground-truth category. It SHALL report both per entity
type and as a micro and macro overall.

#### Scenario: Right span, wrong family

- **WHEN** a prediction covers the right span but names a kind outside the expected
  family
- **THEN** it counts for detection but not for the typed metric

### Requirement: Precision is reported as a band

The harness SHALL report a raw precision and an adjusted precision. The band accounts
for real detections that the dataset does not annotate, on formats a validator backs.

#### Scenario: A validator-backed catch is unannotated

- **WHEN** the proxy detects a checksum-valid value the dataset does not annotate
- **THEN** the report shows both the raw and the adjusted precision

### Requirement: A per-kind false-positive breakdown is emitted

The harness SHALL emit a breakdown of false positives by predicted kind, as a
diagnostic.

#### Scenario: The run finishes

- **WHEN** the harness finishes a run
- **THEN** the report names which predicted kinds produced the false positives

### Requirement: The runner is docker/ctl eval

The `docker/ctl eval` subcommand SHALL invoke the harness against the running HTTP API,
on port 8083 by default. It SHALL accept `DATASET`, `API_URL`, `MAX_ROWS`, `LANG`,
`CONCURRENCY`, and `ENFORCE` as environment variables. `CONCURRENCY` SHALL default to
32. `ENFORCE` SHALL default to report-only.

#### Scenario: Operator sets a language

- **WHEN** `LANG` names one language
- **THEN** the harness scores that language's rows only

#### Scenario: ENFORCE is not set

- **WHEN** `ENFORCE` is unset
- **THEN** the run reports the numbers and exits zero, whatever the floors say

### Requirement: The dataset is fetched on demand and cached

The dataset SHALL NOT be vendored. When `DATASET` is unset, `docker/ctl eval` SHALL
fetch the needed JSONL train files over plain HTTPS into `.cache/ai4privacy/`, with no
authentication token and no Python dependency. It SHALL fetch the `LANG` file alone
when `LANG` is set, and all six train languages otherwise. A `DATASET` override SHALL
be honoured as given.

#### Scenario: No dataset is cached

- **WHEN** the operator runs the eval with no `DATASET` and an empty cache
- **THEN** the runner fetches the files it needs into the cache and proceeds

#### Scenario: A local dataset is named

- **WHEN** `DATASET` names a local JSONL file or directory
- **THEN** the harness uses it and fetches nothing

### Requirement: Rows are streamed, not buffered

The harness SHALL read the JSONL line by line and SHALL never buffer the whole file. It
SHALL parse leniently, ignoring unknown fields. It SHALL apply the `LANG` and
`MAX_ROWS` filters while it streams. It SHALL drive the API with bounded concurrency.

#### Scenario: A large dataset file is scored

- **WHEN** the harness scores a multi-hundred-megabyte file
- **THEN** it streams the rows and holds no full copy in memory
