## MODIFIED Requirements

### Requirement: POST /v1/scan reports the detection

`/v1/scan` SHALL return JSON holding `detected`, `matches_count`, and `kinds`. It SHALL
NOT echo the body. `matches_count` SHALL be the size of the resolved match set, plus one
for each finding a model guard reported. `kinds` SHALL hold kind names only, never a
matched value. `kinds` SHALL be sorted and SHALL hold each kind once, so two scans of the
same body return the same array.

#### Scenario: Body carries PII

- **WHEN** a client posts a body holding an email address and a national number
- **THEN** the response reports `detected` true, the resolved match count, and both kind
  names

#### Scenario: Body is clean

- **WHEN** a client posts a body with no PII
- **THEN** the response reports `detected` false and an empty `kinds` array

#### Scenario: The same body is posted twice

- **WHEN** a client posts the same body holding two kinds twice
- **THEN** both responses carry the same `kinds` array in the same sorted order

#### Scenario: A model guard reports a finding

- **WHEN** a model guard with `labels = ["PROMPT_INJECTION"]` scores the posted body at or
  above its threshold, and the body holds no PII
- **THEN** the response reports `detected` true, `matches_count` 1, and `kinds`
  `["PROMPT_INJECTION"]`

## ADDED Requirements

### Requirement: A window-limit error follows the on_error policy

When a model guard needs more windows for a unit than its window limit, `/v1/scan` SHALL
follow `on_error`. Under `fail_close` it SHALL answer 413 with the body exactly
`{"error":"tokenized content too long to scan"}`, even when another guard reported a
finding. Under `fail_open` it SHALL answer 200 with a report built from the findings of
the guards that succeeded.

#### Scenario: Window limit under fail_close

- **WHEN** a model guard hits its window limit on `/v1/scan` and `on_error` is
  `fail_close`
- **THEN** the API answers 413 with the body
  `{"error":"tokenized content too long to scan"}`

#### Scenario: Window limit under fail_open

- **WHEN** a model guard hits its window limit on `/v1/scan`, another guard reports a
  finding, and `on_error` is `fail_open`
- **THEN** the API answers 200 with a report holding the finding of the guard that
  succeeded

### Requirement: A model guard inference failure is a scanner error

A model guard's inference failure SHALL follow the requirement "A scanner error follows the
on_error policy": 500 with the fixed body under `fail_close`, 200 with the findings of
the guards that succeeded under `fail_open`.

#### Scenario: Inference fails under fail_close

- **WHEN** a model guard's inference fails on `/v1/scan` and `on_error` is `fail_close`
- **THEN** the API answers 500 with the body `{"error":"internal error"}`
