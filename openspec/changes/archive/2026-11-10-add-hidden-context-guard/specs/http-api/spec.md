## MODIFIED Requirements

### Requirement: POST /v1/scan reports the detection

`/v1/scan` SHALL return JSON holding `detected`, `matches_count`, `kinds`, and `guards`. It
SHALL NOT echo the body. `matches_count` SHALL be the size of the resolved match set, plus
one for each finding a model guard or the `hidden_context` guard reported. `kinds` SHALL
hold kind names only, never a matched value. `kinds` SHALL be sorted and SHALL hold each
kind once, so two scans of the same body return the same array.

`guards` SHALL be an array holding one object for each guard that reported at least one
finding, sorted by guard name. A guard that reported no finding SHALL NOT appear, so a
scan with no findings returns an empty array. Each object SHALL hold `name`,
`matches_count`, and `kinds`:

- `name` SHALL be the name configuration gave the guard.
- `matches_count` SHALL be the number of findings that guard reported. The `matches_count`
  values of all objects SHALL add up to the top-level `matches_count`.
- `kinds` SHALL hold the kind names that guard reported, sorted, each kind once, never a
  matched value.

#### Scenario: Body carries PII

- **WHEN** a client posts a body holding an email address and a national number
- **THEN** the response reports `detected` true, the resolved match count, and both kind
  names

#### Scenario: Body is clean

- **WHEN** a client posts a body with no PII
- **THEN** the response reports `detected` false, an empty `kinds` array, and an empty
  `guards` array

#### Scenario: The same body is posted twice

- **WHEN** a client posts the same body holding two kinds twice
- **THEN** both responses carry the same `kinds` array in the same sorted order

#### Scenario: A model guard reports a finding

- **WHEN** a model guard with `labels = ["PROMPT_INJECTION"]` scores the posted body at or
  above its threshold, and the body holds no PII
- **THEN** the response reports `detected` true, `matches_count` 1, and `kinds`
  `["PROMPT_INJECTION"]`

#### Scenario: Two guards report the same kind for one value

- **WHEN** the `pii` guard, through a custom definition labelled `SECRET`, and a model
  guard named `pii_ml` each report one `SECRET` finding for the same word in the posted
  body
- **THEN** the response reports `matches_count` 2 and `kinds` `["SECRET"]`
- **AND** `guards` is `[{"name":"pii","matches_count":1,"kinds":["SECRET"]},
  {"name":"pii_ml","matches_count":1,"kinds":["SECRET"]}]`

#### Scenario: Only guards with findings are listed

- **WHEN** two guards are configured and only one of them reports a finding for the posted
  body
- **THEN** `guards` holds one object, naming the guard that reported the finding

#### Scenario: The hidden context guard reports a finding

- **WHEN** a client posts to `/v1/scan?direction=response` a body holding one marker twice
  and no PII
- **THEN** the response reports `detected` true, `matches_count` 1, and `kinds`
  `["HIDDEN_CONTEXT"]`
- **AND** `guards` is `[{"name":"hidden_context","matches_count":1,"kinds":["HIDDEN_CONTEXT"]}]`

## ADDED Requirements

### Requirement: POST /v1/scan takes the direction of the posted content

`/v1/scan` SHALL accept a `direction` query parameter with the value `request` or
`response`. The scan SHALL run the guards that inspect that direction. Without the
parameter, the scan SHALL be a request scan. Any other value SHALL answer 400 with a JSON
body holding an `error` field, and SHALL scan nothing. The LiteLLM route SHALL NOT take
the parameter; its `input_type` sets the direction.

#### Scenario: No direction

- **WHEN** a client posts a body holding a marker to `/v1/scan`
- **THEN** the `hidden_context` guard is not run and the response reports `detected`
  false

#### Scenario: Request direction

- **WHEN** a client posts a body holding a marker to `/v1/scan?direction=request`
- **THEN** the `hidden_context` guard is not run and the response reports `detected`
  false

#### Scenario: Response direction

- **WHEN** a client posts a body holding a marker and an email placeholder to
  `/v1/scan?direction=response`
- **THEN** the response reports `kinds` `["EMAIL", "HIDDEN_CONTEXT"]`

#### Scenario: Unknown direction

- **WHEN** a client posts to `/v1/scan?direction=sideways`
- **THEN** the API answers 400 with a JSON body holding `error`, and no guard runs
