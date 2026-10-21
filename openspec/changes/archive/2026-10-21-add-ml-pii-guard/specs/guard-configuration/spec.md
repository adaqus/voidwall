## MODIFIED Requirements

### Requirement: A model-backed guard is declared in its own named section

A guard an operator configures SHALL be declared under `[guards.<name>]`, where `<name>`
is operator-supplied. The section SHALL carry everything one guard needs to run one model:
`adapter`, `model_path`, `tokenizer_path`, `max_tokens`, `labels`, and `thresholds`. It
MAY carry `threads`, `overlap_tokens`, `class`, and, for `token_classifier`, `validate_as`.
A `token_classifier` section SHALL carry `config_path`, the model's `config.json`; a
`text_classifier` section SHALL NOT carry `config_path`.

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

#### Scenario: A token classifier omits its config

- **WHEN** a `token_classifier` guard sets no `config_path`
- **THEN** validation fails naming the guard and `config_path`

#### Scenario: A text classifier names a config

- **WHEN** a `text_classifier` guard sets `config_path`
- **THEN** validation fails naming the guard and `config_path`

### Requirement: Labels name the finding kinds a guard reports

`labels` SHALL declare every finding kind the guard can report.

For `text_classifier`, `labels` SHALL hold exactly one entry. That entry SHALL name class
1 of the model's two outputs, the class whose `softmax` score the adapter reports. It
SHALL NOT name output position 0.

For `token_classifier`, `labels` SHALL hold the entity types of the model that the guard
reports, under the model's own type names. A span of a type absent from `labels` SHALL give
no finding.

A label SHALL NOT be checked against a vocabulary of finding kinds, nor against the types a
model's `config.json` declares. The build has no closed set of kinds, so a label is
whatever the operator writes.

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

#### Scenario: A token classifier declares several kinds

- **WHEN** a `token_classifier` guard sets `labels = ["PERSON_NAME", "PHONE_NUMBER"]`
- **THEN** the file loads, and the guard reports spans of those two types only

#### Scenario: A label names a kind the build has never heard of

- **WHEN** a guard lists a label matching no kind any shipped detector reports
- **THEN** the file loads, because the build has no closed set to check it against

#### Scenario: A token classifier label the model does not have

- **WHEN** a `token_classifier` guard lists a label that no entry of the model's `id2label`
  carries
- **THEN** the guard loads and reports nothing of that label

#### Scenario: The labels list is empty

- **WHEN** a guard sets `labels = []`
- **THEN** validation fails naming the guard

#### Scenario: A label is listed twice

- **WHEN** a guard sets `labels = ["PROMPT_INJECTION", "PROMPT_INJECTION"]`
- **THEN** validation fails naming the guard and the repeated label

### Requirement: A model guard reports one finding per unit and kind

A `text_classifier` guard SHALL score each unit it is given. When a unit's score is at or
above the threshold of the guard's label, the guard SHALL report exactly one finding of that
kind for that unit. The finding SHALL carry no span and SHALL carry the unit score as its
confidence. A unit scoring below the threshold SHALL give no finding.

A `token_classifier` guard SHALL report one finding for each span whose type is in `labels`,
whose label has a threshold, whose confidence is at or above that threshold, and that passes
the label's `validate_as` when it has one. The finding SHALL carry the span as a byte range
of the unit, and the span's confidence. A threshold of 0 SHALL let every span of its label
through.

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

#### Scenario: A token classifier finds two values

- **WHEN** a `token_classifier` guard with thresholds of 0.4 decodes two spans of reported
  types in one unit, with confidences 0.8 and 0.5
- **THEN** the guard reports two findings, each with its span and confidence

#### Scenario: A span below its label's threshold

- **WHEN** a `token_classifier` guard's `PERSON_NAME` threshold is 0.4 and a `PERSON_NAME`
  span has confidence 0.3
- **THEN** the guard reports no finding for that span

#### Scenario: A threshold of zero

- **WHEN** a `token_classifier` guard sets the threshold of `IP_ADDRESS` to 0.0
- **THEN** every `IP_ADDRESS` span the decoder returns becomes a finding, unless its
  `validate_as` drops it

### Requirement: A model guard scores the text of a unit

A model guard SHALL score one text per unit. For a plain-text unit, the text SHALL be the
unit's bytes decoded as UTF-8, with every invalid byte sequence replaced by U+FFFD. For a
unit parsed into fragments (a JSON body), the text SHALL be the fragments' values in
document order, joined with a newline; keys SHALL NOT be part of it.

A `token_classifier` guard SHALL map every span back to the unit's bytes:
- in a plain-text unit, to the byte range the span's characters were decoded from; a
  U+FFFD maps to the invalid bytes it replaced;
- in a unit parsed into fragments, to the document-absolute byte range of the span's
  characters inside one fragment value.

The newline that joins two fragments SHALL be a boundary no span crosses: words on its two
sides SHALL NOT merge.

#### Scenario: A plain-text unit holds an invalid byte

- **WHEN** a request body holds an attack prompt and one byte that is not valid UTF-8
- **THEN** the guard scores the decoded text and reports the attack

#### Scenario: A JSON body

- **WHEN** a JSON request body holds an attack prompt as one string value among others
- **THEN** the guard scores the values joined with newlines and reports one finding for
  the body

#### Scenario: A span after an invalid byte

- **WHEN** a plain-text body holds one invalid byte before a value a `token_classifier`
  guard reports
- **THEN** the finding's span is the byte range of that value in the body

#### Scenario: A span in a JSON value

- **WHEN** a JSON body holds a value that a `token_classifier` guard reports, inside its
  second string value
- **THEN** the finding's span is the value's document-absolute byte range in the body

#### Scenario: Two values of one type in neighbouring fragments

- **WHEN** one JSON string ends with a name and the next JSON string starts with a name
- **THEN** the guard reports two spans, one inside each value

## ADDED Requirements

### Requirement: A token classifier guard validates a label's spans as PII kinds

`[guards.<name>.validate_as]` SHALL map a label to a list of PII kind names. A span of that
label SHALL pass when the validator of any pattern of any named kind accepts the span's
text, and a span that passes none SHALL give no finding. The span checked SHALL be the
trimmed span. A label absent from `validate_as` SHALL NOT be validated.

Validation SHALL fail at startup, naming the guard, when:
- a `validate_as` key is absent from `labels`;
- a listed name is not a PII kind;
- a listed kind has no validator other than one that accepts every value;
- a list is empty;
- a `text_classifier` guard sets `validate_as`.

A failed validation SHALL NOT log, count, or return the span's text.

#### Scenario: A card number fails its checksum

- **WHEN** a guard sets `validate_as.PAYMENT_CARD = ["CREDIT_CARD"]` and a `PAYMENT_CARD`
  span holds a placeholder number that fails the Luhn check
- **THEN** the guard reports no finding for that span

#### Scenario: A card number passes its checksum

- **WHEN** the same guard decodes a `PAYMENT_CARD` span that passes the Luhn check
- **THEN** the guard reports the finding

#### Scenario: Any listed kind may accept

- **WHEN** a label lists two kinds, and only the second kind's validator accepts a span
- **THEN** the span passes

#### Scenario: A validate_as key is not a label

- **WHEN** a guard sets `validate_as` for a label absent from `labels`
- **THEN** validation fails naming the guard and the label

#### Scenario: An unknown kind

- **WHEN** a guard lists a name that is not a PII kind in `validate_as`
- **THEN** validation fails naming the guard and the name

#### Scenario: A kind that accepts everything

- **WHEN** a guard lists a kind all of whose patterns accept every value
- **THEN** validation fails naming the guard and the kind

#### Scenario: An empty list

- **WHEN** a guard sets a `validate_as` label to `[]`
- **THEN** validation fails naming the guard and the label

### Requirement: A model guard declares its finding class

A `[guards.<name>]` section MAY set `class`. Its only value SHALL be `"pii"`, and any other
value SHALL fail the schema. When `class` is absent, the guard SHALL have no class. The
class SHALL change only which metric families count the guard's findings, as the `metrics`
capability states. It SHALL NOT change detection or the outcome.

#### Scenario: A PII model guard

- **WHEN** a model guard sets `class = "pii"`
- **THEN** the file loads and the guard's findings count in the PII metric families

#### Scenario: An unknown class

- **WHEN** a model guard sets `class = "toxicity"`
- **THEN** the schema rejects the file

#### Scenario: No class

- **WHEN** a model guard sets no `class`
- **THEN** the guard's findings count in no PII metric family
