## Purpose

The evaluation measures how well the `voidwall-pii` regex engine detects PII, in two
ways. Against the public AI4Privacy openpii300k dataset, it reports recall and precision
per dataset label, and micro precision, recall, F1, and F2. On the English tasks of the PII
Masking Benchmark (piimb), it reports character-level precision, recall, F1, and F2 per
task and their average, computed by the benchmark's own metric code. It measures the
engine, not the proxy.

## Requirements

### Requirement: The harness is a separate tool outside the image

The harness SHALL be a binary named `ai4privacy-eval` in the workspace crate
`voidwall-eval`. Among workspace crates, that crate SHALL depend on `voidwall-pii` only.
The Docker image SHALL NOT carry the harness.

#### Scenario: The image is built

- **WHEN** the Docker image is built
- **THEN** it holds no `ai4privacy-eval` binary and no dataset file

### Requirement: The harness scores the regex engine directly

The harness SHALL detect PII by calling the `voidwall-pii` scanner in-process. It SHALL
NOT start or call the proxy. Before it scores a row, it SHALL pass the row's matches
through `voidwall_pii::resolve_overlaps`, and it SHALL score the resolved set only.

#### Scenario: Two matches overlap

- **WHEN** the scanner returns two overlapping matches for one row
- **THEN** the harness scores only the matches `resolve_overlaps` keeps

#### Scenario: Proxy is not running

- **WHEN** no Voidwall proxy runs
- **THEN** the harness still scores every row

### Requirement: The scanner is configured per language

For each language, the harness SHALL build the scanner with that language and with these
countries:

| Language | Countries |
|---|---|
| en | International, US, GB, AU, NZ, CA, IE, ZA |
| fr | International, FR, CH, CA |
| de | International, DE, AT, CH |
| nl | International, NL |
| it | International, IT, CH |
| es | International, ES |

The harness SHALL score each row with the scanner for the row's `language` field. It SHALL
skip a row whose language is none of the six, and the report SHALL state how many rows it
skipped.

#### Scenario: French row

- **WHEN** a row's `language` field is French
- **THEN** the harness scores it with the scanner built for `fr` and FR, CH, CA, and
  International

#### Scenario: Row in an unsupported language

- **WHEN** a row's `language` field names none of the six languages
- **THEN** the harness does not score that row and counts it as skipped

### Requirement: AI4Privacy labels map to PiiKinds

Each AI4Privacy label SHALL map to the set of `PiiKind`s that count as the right kind for
it:

| Label | PiiKinds |
|---|---|
| EMAIL | EMAIL |
| IP | IP_ADDRESS |
| GEOCOORD | PRECISE_GEOLOCATION |
| BOD | DATE_OF_BIRTH |
| GIVENNAME1, GIVENNAME2, LASTNAME1, LASTNAME2, LASTNAME3 | PERSON_NAME |
| TEL | PHONE_NUMBER and every country phone number kind |
| POSTCODE | every country postal code kind, GB_POSTCODE, IE_EIRCODE |
| STREET | US_GB_CA_AU_NZ_IE_ZA_STREET, GB_ADDRESS, DE_AT_CH_ADDRESS, FR_CH_ADDRESS |
| SECADDRESS | SECONDARY_ADDRESS, GB_ADDRESS, DE_AT_CH_ADDRESS, FR_CH_ADDRESS |
| PASSPORT | PASSPORT_NUMBER, every country passport number kind, US_PASSPORT_NEW |
| DRIVERLICENSE | every country driver's licence kind |
| IDCARD | PL_ID_CARD, DE_PERSONALAUSWEIS, ES_DNI, ES_NIE, FR_CNI, IT_CODICE_FISCALE, ZA_ID, NL_BSN |
| SOCIALNUMBER | US_SSN, US_ITIN, GB_NINO, CA_SIN, IE_PPSN, AU_TFN, FR_NIR, ES_NUSS, NL_BSN, PL_PESEL, IT_CODICE_FISCALE, CH_AHV, AT_SVNR, NZ_IRD_NUMBER, ZA_ID |

A label that maps to at least one `PiiKind` SHALL be supported. PASS, TITLE, CARDISSUER,
COUNTRY, CITY, STATE, SEX, DATE, TIME, USERNAME, and BUILDING SHALL be unsupported. A label
outside this vocabulary SHALL be unsupported, and the report SHALL name it.

#### Scenario: Phone number of any country

- **WHEN** a TEL annotation is covered by a prediction of a country phone number kind
- **THEN** the prediction counts as the right kind for TEL

#### Scenario: Label outside the vocabulary

- **WHEN** a row holds an annotation whose label the mapping does not know
- **THEN** the harness scores it as unsupported and the report names the label

### Requirement: Scoring is span-level overlap

Annotation offsets are character offsets. The harness SHALL compare an annotation and a
prediction over the same text positions. A prediction that overlaps an annotation SHALL
count as a true positive. A prediction that overlaps no annotation SHALL count as a false
positive. An annotation that no prediction overlaps SHALL count as a false negative.
Precision SHALL be the matched predictions over all predictions. Recall SHALL be the
matched annotations over all annotations. F1 SHALL be their harmonic mean. F2 SHALL be
5·P·R / (4·P + R), which weighs recall more than precision.

#### Scenario: Prediction overlaps an annotation

- **WHEN** a prediction overlaps an annotation
- **THEN** the harness counts a true positive

#### Scenario: Prediction overlaps nothing

- **WHEN** a prediction overlaps no annotation
- **THEN** the harness counts a false positive

#### Scenario: F2 weighs recall more than F1 does

- **WHEN** precision is 1 and recall is 0.5
- **THEN** F1 is 2/3 and F2 is 5/9

#### Scenario: Multi-byte characters precede the annotation

- **WHEN** a row holds multi-byte characters before an annotated value and the scanner
  detects that value
- **THEN** the prediction and the annotation overlap and the harness counts a true positive

### Requirement: Two metric variants are reported

The harness SHALL report detection metrics, which ignore the kind, and typed metrics, where
the predicted kind must be in the set the label maps to.

#### Scenario: Right span, wrong kind

- **WHEN** a prediction overlaps an annotation and its kind is not in the label's set
- **THEN** it counts for the detection metrics and not for the typed metrics

### Requirement: The report gives per-label and overall numbers

The report SHALL give recall per label and SHALL give precision per label. A prediction
SHALL count toward the precision of every label whose set holds its kind. The report SHALL
give micro precision, recall, F1, and F2 over all labels, and macro recall over the supported
labels. The report SHALL hold no text from the dataset; it SHALL hold labels, kind names,
and counts only. The report SHALL end with a legend that explains the detection and typed
variants, the column names, and the micro and macro totals. The legend SHALL be the same
with and without `SUPPORTED_ONLY=1`, and SHALL NOT name that variable.

#### Scenario: A run finishes

- **WHEN** the harness finishes a run
- **THEN** the report shows each label's recall and precision in both variants, the micro
  totals, and the macro recall

#### Scenario: The legend explains the variants

- **WHEN** the harness reports a run
- **THEN** the report ends with a legend that says what the detection and the typed
  variants count

#### Scenario: The report holds no values

- **WHEN** the harness reports a run
- **THEN** no annotated value and no row text appears in the output

### Requirement: SUPPORTED_ONLY scores supported labels only

When `SUPPORTED_ONLY=1`, the report SHALL omit unsupported labels, and the totals SHALL
leave out their annotations. A prediction that overlaps only unsupported annotations SHALL
count as neither a true positive nor a false positive.

#### Scenario: Prediction overlaps only an unsupported annotation

- **WHEN** `SUPPORTED_ONLY=1` and a prediction overlaps a CITY annotation and nothing else
- **THEN** the prediction does not change precision

### Requirement: The runner is docker/ctl ai4p-eval

`docker/ctl ai4p-eval` SHALL run the harness. It SHALL accept `AI4P_LANG`, `DATASET`, `MAX_ROWS`, and
`SUPPORTED_ONLY` as environment variables. `AI4P_LANG` SHALL accept the codes en, nl, fr, de,
it, and es, and the full English language names. When `AI4P_LANG` is unset, the run SHALL score
all six languages. An unknown `AI4P_LANG` SHALL stop the run with a non-zero exit status. The
exit status SHALL NOT depend on the scores.

#### Scenario: One language

- **WHEN** `AI4P_LANG=fr docker/ctl ai4p-eval` runs
- **THEN** the harness scores the French rows only

#### Scenario: No language

- **WHEN** `AI4P_LANG` is unset
- **THEN** the harness scores the rows of all six languages

#### Scenario: Unknown language

- **WHEN** `AI4P_LANG=pt docker/ctl ai4p-eval` runs
- **THEN** the run stops with a non-zero exit status and names the accepted values

### Requirement: The dataset is fetched on demand and cached

The dataset SHALL NOT be vendored. When `DATASET` is unset, `docker/ctl ai4p-eval` SHALL fetch
the needed openpii300k train files over HTTPS into `.cache/ai4privacy/`, with no token. It
SHALL fetch the `AI4P_LANG` file alone when `AI4P_LANG` is set, and all six files otherwise. It SHALL
NOT fetch a file the cache already holds. When `DATASET` names a local JSONL file or
directory, the run SHALL use it and fetch nothing.

#### Scenario: Empty cache

- **WHEN** `AI4P_LANG=de docker/ctl ai4p-eval` runs with an empty cache
- **THEN** the runner fetches the German file into the cache and scores it

#### Scenario: Cached file

- **WHEN** the cache already holds the file for `AI4P_LANG`
- **THEN** the runner fetches nothing

#### Scenario: Local dataset

- **WHEN** `DATASET` names a local JSONL file
- **THEN** the harness scores that file and fetches nothing

### Requirement: Rows are streamed

The harness SHALL read JSONL line by line and SHALL NOT hold the whole file in memory. It
SHALL ignore unknown fields. It SHALL skip a line that does not parse and SHALL count it in
the report. It SHALL stop after `MAX_ROWS` scored rows when `MAX_ROWS` is set.

#### Scenario: Row cap

- **WHEN** `MAX_ROWS=200`
- **THEN** the harness scores 200 rows and reports on them

#### Scenario: Malformed line

- **WHEN** a dataset line is not valid JSON
- **THEN** the harness skips it, counts it as a parse error, and continues

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
