## Purpose

`DictionaryDetector` finds PII drawn from a finite vocabulary, where a generated
format does not exist. Person names are the case it serves. It looks a candidate up in
a finite-state transducer, at microsecond cost, and complements the Vectorscan and
regex chain rather than replacing it.

## Requirements

### Requirement: The gazetteer is one shared read-only artifact

The detector SHALL load one FST map, built offline. It SHALL load it once and SHALL
share it read-only across every scanner thread. It SHALL NOT hold one copy per thread.
It SHALL stay separate from the Vectorscan database, so it does not affect Vectorscan
compile time or the keyword automaton size.

#### Scenario: Several scanner threads run

- **WHEN** the pool spawns several scanner threads with the detector active
- **THEN** the process holds one copy of the gazetteer, shared by every thread

### Requirement: A gazetteer entry carries role flags

Each surface form SHALL carry a flag mask. `IS_GIVEN` and `IS_SURNAME` SHALL name the
role. `ALSO_COMMON_WORD` SHALL mark a form that is also an ordinary word. There SHALL
be no per-language flag, because a name form routinely belongs to several languages.

#### Scenario: A form is both a name and an ordinary word

- **WHEN** a form such as an English word that is also a given name is looked up
- **THEN** the entry carries `ALSO_COMMON_WORD`

### Requirement: The gazetteer covers English names and Italian and Spanish surnames

The single artifact SHALL hold English given names and surnames, plus Italian and
Spanish surnames. The entries SHALL carry their accents, so real text matches.

#### Scenario: An accented Spanish surname appears

- **WHEN** the text carries a Spanish surname written with its accent
- **THEN** the detector resolves it as a surname

### Requirement: Detection tokenizes, windows, and looks up

The detector SHALL tokenize with Unicode-aware word boundaries and SHALL keep each
token's byte offsets. It SHALL form windows of one to three adjacent tokens, so a
multi-token surname is covered. It SHALL build a canonical key by lowercasing the
tokens and joining them with a single space. It SHALL emit a `PersonName` match over
the original byte span.

#### Scenario: A name sits inside a longer word

- **WHEN** a gazetteer form appears as a substring of a longer word
- **THEN** the detector does not match, because tokenization keeps the word boundary

#### Scenario: A multi-token surname appears

- **WHEN** the text carries a surname made of two or three tokens
- **THEN** a window covers it and the detector emits one match over the whole span

### Requirement: Cost is independent of dictionary size

The scan cost SHALL be proportional to the text length, not to the gazetteer size. The
detector SHALL start a window only at a capitalised, non-numeric token. It SHALL stop
extending a window once its prefix dead-ends in the automaton.

#### Scenario: The gazetteer grows

- **WHEN** the gazetteer gains entries
- **THEN** the per-request scan cost does not grow with it

#### Scenario: A window prefix dead-ends

- **WHEN** a one-token prefix matches no path in the automaton
- **THEN** the detector does not extend that window further

### Requirement: A common-word form needs promoting evidence

A hit carrying `ALSO_COMMON_WORD` SHALL be suppressed unless cheap evidence promotes
it: capitalisation mid-sentence, an adjacent given and surname pair, or a nearby title
or honorific keyword. A form without that flag SHALL fire on a bare hit.

#### Scenario: Common-word form with no evidence

- **WHEN** a form carrying `ALSO_COMMON_WORD` appears with no promoting evidence
- **THEN** the detector emits no match

#### Scenario: Common-word form beside a surname

- **WHEN** a form carrying `ALSO_COMMON_WORD` appears next to a known surname
- **THEN** the detector emits a match over the pair

#### Scenario: Form is not a common word

- **WHEN** a form without `ALSO_COMMON_WORD` is found
- **THEN** the detector emits a match on the bare hit

### Requirement: Structured scanning uses the value only

In structured scanning the detector SHALL scan each fragment's value text directly and
SHALL adjust the offsets back to document-absolute positions. It SHALL NOT use the key
path as context, because a name needs no keyword.

#### Scenario: A JSON value holds a name

- **WHEN** a JSON string value holds a person name under any key
- **THEN** the detector matches it and reports document-absolute offsets

### Requirement: The detector runs last in the chain

The detector SHALL be registered after the keyword-context detector. Chain order SHALL
NOT change the `mark_piis` output, because the proxy resolves the union through
`pii::resolve_overlaps`. Running last SHALL let `has_piis` short-circuit on a cheaper
detector first.

#### Scenario: A cheaper detector already matched

- **WHEN** `has_piis` finds a match in an earlier detector
- **THEN** the tokenization work of the dictionary detector is skipped

### Requirement: Activation follows the PersonName kind toggle

The detector SHALL be built and registered only when `PersonName` is in the enabled
kind set. When `PersonName` is disabled, the detector SHALL NOT be constructed and the
gazetteer SHALL NOT be loaded. There SHALL be no dedicated config key.

#### Scenario: PersonName is enabled

- **WHEN** `detect` names `PersonName`, or `ignore` omits it
- **THEN** the detector is constructed and the gazetteer is loaded

#### Scenario: PersonName is disabled

- **WHEN** `ignore` names `PersonName`
- **THEN** the gazetteer is never loaded and the hot path pays nothing

### Requirement: The proxy surface is unchanged

A match SHALL flow through the existing pipeline as `PersonName`. It SHALL appear in
`pii_proxy_detections_total` with the `PERSON_NAME` kind, in `X-PII-Detected`, and as
the `[PERSON_NAME]` redaction replacement. The detector SHALL add no config key, no
metric, and no response field.

#### Scenario: A name is redacted under type_label

- **WHEN** the detector matches and `redact_strategy` is `type_label`
- **THEN** the replacement is `[PERSON_NAME]`
