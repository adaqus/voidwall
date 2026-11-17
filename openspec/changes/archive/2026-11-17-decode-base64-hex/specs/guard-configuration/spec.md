## RENAMED Requirements

- FROM: `### Requirement: A guard chooses the scan view or the raw text`
- TO: `### Requirement: A guard chooses the scan view or the decoded view`

## MODIFIED Requirements

### Requirement: A guard chooses the scan view or the decoded view

The `[builtin_guards.pii]` section and every `[guards.<name>]` section MAY set
`scan_view`, a boolean. It SHALL decide whether the guard reads a request unit through
the scan view that the `hidden-unicode-normalization` capability builds (`true`) or
through the decoded view that the `encoded-content-decoding` capability builds (`false`).
The defaults SHALL be:

- `true` for the `pii` guard;
- `true` for a model guard with `adapter = "token_classifier"`;
- `false` for a model guard with `adapter = "text_classifier"`.

`scan_view` SHALL change only what the guard reads in the request direction. It SHALL NOT
change the guard's directions, its surface, or how its findings block. A value that is not
a boolean SHALL fail the schema. The `hidden_context` and `invisible_text` sections SHALL
NOT accept `scan_view`.

#### Scenario: Defaults of the shipped guards

- **WHEN** the config declares the `pii` guard, a `text_classifier` guard and a
  `token_classifier` guard, and none sets `scan_view`
- **THEN** the `pii` guard and the `token_classifier` guard read the scan view of a
  request, and the `text_classifier` guard reads its decoded view

#### Scenario: A text classifier set to read the scan view

- **WHEN** a `text_classifier` guard sets `scan_view = true`
- **THEN** the file loads and the guard reads the scan view of a request

#### Scenario: The pii guard set to read the raw text

- **WHEN** `[builtin_guards.pii]` sets `scan_view = false`
- **THEN** the file loads and the guard reads the decoded view of a request

#### Scenario: The pii guard set to read the decoded view finds base64

- **WHEN** `[builtin_guards.pii]` sets `scan_view = false`, and a request body holds an
  email placeholder in base64
- **THEN** the guard reports the email kind

#### Scenario: A value that is not a boolean

- **WHEN** a model guard sets `scan_view = "yes"`
- **THEN** the schema rejects the file

#### Scenario: The pii guard reads the raw text of a response

- **WHEN** `[builtin_guards.pii]` sets `scan_view = true`, and a response body holds an
  IBAN placeholder with a soft hyphen between two digits
- **THEN** the guard reads the raw text of the response and reports no IBAN

#### Scenario: The hidden context guard sets scan_view

- **WHEN** `[builtin_guards.hidden_context]` sets `scan_view = true`
- **THEN** the schema rejects the file

### Requirement: A model guard scores the text of a unit

A model guard SHALL score one text per unit. For a plain-text unit, the text SHALL be the
unit's bytes decoded as UTF-8, with every invalid byte sequence replaced by U+FFFD. For a
unit parsed into fragments (a JSON body), the text SHALL be the fragments' decoded values
in document order, joined with a newline; keys SHALL NOT be part of it.

In the request direction, when the guard reads the scan view (`scan_view`, see "A guard
chooses the scan view or the decoded view"), the bytes of a plain-text unit and the values
of a fragment SHALL be those of the scan view that the `hidden-unicode-normalization`
capability builds. Otherwise they SHALL be those of the decoded view that the
`encoded-content-decoding` capability builds. In the response direction they SHALL be the
raw text.

The span of a `token_classifier` finding SHALL name the unit's bytes:
- in a plain-text unit, the byte range the span's characters were decoded from; a
  U+FFFD maps to the invalid bytes it replaced;
- in a unit parsed into fragments, the document-absolute byte range that the span's
  characters were decoded from inside one fragment value; a character from an escape
  sequence maps to the whole sequence.

When the guard reads the scan view, the span SHALL name bytes of the raw unit, by the
span rule of `hidden-unicode-normalization`. When it reads the decoded view, the span
SHALL name bytes of the raw unit, by the span rule of `encoded-content-decoding`.

The newline that joins two fragments SHALL be a boundary no span crosses: words on its two
sides SHALL NOT merge.

#### Scenario: A plain-text unit holds an invalid byte

- **WHEN** a request body holds an attack prompt and one byte that is not valid UTF-8
- **THEN** the guard scores the decoded text and reports the attack

#### Scenario: A JSON body

- **WHEN** a JSON request body holds an attack prompt as one string value among others
- **THEN** the guard scores the values joined with newlines and reports one finding for
  the body

#### Scenario: An escaped attack prompt in a JSON body

- **WHEN** a JSON request body holds an attack prompt with every character written as a
  `\uXXXX` escape
- **THEN** the guard scores the decoded prompt and reports the attack

#### Scenario: A text classifier reads the raw text by default

- **WHEN** a request body holds an attack prompt with a soft hyphen after each letter,
  and a `text_classifier` guard sets no `scan_view`
- **THEN** the guard scores the text with the soft hyphens in it

#### Scenario: A text classifier reads a base64 prompt by default

- **WHEN** a request body holds an attack prompt in base64, and a `text_classifier` guard
  sets no `scan_view`
- **THEN** the guard scores the decoded prompt and reports the attack

#### Scenario: A text classifier set to read the scan view

- **WHEN** a request body holds an attack prompt with a soft hyphen after each letter,
  and a `text_classifier` guard sets `scan_view = true`
- **THEN** the guard scores the scan view, which holds the prompt without soft hyphens,
  and reports the attack

#### Scenario: A token classifier reads the scan view by default

- **WHEN** a request body holds a name with a soft hyphen between two of its letters,
  and a `token_classifier` guard sets no `scan_view`
- **THEN** the guard scores the scan view and reports the name

#### Scenario: The response direction

- **WHEN** a response body holds a name with a soft hyphen between two of its letters,
  and a `token_classifier` guard sets no `scan_view`
- **THEN** the guard scores the raw text, with the soft hyphen in it

#### Scenario: A span after an invalid byte

- **WHEN** a plain-text body holds one invalid byte before a value a `token_classifier`
  guard reports
- **THEN** the finding's span is the byte range of that value in the body

#### Scenario: A span in a JSON value

- **WHEN** a JSON body holds a value that a `token_classifier` guard reports, inside its
  second string value
- **THEN** the finding's span is the value's document-absolute byte range in the body

#### Scenario: A span in a JSON value with escaped non-ASCII

- **WHEN** a JSON body holds a name that a `token_classifier` guard reports, with its
  non-ASCII letters written as `\uXXXX` escapes
- **THEN** the guard reports the name, and the finding's span is the byte range of the
  escaped name in the raw body

#### Scenario: A span after removed characters in a request

- **WHEN** a plain-text request body holds soft hyphens, then ordinary text, and then a
  name that a `token_classifier` guard reports through the scan view
- **THEN** the finding's span is the byte range of the name in the raw body

#### Scenario: Two values of one type in neighbouring fragments

- **WHEN** one JSON string ends with a name and the next JSON string starts with a name
- **THEN** the guard reports two spans, one inside each value
