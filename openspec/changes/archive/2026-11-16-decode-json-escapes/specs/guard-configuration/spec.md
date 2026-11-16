## MODIFIED Requirements

### Requirement: A model guard scores the text of a unit

A model guard SHALL score one text per unit. For a plain-text unit, the text SHALL be the
unit's bytes decoded as UTF-8, with every invalid byte sequence replaced by U+FFFD. For a
unit parsed into fragments (a JSON body), the text SHALL be the fragments' decoded values
in document order, joined with a newline; keys SHALL NOT be part of it.

The span of a `token_classifier` finding SHALL name the unit's bytes:
- in a plain-text unit, the byte range the span's characters were decoded from; a
  U+FFFD maps to the invalid bytes it replaced;
- in a unit parsed into fragments, the document-absolute byte range that the span's
  characters were decoded from inside one fragment value; a character from an escape
  sequence maps to the whole sequence.

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

#### Scenario: Two values of one type in neighbouring fragments

- **WHEN** one JSON string ends with a name and the next JSON string starts with a name
- **THEN** the guard reports two spans, one inside each value
