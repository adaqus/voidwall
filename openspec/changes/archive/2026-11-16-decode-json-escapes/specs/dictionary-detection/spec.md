## MODIFIED Requirements

### Requirement: Structured scanning uses the value only

In structured scanning the detector SHALL scan each fragment's value text directly. The
span of a match SHALL be document-absolute, by the span rule that `pii-scanning` states
for a JSON value. The detector SHALL NOT use the key path as context, because a name needs
no keyword.

#### Scenario: A JSON value holds a name

- **WHEN** a JSON string value holds a person name under any key
- **THEN** the detector matches it and the finding's span is document-absolute
