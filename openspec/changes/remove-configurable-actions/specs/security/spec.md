## MODIFIED Requirements

### Requirement: A PII value never reaches an error response

A block response SHALL list detected kind names. It SHALL NOT carry the matched text. An
error response SHALL NOT echo the body that produced it.

#### Scenario: A request is blocked

- **WHEN** the proxy returns a 403 for a detection
- **THEN** the body lists the kinds and carries no matched value

#### Scenario: A body fails to parse

- **WHEN** the API returns 400 for a malformed body
- **THEN** the response does not echo the body content

### Requirement: Body buffers are released promptly

The proxy SHALL drop the buffered body once the scan is done. It SHALL not hold a body
longer than the request needs, and SHALL avoid an unnecessary copy. A structured body
SHALL NOT be retained after parsing: the scanner reads the parsed fragments, so the
original document bytes are released when parsing ends.

#### Scenario: A request completes

- **WHEN** the proxy finishes forwarding a request
- **THEN** the buffered body is released

#### Scenario: A structured body is parsed

- **WHEN** a JSON or CSV body is parsed into fragments
- **THEN** the original document bytes are not held beyond the parse
