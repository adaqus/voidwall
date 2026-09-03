## Purpose

The scanner finds PII in HTTP messages. It runs the `pii` crate on a dedicated pool of
OS threads, parses structured bodies before it scans them, and resolves overlapping
matches into one non-overlapping set.

## Requirements

### Requirement: Scan targets are configurable

The scanner SHALL accept a scan target set holding the URL path, the query parameters,
a header allowlist, and the body. The path, the query, and the body SHALL default to
enabled. The header allowlist SHALL default to empty.

#### Scenario: Default scan configuration

- **WHEN** the config omits every `scan` field
- **THEN** the scanner inspects the URL path, the query parameters, and the body
- **AND** the scanner inspects no header

#### Scenario: A target is disabled

- **WHEN** `scan.body` is false
- **THEN** the scanner does not inspect the body

#### Scenario: Headers are listed

- **WHEN** `scan.headers` names a header
- **THEN** the scanner inspects that header only

### Requirement: Body size limit

The scanner SHALL not scan a body larger than `scan.max_body_size`. That limit SHALL
default to 1048576 bytes. An oversize body SHALL follow the `on_error` policy and SHALL
increment `voidwall_errors_total`.

#### Scenario: Body exceeds the limit under fail_open

- **WHEN** a body is larger than `max_body_size` and `on_error` is `fail_open`
- **THEN** the proxy forwards the message unscanned and increments the error metric

#### Scenario: Body exceeds the limit under fail_close

- **WHEN** a body is larger than `max_body_size` and `on_error` is `fail_close`
- **THEN** the proxy blocks the message and increments the error metric

### Requirement: Content type allowlist

The scanner SHALL scan a body only when its content type appears in
`scan.content_types`. The default list SHALL hold `application/json`, `text/plain`,
`text/html`, `application/x-www-form-urlencoded`, `text/csv`, and
`text/tab-separated-values`.

#### Scenario: Content type is not allowed

- **WHEN** a body carries a content type outside the allowlist
- **THEN** the scanner does not scan the body and the `on_error` policy applies

### Requirement: Structured scanning replaces flat scanning

The scanner SHALL classify a body by its content type. A JSON, CSV, or TSV body SHALL
be parsed into context-value fragments and scanned through the structured path only.
Every other body SHALL be scanned as flat text. A body SHALL never travel both paths.

#### Scenario: JSON body

- **WHEN** a body carries a JSON media type
- **THEN** the scanner flattens it into fragments and scans the fragments

#### Scenario: Plain text body

- **WHEN** a body carries `text/plain`
- **THEN** the scanner scans the raw bytes as flat text

### Requirement: JSON and CSV media type dispatch is lenient

The scanner SHALL treat `application/json`, `text/json`, and any
`application/*+json` suffix type as JSON. It SHALL treat `text/csv`,
`application/csv`, and `text/x-csv` as CSV. It SHALL treat
`text/tab-separated-values` and `text/tsv` as TSV. It SHALL ignore content type
parameters and SHALL match case-insensitively. It SHALL NOT treat
`application/vnd.ms-excel` as CSV, because that type also names a binary spreadsheet.

#### Scenario: Structured suffix type

- **WHEN** a body carries `application/ld+json`
- **THEN** the scanner parses it as JSON

#### Scenario: Content type carries a parameter

- **WHEN** a body carries `application/json; charset=utf-8`
- **THEN** the scanner parses it as JSON

### Requirement: JSON flattening produces key-path fragments

The scanner SHALL flatten nested JSON recursively. Each string value SHALL become one
fragment. The context SHALL be the dot-separated key path. An array element SHALL carry
its index in square brackets. A number, a boolean, and a null SHALL produce no
fragment. A fragment offset SHALL point at the value content bytes, excluding the
surrounding quotes.

#### Scenario: Nested object

- **WHEN** the body is `{"user": {"phone_number": "555-1234"}}`
- **THEN** one fragment carries the context `user.phone_number` and the value `555-1234`

#### Scenario: Array of strings

- **WHEN** the body is `{"phones": ["555-1234", "555-5678"]}`
- **THEN** the fragments carry the contexts `phones[0]` and `phones[1]`

#### Scenario: Non-string value

- **WHEN** a JSON value is a number, a boolean, or null
- **THEN** the scanner produces no fragment for it

### Requirement: CSV and TSV flattening uses the column name

The scanner SHALL parse the header row and SHALL produce one fragment per data cell.
The context SHALL be the column name followed by the row index in square brackets. A
fragment offset SHALL point at the cell content bytes.

#### Scenario: CSV with a header row

- **WHEN** the body is `phone_number,name` followed by the row `555-1234,John`
- **THEN** one fragment carries the context `phone_number[0]` and the value `555-1234`
- **AND** one fragment carries the context `name[0]` and the value `John`

### Requirement: CSV without a header row falls back to flat text

The scanner SHALL fall back to flat text scanning when it detects no header row.

#### Scenario: No header row is detected

- **WHEN** a CSV body has no detectable header row
- **THEN** the scanner scans the raw bytes as flat text

### Requirement: A body that fails to parse follows the on_error policy

The scanner SHALL surface a parse failure as an error. Malformed JSON and an
unterminated CSV quote SHALL not be scanned silently.

#### Scenario: Malformed JSON body

- **WHEN** a body claims a JSON content type but does not parse
- **THEN** the scanner returns an error and the `on_error` policy decides the outcome

### Requirement: Keyword-context detection walks the key path

For each fragment, the scanner SHALL synthesize `"{context}: {value}"` and run the
keyword-context pipeline. It SHALL iterate over the key path, starting from the full
prefix and dropping the last segment each time, so every segment gets a turn adjacent
to the separator. It SHALL stop as soon as a match is recorded for that value's byte
range.

#### Scenario: Keyword sits at the leaf

- **WHEN** a fragment carries the context `user.phone_number`
- **THEN** the first iteration exposes `phone_number` and the keyword detector matches

#### Scenario: Keyword sits above the leaf

- **WHEN** a fragment carries the context `phone_number.primary`
- **THEN** a later iteration exposes `phone_number` and the keyword detector matches

### Requirement: Oversize key paths fall back to per-segment synthesis

When a synthesized prefix would exceed the detector lookback window of 512 bytes, the
scanner SHALL synthesize one fragment per segment instead.

#### Scenario: Very long key path

- **WHEN** the synthesized prefix exceeds 512 bytes
- **THEN** the scanner synthesizes `"{segment}: {value}"` once per path segment

### Requirement: Overlap resolution runs before every use of the matches

The scanner SHALL pass every `mark_piis` and `mark_piis_structured` result through
`voidwall_pii::resolve_overlaps` before it counts, redacts, or reports a match. Every
count, kind list, and metric SHALL derive from the resolved set. The same value at two
distinct byte offsets SHALL stay two matches.

#### Scenario: Two detectors match overlapping spans

- **WHEN** two detectors report overlapping spans over the same bytes
- **THEN** the resolved set holds one match, and the count reflects the resolved set

#### Scenario: One value appears twice

- **WHEN** the same value appears at two distinct byte offsets
- **THEN** the resolved set holds two matches

### Requirement: Redaction preserves the document structure

Redaction SHALL operate on the original raw bytes, using document-absolute offsets. A
replacement inside a JSON string SHALL stay between the existing quotes. A replacement
inside a CSV or TSV cell SHALL stay inside the cell boundary.

#### Scenario: Redacting a JSON string value

- **WHEN** the scanner redacts a value inside a JSON body
- **THEN** the result is still valid JSON

#### Scenario: Redacting a CSV cell

- **WHEN** the scanner redacts a value inside a CSV body
- **THEN** the delimiter structure is unchanged

### Requirement: The scanner runs on dedicated OS threads

The scanner pool SHALL spawn dedicated OS threads. Each thread SHALL own its own
`voidwall_pii::Scanner`. The scanner SHALL never run on the tokio async runtime. The
thread count SHALL come from the effective scanner thread setting.

#### Scenario: Pool starts

- **WHEN** the proxy builds the scanner pool
- **THEN** it spawns one named OS thread per configured scanner thread
- **AND** each thread holds its own scanner instance

### Requirement: The pool applies backpressure

The pool SHALL use a bounded channel whose capacity is four times the thread count. A
full channel SHALL block the caller on the tokio blocking pool, up to the send timeout.
The pool SHALL return an overload error when the timeout expires.

#### Scenario: Channel is full past the timeout

- **WHEN** every scanner thread is busy and the send timeout expires
- **THEN** the pool returns an overload error and the `on_error` policy applies

#### Scenario: Every scanner thread has died

- **WHEN** the channel is disconnected
- **THEN** the pool returns an error naming the dead threads

### Requirement: The pool shuts down cleanly

Shutdown SHALL close the channel and SHALL join every scanner thread.

#### Scenario: Shutdown is requested

- **WHEN** the pool shuts down
- **THEN** the channel closes and every scanner thread exits and is joined

### Requirement: The scanner never leaks a PII value

The scanner SHALL never write a PII value to a log, a metric label, or an error
message. It SHALL log the kind name and the match count only. It SHALL release the body
buffer once the scan ends.

#### Scenario: A scan detects PII

- **WHEN** the scanner detects PII and logs the outcome
- **THEN** the log line names the kind and the count, and carries no matched text
