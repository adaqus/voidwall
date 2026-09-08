## Purpose

The scanner finds PII in HTTP messages. It runs the `pii` crate on a dedicated pool of
OS threads, parses structured bodies before it scans them, and resolves overlapping
matches into one non-overlapping set.

## Requirements

### Requirement: A guard returns findings only

A guard SHALL be one detection concern. It SHALL return a list of findings and SHALL do
nothing else: it SHALL NOT block, redact, add a header, or write a metric. Each finding
SHALL name the unit it came from, the kind it found, and the guard that reported it, and
SHALL carry a byte span, a confidence, or both when the guard has them.

Every guard SHALL declare which unit kinds it is interested in. The engine, not the
guard, SHALL apply that declaration.

#### Scenario: A guard reports a match

- **WHEN** a guard finds an email address in a request body
- **THEN** it returns one finding naming the body unit, the kind, its own name, and the
  byte span of the match
- **AND** the message is unchanged and no metric has moved

#### Scenario: A guard reports a verdict with no span

- **WHEN** a guard classifies a whole unit rather than a substring of it
- **THEN** it returns a finding that carries a confidence and no span

### Requirement: The engine aggregates the guards

One engine SHALL own every guard and SHALL be the only entry point for detection. For
each message it SHALL select the units, call every guard whose declared interest matches
at least one selected unit, await them all, and return the merged findings.

A guard whose declared interest matches no selected unit SHALL NOT be called.

The merged findings SHALL be returned in a stable order that does not depend on the
order in which the guards finished: by unit, then by span start, then by span end, then
by guard name, then by kind, with span-less findings last.

The engine SHALL stop waiting only when a finding triggers a block. Guards still running
at that point SHALL be abandoned, and their findings SHALL NOT appear in the result. A
redact or header outcome SHALL NOT stop the engine.

#### Scenario: No guard is interested

- **WHEN** the selected units are of a kind no guard declares interest in
- **THEN** no guard is called and the result holds no findings

#### Scenario: Two guards run over the same message

- **WHEN** two guards both declare interest in the body and both report a finding
- **THEN** the result holds both findings in the stable order

#### Scenario: The same message is scanned twice

- **WHEN** the same message is scanned twice with the same configuration
- **THEN** the two results list their findings in the same order

#### Scenario: A blocking finding arrives first

- **WHEN** one guard reports a finding that triggers a block while another guard is
  still running
- **THEN** the engine returns the block outcome and the result carries no finding from
  the abandoned guard

#### Scenario: A redacting finding arrives first

- **WHEN** one guard reports a finding that triggers only a redaction while another
  guard is still running
- **THEN** the engine waits for the second guard and the result holds both findings

### Requirement: The kind list is ordered and holds each kind once

The kind list of a scan result SHALL be derived from the findings. It SHALL be sorted by
kind name and SHALL hold each kind once, however many findings or guards reported it.
Two scans of the same content SHALL produce the same list in the same order.

#### Scenario: One kind is found many times

- **WHEN** a scan produces four findings of the same kind
- **THEN** the kind list holds that kind once

#### Scenario: Two guards report the same kind

- **WHEN** two guards each report a finding of the same kind
- **THEN** the kind list holds that kind once

#### Scenario: Several kinds are found

- **WHEN** a scan finds three different kinds
- **THEN** the kind list names them in sorted order, and a second scan of the same
  content returns the same order

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

Overlap resolution SHALL be scoped to a kind vocabulary, not to a message. While one
guard is the only producer of a vocabulary, that guard SHALL pass every match through
`voidwall_pii::resolve_overlaps` before it returns its findings. Every count, kind list,
and metric SHALL derive from the resolved set. The same value at two distinct byte
offsets SHALL stay two matches.

Resolution SHALL NOT be applied twice over the same spans. Resolving each guard's
findings and then resolving the union is not the same as resolving the union, so when a
second guard produces the same vocabulary, resolution SHALL move to the engine over the
union and the per-guard resolution SHALL be removed.

#### Scenario: Two detectors match overlapping spans

- **WHEN** two detectors report overlapping spans over the same bytes
- **THEN** the resolved set holds one match, and the count reflects the resolved set

#### Scenario: One value appears twice

- **WHEN** the same value appears at two distinct byte offsets
- **THEN** the resolved set holds two matches

#### Scenario: Findings are resolved once

- **WHEN** the engine merges the findings of the guards
- **THEN** it applies no further overlap resolution to spans a guard already resolved

### Requirement: Redaction preserves the document structure

Redaction SHALL be applied by the action engine over the findings of a scan. It SHALL
operate on the original raw bytes, using document-absolute offsets. A replacement inside
a JSON string SHALL stay between the existing quotes. A replacement inside a CSV or TSV
cell SHALL stay inside the cell boundary. Redaction SHALL read the scanned content
without mutating it.

#### Scenario: Redacting a JSON string value

- **WHEN** the redact action replaces a value inside a JSON body
- **THEN** the result is still valid JSON

#### Scenario: Redacting a CSV cell

- **WHEN** the redact action replaces a value inside a CSV body
- **THEN** the delimiter structure is unchanged

#### Scenario: The scanned content is not mutated

- **WHEN** the redact action produces a redacted body
- **THEN** it returns replacement bytes and the scanned content is unchanged

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

Dropping the scanner pool SHALL be the only way to shut it down. It SHALL close the
channel and SHALL join every scanner thread. No caller SHALL need to reclaim the pool to
shut it down, and no shutdown path SHALL leave a scanner thread running.

#### Scenario: Shutdown is requested

- **WHEN** the process releases the detection engine at shutdown
- **THEN** the channel closes and every scanner thread exits and is joined before the
  shutdown log line is written

#### Scenario: The pool is still shared

- **WHEN** more than one holder still references the pool at shutdown
- **THEN** the threads are joined when the last holder releases it, and none is left
  running

### Requirement: The scanner never leaks a PII value

The scanner SHALL never write a PII value to a log, a metric label, or an error
message. It SHALL log the kind name and the match count only. It SHALL release the body
buffer once the scan ends.

#### Scenario: A scan detects PII

- **WHEN** the scanner detects PII and logs the outcome
- **THEN** the log line names the kind and the count, and carries no matched text
