## Purpose

The scanner finds PII in HTTP messages. It runs the `pii` crate on a dedicated pool of
OS threads, parses structured bodies before it scans them, and resolves overlapping
matches into one non-overlapping set.

## Requirements

### Requirement: A guard returns findings only

A guard SHALL be one detection concern. It SHALL return a list of findings and SHALL do
nothing else: it SHALL NOT block the message, change it, or write a metric. A finding
SHALL name the unit it came from, the kind it found, and the guard that reported it, and
SHALL carry a byte span, a confidence, or both when the guard has them.

A guard SHALL name itself with the name configuration gave it, not with a fixed string
the build defines.

Every guard SHALL declare which unit kinds it is interested in. The engine, not the
guard, SHALL apply that declaration. A guard's declared interest SHALL come from its
configured scan surface.

#### Scenario: A guard reports a match

- **WHEN** a guard finds an email address in a request body
- **THEN** it returns one finding naming the body unit, the kind, its configured guard
  name, and the byte span

#### Scenario: A guard reports a verdict with no span

- **WHEN** a guard classifies a whole unit rather than a substring of it
- **THEN** it returns a finding carrying a confidence and no span

### Requirement: The engine aggregates the guards and owns the stage order

One engine SHALL own every guard and SHALL be the only entry point for detection. For
each message it SHALL select the units, call every guard whose declared interest matches
at least one selected unit, await them all, and return the merged findings.

A guard whose declared interest matches no selected unit SHALL NOT be called.

The merged findings SHALL be returned in a stable order that does not depend on the
order in which the guards finished: by unit, then by span start, then by span end, then
by guard name, then by kind, with span-less findings last.

The engine SHALL stop waiting only when the caller's policy says a finding ends the scan.
Guards still running at that point SHALL be abandoned, and their findings SHALL NOT appear
in the result. A caller that reports a detection without stopping the message SHALL NOT
stop the engine early.

A guard error SHALL NOT end the scan. The engine SHALL keep waiting for the other guards,
and SHALL return the findings of the guards that succeeded together with the error.

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

- **WHEN** one guard reports a finding while another guard is still running, and the
  caller's policy says a finding ends the scan
- **THEN** the engine returns and the result carries no finding from the abandoned guard

#### Scenario: A reporting caller waits for every guard

- **WHEN** one guard reports a finding while another guard is still running, and the
  caller reports rather than blocks
- **THEN** the engine waits for the second guard and the result holds both findings

#### Scenario: A guard fails before another guard reports

- **WHEN** one guard returns an error while another guard is still running, and the second
  guard then reports a finding
- **THEN** the engine waits for the second guard and returns its finding together with the
  error

#### Scenario: A guard fails and no other guard reports

- **WHEN** one guard returns an error and every other guard reports nothing
- **THEN** the engine returns the error and no finding

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

Each guard SHALL carry a scan surface holding the URL path, the query parameters, and
the body, each defaulting to enabled.

The surface SHALL belong to the guard. Two enabled guards MAY carry different surfaces,
and the engine SHALL call each guard only with the units its own surface admits.

The header allowlist SHALL NOT be part of the surface. It belongs to the route, which
decides which header values become units at all; a guard that runs for a route SHALL
see every header unit that route produced.

#### Scenario: Default scan configuration

- **WHEN** a guard omits every `surface` field
- **THEN** it inspects the URL path, the query parameters, and the body

#### Scenario: A target is disabled

- **WHEN** a guard sets `surface.body` to false
- **THEN** that guard does not inspect the body

#### Scenario: Headers are listed

- **WHEN** a route names one header and two guards are selected for that route
- **THEN** both guards inspect that header value, and no other header is inspected

### Requirement: Body size limit

The proxy SHALL not scan a body larger than the top-level `max_body_size`. That limit
SHALL default to 1048576 bytes. It SHALL apply to every guard alike, because it governs
how much of a message is read before detection begins. An oversize body SHALL follow the
`on_error` policy and SHALL increment `voidwall_errors_total`.

#### Scenario: Body exceeds the limit under fail_open

- **WHEN** a body is larger than `max_body_size` and `on_error` is `fail_open`
- **THEN** the proxy forwards the message unscanned and increments the error metric

#### Scenario: Body exceeds the limit under fail_close

- **WHEN** a body is larger than `max_body_size` and `on_error` is `fail_close`
- **THEN** the proxy blocks the message and increments the error metric

### Requirement: Content type allowlist

The proxy SHALL scan a body only when its content type appears in the top-level
`content_types` list. The default list SHALL hold `application/json`, `text/plain`,
`text/html`, `application/x-www-form-urlencoded`, `text/csv`, and
`text/tab-separated-values`. The list SHALL apply to every guard alike.

A body whose content type sits outside the list SHALL be skipped in silence. That is not
an error. The `on_error` policy SHALL NOT apply to it and `voidwall_errors_total` SHALL
NOT increment.

#### Scenario: Content type is not allowed

- **WHEN** a body carries a content type outside the allowlist
- **THEN** the proxy does not scan the body

#### Scenario: A skipped content type is not an error

- **WHEN** a body carries a content type outside the allowlist and `on_error` is `fail_close`
- **THEN** the proxy forwards the message to the upstream unchanged

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

Overlap resolution SHALL be scoped to a kind vocabulary, not to a message. A vocabulary
SHALL be the set of kinds one guard produces. Two guards that report kinds of the same name
SHALL NOT share a vocabulary: the engine SHALL merge their findings and SHALL resolve nothing
between them.

The regex PII guard SHALL pass every match through `voidwall_pii::resolve_overlaps` before it
returns its findings. Every count, kind list, and metric of its findings SHALL derive from
the resolved set. The same value at two distinct byte offsets SHALL stay two matches.

Resolution SHALL NOT be applied twice over the same spans. Resolving each guard's findings
and then resolving the union is not the same as resolving the union, so if two guards are
ever built to produce one vocabulary, resolution SHALL move to the engine over their union
and the per-guard resolution SHALL be removed.

#### Scenario: Two detectors match overlapping spans

- **WHEN** two detectors report overlapping spans over the same bytes
- **THEN** the resolved set holds one match, and the count reflects the resolved set

#### Scenario: One value appears twice

- **WHEN** the same value appears at two distinct byte offsets
- **THEN** the resolved set holds two matches

#### Scenario: Findings are resolved once

- **WHEN** the engine merges the findings of the guards
- **THEN** it applies no further overlap resolution to spans a guard already resolved

#### Scenario: Two guards report a kind of the same name

- **WHEN** the regex PII guard and a model guard each report a `PERSON_NAME` finding over the
  same bytes of one unit
- **THEN** both findings are kept, the kind list holds `PERSON_NAME` once, and the match
  count counts both

### Requirement: Fragment offsets are document-absolute

A structured-body parser SHALL report each fragment's offset as a byte offset into the
original document, not into the fragment. A finding's span SHALL therefore be comparable
across every fragment of one unit, which is what overlap resolution and the resolved match
count require.

#### Scenario: A parser reports a fragment

- **WHEN** the JSON or CSV parser reports a fragment
- **THEN** the offset points at that fragment's value bytes inside the raw document

#### Scenario: Two values in one document each match

- **WHEN** two values in one JSON body each hold one match
- **THEN** the two spans do not overlap and the resolved match count is two

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

### Requirement: Scanner failures follow the on_error policy

When the scanner fails, or the message exceeds a configured limit, the proxy SHALL follow
the `on_error` policy. `fail_open` SHALL forward the message. `fail_close` SHALL block it.
`fail_close` SHALL be the default. The proxy SHALL increment `voidwall_errors_total` with
the outcome that was taken.

#### Scenario: Scanner fails under fail_open

- **WHEN** the scanner returns an error and `on_error` is `fail_open`
- **THEN** the proxy forwards the message
- **AND** `voidwall_errors_total{outcome="passed"}` increments

#### Scenario: Scanner fails under fail_close

- **WHEN** the scanner returns an error and `on_error` is `fail_close`
- **THEN** the proxy blocks the message
- **AND** `voidwall_errors_total{outcome="blocked"}` increments

#### Scenario: The configuration names no policy

- **WHEN** `on_error` is absent from the configuration and the scanner returns an error
- **THEN** the proxy blocks the message
- **AND** `voidwall_errors_total{outcome="blocked"}` increments
