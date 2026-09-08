## ADDED Requirements

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

## MODIFIED Requirements

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
