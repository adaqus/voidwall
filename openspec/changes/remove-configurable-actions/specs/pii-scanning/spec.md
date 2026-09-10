## ADDED Requirements

### Requirement: Scanner failures follow the on_error policy

When the scanner fails, or the message exceeds a configured limit, the proxy SHALL follow
the `on_error` policy. `fail_open` SHALL forward the message. `fail_close` SHALL block it.
`fail_open` SHALL be the default. The proxy SHALL increment `voidwall_errors_total` with
the outcome that was taken.

#### Scenario: Scanner fails under fail_open

- **WHEN** the scanner returns an error and `on_error` is `fail_open`
- **THEN** the proxy forwards the message
- **AND** `voidwall_errors_total{outcome="passed"}` increments

#### Scenario: Scanner fails under fail_close

- **WHEN** the scanner returns an error and `on_error` is `fail_close`
- **THEN** the proxy blocks the message
- **AND** `voidwall_errors_total{outcome="blocked"}` increments

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

## MODIFIED Requirements

### Requirement: A guard returns findings only

A guard SHALL be one detection concern. It SHALL return a list of findings and SHALL do
nothing else: it SHALL NOT block the message, change it, or write a metric. Each finding
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

## REMOVED Requirements

### Requirement: The engine aggregates the guards

**Reason**: The short-circuit rule was written as "a redact or header outcome SHALL NOT
stop the engine", and both outcomes are deleted. The rule survives as *The engine
aggregates the guards and owns the stage order*, expressed as whether the caller blocks or
reports. Every other clause is carried over unchanged.
**Migration**: None. The engine behaves as before: it short-circuits for a block and
nothing else.

### Requirement: Redaction preserves the document structure

**Reason**: Redaction is deleted. Nothing rewrites a scanned document, so there is no
structure to preserve on the way out. The requirement also carried the only statement that
fragment offsets are document-absolute; that clause survives as *Fragment offsets are
document-absolute*, which ties it to overlap resolution rather than to rewriting.
**Migration**: None. Structured parsing is unchanged: a JSON key path and a CSV column
header still reach the scanner as context, and offsets still point into the raw document.
