## Purpose

An operator can add their own PII definitions on top of the built-in kinds. Each
definition is a regex with a chosen label and optional context keywords. A match
behaves exactly like a built-in kind everywhere it surfaces.

## Requirements

### Requirement: A custom definition carries four fields

A `[[builtin_guards.pii.custom]]` entry SHALL carry a `label` and a `pattern`, both
required. It MAY carry `keywords` and a `country`. `country` SHALL default to
`International`.

A custom definition SHALL belong to the guard that runs it, so an entry declared outside
a guard section SHALL be rejected by the schema.

#### Scenario: Minimal definition

- **WHEN** an entry names a label and a pattern only
- **THEN** the entry is accepted with no keywords and the `International` country

#### Scenario: An entry sits outside the guard

- **WHEN** the config declares `[[pii.custom]]` at the top level
- **THEN** the schema rejects the file

### Requirement: The pattern must compile for both engines

A `pattern` SHALL compile in the `regex` crate and in Vectorscan. It SHALL therefore
carry no backreference and no lookaround. A compilation failure SHALL surface as a
startup error.

#### Scenario: Pattern uses a lookahead

- **WHEN** a pattern carries a construct Vectorscan cannot compile
- **THEN** the scanner build fails and the proxy refuses to start

### Requirement: Keywords gate the match and stay outside the span

When `keywords` is non-empty, a match SHALL require one of those keywords just before
the pattern, with a permissive separator between them. The reported span SHALL cover
the pattern only, and SHALL NOT include the keyword.

#### Scenario: Keyword is present

- **WHEN** a definition declares keywords and one appears just before a pattern match
- **THEN** the detector reports a match spanning the pattern only

#### Scenario: Keyword is absent

- **WHEN** a definition declares keywords and none appears before the pattern
- **THEN** the detector reports no match

### Requirement: Country scope drops out-of-scope entries at build time

An entry whose `country` is outside the scanner's enabled country set SHALL be dropped
when the scanner is built.

#### Scenario: Country is not enabled

- **WHEN** an entry names a country the scanner does not enable
- **THEN** the entry is dropped and never matches

### Requirement: Custom definitions are independent of detect and ignore

`builtin_guards.pii.detect` and `builtin_guards.pii.ignore` SHALL apply to built-in
kinds only. A custom entry SHALL run regardless of either list. The only way to disable
one SHALL be to remove it from the config, or to disable the guard that owns it.

#### Scenario: detect names a closed set

- **WHEN** `detect` names a closed set of built-in kinds
- **THEN** every configured custom definition still runs

#### Scenario: The owning guard is disabled

- **WHEN** `builtin_guards.pii` sets `enabled = false`
- **THEN** no custom definition declared under it runs

### Requirement: CUSTOM is reserved

The literal `Custom` kind SHALL NOT appear in `detect` or in `ignore`. Validation SHALL
reject it, naming the field.

#### Scenario: detect lists Custom

- **WHEN** `detect` or `ignore` lists `Custom`
- **THEN** validation fails naming the field and the reserved value

### Requirement: The operator label surfaces wherever a kind name appears

A custom match SHALL report the operator's label in the Prometheus `pii_kind` label, in
the `kinds` list of a block response, and in the `kinds` array of `/v1/scan`.

#### Scenario: A custom definition matches in the reverse proxy

- **WHEN** a custom definition matches a forwarded request
- **THEN** the proxy blocks it and the `kinds` array of the 403 body carries the
  operator's label

#### Scenario: A custom definition matches on the HTTP API

- **WHEN** a custom definition matches a body posted to `/v1/scan`
- **THEN** the `kinds` array lists the operator's label

#### Scenario: A custom match is counted

- **WHEN** a custom definition matches
- **THEN** `voidwall_pii_detections_total` carries the operator's label as `pii_kind`

### Requirement: Label cardinality stays bounded

The entry count SHALL be capped at 64. Labels are operator-supplied config, so metric
cardinality stays under operator control.

#### Scenario: Config exceeds the cap

- **WHEN** the config holds more than 64 custom entries
- **THEN** validation fails naming the count and the cap

### Requirement: A label is config, never a matched value

A label SHALL be treated as operator configuration. Publishing it in a log, a metric,
or a response SHALL NOT break the rule that a PII value never leaves the process.

#### Scenario: A custom match is logged

- **WHEN** the proxy logs a custom detection
- **THEN** the line carries the operator's label and no matched text
