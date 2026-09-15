## MODIFIED Requirements

### Requirement: Scanner thread count

`builtin_guards.pii.scanner_threads` SHALL be at least 1 when it is set. When it is
absent, the effective count SHALL come from the available parallelism: the core count
capped at 4 when there are 8 cores or fewer, and half the core count otherwise.

The setting SHALL belong to the guard that owns the scanner, not to a global section.

#### Scenario: Explicit zero

- **WHEN** `scanner_threads` is 0
- **THEN** validation fails

#### Scenario: Setting is absent

- **WHEN** `scanner_threads` is absent
- **THEN** the effective count is at least 1 and follows the core-count rule

#### Scenario: The setting sits outside the guard

- **WHEN** `scanner_threads` is set at the top level rather than under the guard
- **THEN** the schema rejects the file

### Requirement: detect and ignore are mutually exclusive

`builtin_guards.pii.detect` and `builtin_guards.pii.ignore` SHALL NOT both be set. Every
kind named in `detect` SHALL be reachable from the countries configured for that guard.

#### Scenario: Both lists are set

- **WHEN** the guard sets `detect` and `ignore`
- **THEN** validation fails

#### Scenario: A kind is unreachable from the countries

- **WHEN** `detect` names a kind no configured country can produce
- **THEN** validation fails naming that kind

### Requirement: User-defined PII entries are validated

Validation SHALL accept at most 64 `[[builtin_guards.pii.custom]]` entries. Each entry
SHALL carry a non-empty label and a non-empty pattern. A label SHALL NOT collide with a
built-in kind label, and SHALL NOT repeat inside the file.

#### Scenario: Too many entries

- **WHEN** the config holds more than 64 custom entries
- **THEN** validation fails naming the count and the cap

#### Scenario: Empty label or pattern

- **WHEN** a custom entry carries an empty label, or an empty pattern
- **THEN** validation fails naming the entry

#### Scenario: Label collides with a built-in kind

- **WHEN** a custom label equals a built-in `PiiKind` label
- **THEN** validation fails naming the collision

#### Scenario: Duplicate custom label

- **WHEN** two custom entries carry the same label
- **THEN** validation fails naming the duplicate

### Requirement: A validation failure is categorised

A validation failure SHALL carry one of five categories: `file`, `toml parse`, `schema`,
`semantic`, or `scanner build`. The message SHALL name the category and the cause.

A reserved guard name, an unknown guard in a route's `guards` list, and an unknown
built-in guard name SHALL each carry the `semantic` category.

#### Scenario: The file is missing

- **WHEN** the named path does not exist
- **THEN** the failure carries the `file` category

#### Scenario: The TOML does not parse

- **WHEN** the file holds a TOML syntax error
- **THEN** the failure carries the `toml parse` category

#### Scenario: A field is missing or of the wrong type

- **WHEN** the TOML parses but does not match the schema
- **THEN** the failure carries the `schema` category

#### Scenario: A rule fails

- **WHEN** the schema matches but a validation rule fails
- **THEN** the failure carries the `semantic` category

#### Scenario: A route names an unknown guard

- **WHEN** a route's `guards` list names a guard that is not enabled
- **THEN** the failure carries the `semantic` category and names the guard

#### Scenario: A custom pattern does not compile

- **WHEN** a `[[builtin_guards.pii.custom]]` pattern fails to compile
- **THEN** the failure carries the `scanner build` category and names the label

### Requirement: There is no partial start

The proxy SHALL NOT skip an invalid entry and continue. An invalid config SHALL stop
the start. Dropping a declared PII definition silently is a security regression.

#### Scenario: One custom entry is invalid

- **WHEN** one `[[builtin_guards.pii.custom]]` entry fails validation
- **THEN** the proxy refuses to start, rather than dropping that entry

## ADDED Requirements

### Requirement: Ingest limits are set once for every guard

`max_body_size`, `content_types`, and `on_error` SHALL be top-level keys. They SHALL
govern how a message is admitted and decoded before any guard sees it, so they SHALL
apply to every guard alike and SHALL NOT be set per guard.

`max_body_size` SHALL default to 1048576 bytes. `on_error` SHALL default to
`fail_close`.

#### Scenario: Limits are shared

- **WHEN** the config sets `max_body_size` at the top level and enables a guard
- **THEN** that limit applies to every guard, in every mode

#### Scenario: A limit is set under a guard

- **WHEN** a guard section sets `max_body_size`
- **THEN** the schema rejects the file

## REMOVED Requirements

### Requirement: A per-route scan override fully replaces the defaults

**Reason**: The `scan` table no longer exists. Its scan-surface fields moved to a
per-guard `surface`, and its limit fields moved to top-level ingest keys, so a route has
no scan table left to replace.

**Migration**: Replace a route's `scan` table with `guards`, a list of guard names. A
route that used `scan` to switch detection off for one path SHALL use `guards = []`. A
route that used `scan` to narrow the inspected surface SHALL declare a guard with that
surface and name it in `guards`.
