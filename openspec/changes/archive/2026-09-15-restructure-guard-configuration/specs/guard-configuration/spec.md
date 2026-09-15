## Purpose

States how a guard is declared, enabled, given a scan surface, and selected per route,
and how configuration distinguishes a guard that ships with Voidwall from one an
operator configures.

## ADDED Requirements

### Requirement: A built-in guard is declared in its own section

A guard that ships with Voidwall SHALL be declared under `[builtin_guards.<name>]`,
where `<name>` is drawn from a fixed set the build defines. `pii` SHALL be the only
name in that set. A built-in guard SHALL NOT carry a `type` field: its section key
identifies it.

A built-in guard SHALL be a singleton. The section shape SHALL admit one instance per
name, so two instances of one built-in guard SHALL NOT be expressible.

#### Scenario: The built-in PII guard is declared

- **WHEN** the config holds a `[builtin_guards.pii]` table
- **THEN** the proxy builds the regex PII guard from it

#### Scenario: An unknown built-in name

- **WHEN** the config holds a `[builtin_guards.jailbreak]` table
- **THEN** validation fails naming the unknown built-in guard

#### Scenario: A built-in guard carries a type field

- **WHEN** `[builtin_guards.pii]` sets `type`
- **THEN** the schema rejects the file

### Requirement: A built-in guard section is enabled unless it says otherwise

`enabled` SHALL default to true when the guard's section is present. `enabled = false`
SHALL build no guard and SHALL load none of its resources. An absent section SHALL build
no guard.

An operator who writes a guard section therefore gets a guard that runs. Disabling one
SHALL be explicit.

#### Scenario: Section present without the enabled key

- **WHEN** `[builtin_guards.pii]` names countries and languages but omits `enabled`
- **THEN** the guard is built and inspects traffic

#### Scenario: Section present and disabled

- **WHEN** `[builtin_guards.pii]` sets `enabled = false`
- **THEN** no scanner thread starts and no gazetteer is loaded

#### Scenario: Section absent

- **WHEN** the config holds no `[builtin_guards.pii]` table
- **THEN** no PII guard is built

### Requirement: Built-in guard names are reserved

A name in the built-in set SHALL NOT be taken by a configured guard. Validation SHALL
reject a collision, naming the reserved name, so that one flat name space identifies
every guard a route can select.

#### Scenario: A configured guard takes a reserved name

- **WHEN** the config declares a guard named `pii` outside `[builtin_guards]`
- **THEN** validation fails naming `pii` as reserved

### Requirement: A guard declares its scan surface

Each guard SHALL carry a `surface` table holding `url_path`, `query_params`, and `body`,
each defaulting to true. The surface SHALL be the configuration form of the guard's
declared interest: the engine SHALL pass a guard only the units its surface admits.

The surface SHALL be per guard, not global. A unit kind no enabled guard admits SHALL
NOT be built.

The surface SHALL NOT name headers. Which header values a message is decoded into is a
property of the traffic rather than of a detector, so it SHALL be declared per route —
see "A route names the headers it exposes to detection".

#### Scenario: Default surface

- **WHEN** a guard section omits `surface`
- **THEN** the guard inspects the URL path, the query string, and the body

#### Scenario: A target is disabled for one guard

- **WHEN** a guard sets `surface.body = false`
- **THEN** that guard is not called with the body unit

#### Scenario: The surface names a header

- **WHEN** a guard sets `surface.headers`
- **THEN** the schema rejects the file

### Requirement: A route names the headers it exposes to detection

A reverse proxy route MAY carry `headers`, a list of header names, defaulting to empty.
A named header's value SHALL be decoded into a unit in both directions, and every guard
selected for that route SHALL see it. A header the route does not name SHALL NOT be
decoded into a unit at all.

The list SHALL belong to the route and SHALL NOT be set per guard or globally, so one
place answers which of a route's headers detection reads.

#### Scenario: Route names a header

- **WHEN** a route sets `headers = ["authorization"]` and a request carries that header
- **THEN** that header value is scanned and no other header is

#### Scenario: Route names no header

- **WHEN** a route declares no `headers` key
- **THEN** no header unit is built for that route

#### Scenario: A route that selects no guard names headers

- **WHEN** a route sets `guards = []` and names a header
- **THEN** no guard runs, so the header value is not inspected

### Requirement: A route selects guards by name

A reverse proxy route MAY carry `guards`, a list of guard names. The named guards SHALL
run for that route and no other guard SHALL. A route without `guards` SHALL use every
enabled guard. `guards = []` SHALL select none, which SHALL leave that route's traffic
uninspected.

A name in `guards` that matches no enabled guard SHALL fail validation.

#### Scenario: Route names a guard

- **WHEN** a route sets `guards = ["pii"]`
- **THEN** the PII guard runs for that route

#### Scenario: Route omits the list

- **WHEN** a route declares no `guards` key
- **THEN** every enabled guard runs for that route

#### Scenario: Route opts out

- **WHEN** a route sets `guards = []`
- **THEN** no guard runs and the message is forwarded uninspected

#### Scenario: Route names an unknown guard

- **WHEN** a route sets `guards = ["injection"]` and no such guard is enabled
- **THEN** validation fails naming the unknown guard

### Requirement: No enabled guard warns rather than stops the start

When configuration enables no guard, the proxy SHALL log one warning at startup and
SHALL continue. It SHALL NOT refuse to start. This matches the modes, where a config
that enables nothing starts and serves nothing.

#### Scenario: Every guard is disabled

- **WHEN** the config enables a proxy mode and no guard
- **THEN** the proxy starts, logs a warning that no guard is enabled, and forwards
  traffic uninspected

### Requirement: A guard name is operator-supplied and bounded by configuration

A guard SHALL carry a name that configuration supplies rather than a fixed string the
build defines. The set of guard names SHALL be fixed when configuration is loaded, so
it SHALL NOT grow with traffic.

A guard name SHALL NOT be derived from a request, a response, or any detected value.

#### Scenario: A finding names its guard

- **WHEN** a guard reports a finding
- **THEN** the finding names the guard by its configured name

#### Scenario: A guard name never comes from traffic

- **WHEN** the proxy scans a message
- **THEN** no guard name is taken from the message, its headers, or a matched value
