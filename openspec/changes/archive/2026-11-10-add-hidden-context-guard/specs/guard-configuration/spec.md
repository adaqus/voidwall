## MODIFIED Requirements

### Requirement: A built-in guard is declared in its own section

A guard that ships with Voidwall SHALL be declared under `[builtin_guards.<name>]`,
where `<name>` is drawn from a fixed set the build defines. `pii` and `hidden_context`
SHALL be the only names in that set. A built-in guard SHALL NOT carry a `type` field: its
section key identifies it.

A built-in guard SHALL be a singleton. The section shape SHALL admit one instance per
name, so two instances of one built-in guard SHALL NOT be expressible.

#### Scenario: The built-in PII guard is declared

- **WHEN** the config holds a `[builtin_guards.pii]` table
- **THEN** the proxy builds the regex PII guard from it

#### Scenario: The built-in hidden context guard is declared

- **WHEN** the config holds a `[builtin_guards.hidden_context]` table with one marker
- **THEN** the proxy builds the `hidden_context` guard from it

#### Scenario: An unknown built-in name

- **WHEN** the config holds a `[builtin_guards.jailbreak]` table
- **THEN** validation fails naming the unknown built-in guard

#### Scenario: A built-in guard carries a type field

- **WHEN** `[builtin_guards.pii]` sets `type`
- **THEN** the schema rejects the file

### Requirement: A guard declares its scan surface

Each guard except `hidden_context` SHALL carry a `surface` table holding `url_path`,
`query_params`, `body`, and `headers`. The surface SHALL be the configuration form of the
guard's declared interest: the engine SHALL pass a guard only the units its surface
admits.

The surface SHALL be per guard, not global. A unit kind no enabled guard admits SHALL
NOT be built. A built-in guard's surface SHALL default `url_path`, `query_params`, `body`,
and `headers` to true.

`headers` SHALL be a boolean and SHALL NOT be a list of header names. Which header values a
message is decoded into is a property of the traffic rather than of a detector, so the set
SHALL be declared per route — see "A route names the headers it exposes to detection". The
guard's boolean SHALL decide only whether that guard sees the header units the route built.

A surface that disables every target SHALL fail validation, because it describes a guard
that can never be called.

The `hidden_context` guard's interest SHALL be fixed to the response body. Its section
SHALL NOT accept a `surface` key.

#### Scenario: Default surface

- **WHEN** a built-in guard section omits `surface`
- **THEN** the guard inspects the URL path, the query string, the body, and every header
  value the route named

#### Scenario: A target is disabled for one guard

- **WHEN** a guard sets `surface.body = false`
- **THEN** that guard is not called with the body unit

#### Scenario: One guard declines header units and another admits them

- **WHEN** a route names a header, one selected guard sets `surface.headers = false`, and
  another selected guard admits them
- **THEN** that header value is decoded into a unit, the admitting guard is called with
  it, and the declining guard is not

#### Scenario: Every selected guard declines header units

- **WHEN** a route names a header and every guard it selected sets
  `surface.headers = false`
- **THEN** that header value is never decoded into a unit, because a unit kind no
  selected guard admits is not built

#### Scenario: The surface names a header

- **WHEN** a guard sets `surface.headers` to a list of header names
- **THEN** the schema rejects the file

#### Scenario: Every target is disabled

- **WHEN** a guard disables `url_path`, `query_params`, `body`, and `headers`
- **THEN** validation fails naming the guard

#### Scenario: The hidden context guard sets a surface

- **WHEN** `[builtin_guards.hidden_context]` sets `surface`
- **THEN** the schema rejects the file

## ADDED Requirements

### Requirement: A guard inspects the directions its kind fixes

Each guard SHALL be passed units of the directions it inspects and no other. The `pii`
guard and every model guard SHALL inspect both requests and responses. The
`hidden_context` guard SHALL inspect responses only. No setting SHALL change a guard's
directions.

#### Scenario: A request on a route selecting both built-in guards

- **WHEN** a route selects `pii` and `hidden_context` and a request holds an email
  placeholder and a marker
- **THEN** the `pii` guard is called with the request units, the `hidden_context` guard
  is not called, and the request is blocked with `kinds` `["EMAIL"]`

#### Scenario: A response on the same route

- **WHEN** the upstream response on that route holds a marker and no PII
- **THEN** both guards are called with the response body, and the response is blocked
  with `kinds` `["HIDDEN_CONTEXT"]`
