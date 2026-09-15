## MODIFIED Requirements

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
