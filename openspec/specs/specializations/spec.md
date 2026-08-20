## Purpose

A specialization is a per-endpoint adapter. It decodes a known wire format, scans only
the fields that can carry PII, and re-encodes the result correctly. It fixes two things
flat scanning cannot: encoding round-trip correctness, and false positives on opaque
identifiers.

## Requirements

### Requirement: A specialization is selected explicitly

The proxy SHALL never guess a specialization from the path, the User-Agent, or the
payload shape. The HTTP API SHALL select one with the `?specialization=<name>` query
parameter. A reverse proxy route SHALL select one with the `specialization` field.
Omitting the selection SHALL keep content-type routing.

#### Scenario: No specialization is selected

- **WHEN** a route declares no specialization
- **THEN** the proxy uses content-type routing and scans the body as-is

#### Scenario: A specialization is named

- **WHEN** a route declares `specialization = "ga4"`
- **THEN** that specialization owns the query and body decoding for the route

### Requirement: Two specializations ship with the proxy

The proxy SHALL resolve the names `ga4` and `matomo`. Any other name SHALL fail to
resolve, and config validation SHALL reject it.

#### Scenario: A known name is looked up

- **WHEN** the proxy resolves `ga4` or `matomo`
- **THEN** lookup returns that specialization

#### Scenario: An unknown name is looked up

- **WHEN** the proxy resolves any other name
- **THEN** lookup returns nothing

### Requirement: A specialization is path-agnostic

A specialization SHALL NOT match on the request path. The route configuration selects
it. An operator who serves a platform on two paths, such as `/matomo.php` and the
legacy `/piwik.php`, SHALL declare a route for each.

#### Scenario: Legacy alias path

- **WHEN** an operator serves both `/matomo.php` and `/piwik.php`
- **THEN** each path needs its own route entry naming the `matomo` specialization

### Requirement: The specialization owns the decode, scan, and encode loop

A specialization SHALL receive the raw query string and the raw body together, with the
body content type, plus a scan handle. It SHALL return the re-encoded query, the
re-encoded body with its content type, and the aggregated scan result. It SHALL never
expose a raw byte offset to the redaction code.

#### Scenario: Payload sits in the query string

- **WHEN** a tracker call carries its payload in the query string
- **THEN** the specialization returns a re-encoded query and no body change

#### Scenario: Payload sits in the body

- **WHEN** a tracker call carries its payload in the body
- **THEN** the specialization returns a re-encoded body and no query change

### Requirement: The scan handle scans one field value at a time

The scan handle SHALL expose one asynchronous method. It SHALL scan one field value and
SHALL return the matched kinds, plus the redacted replacement when redaction is enabled
for that direction. The specialization SHALL call it once per declared field and SHALL
stitch the results back into the re-encoded payload.

#### Scenario: A declared field carries PII

- **WHEN** the specialization scans a declared field holding an email address
- **THEN** the handle returns the kind and the replacement, and the specialization
  re-encodes the field

### Requirement: Nested encodings are decoded recursively

A specialization SHALL decode a nested URL field, scan its inner query parameters
through the same scan handle, and re-encode every layer. A redaction label SHALL be
encoded correctly for each layer it sits in.

#### Scenario: Redaction inside a form-encoded body

- **WHEN** a redaction label is written into an `application/x-www-form-urlencoded`
  field
- **THEN** the output carries the percent-encoded form, not the raw brackets

#### Scenario: Redaction inside a nested URL parameter

- **WHEN** a redaction label is written inside a URL that is itself a URL parameter
- **THEN** the output is encoded once per layer

### Requirement: Recursion is bounded

A specialization SHALL stop nested decoding at its depth bound and SHALL report a
recursion-limit failure. That failure SHALL be distinct from a decode failure, so an
operator can spot a pathological payload.

#### Scenario: Payload nests beyond the bound

- **WHEN** a payload nests URLs past the depth bound
- **THEN** the specialization reports a recursion-limit failure, not a decode failure

### Requirement: Field allowlists live in code

Each specialization SHALL declare its scanned fields in code, not in config. Adding a
field SHALL require a code change and a test. A field outside the allowlist SHALL pass
through unchanged. A field inside the allowlist that holds no PII SHALL also pass
through unchanged.

#### Scenario: An opaque identifier field

- **WHEN** a payload carries a field outside the allowlist, such as a generated client
  identifier
- **THEN** the specialization does not scan it and passes it through unchanged

### Requirement: Operator-acknowledged channels are not redacted

A field whose declared purpose is to carry an identifier or to override the client IP
SHALL NOT be scanned. Redacting such a field breaks the integration rather than catching
a leak. Every field not designed to carry an identifier SHALL still be scanned.

#### Scenario: A deliberate user-identifier field

- **WHEN** a payload carries the platform's own user-identifier field
- **THEN** the specialization leaves it untouched

#### Scenario: Accidental PII in a content field

- **WHEN** a payload carries an email address in a page title or an event parameter
- **THEN** the specialization scans it and detects the PII

### Requirement: The specialization replaces query and body scanning only

A specialization SHALL replace the proxy's default scanning of the query string and the
body for the matched request. It SHALL NOT replace scanning of the URL path, governed
by `scan.url_path`, nor of the request headers, governed by `scan.headers`. Those
continue through the default scanner.

#### Scenario: PII sits in the URL path

- **WHEN** a specialization is active and the URL path holds PII
- **THEN** the default scanner still inspects the path under `scan.url_path`

### Requirement: A decode failure falls back to raw scanning

When a specialization fails, the proxy SHALL fall back to the existing flat or
structured path against the raw body, and the request SHALL complete normally. The
proxy SHALL NOT consult `on_error`, because the failure is recoverable. `on_error`
governs scanner failures and limit violations only.

#### Scenario: Payload does not decode

- **WHEN** a specialization reports a decode failure
- **THEN** the proxy scans the raw body instead and completes the request

#### Scenario: on_error is fail_close

- **WHEN** a specialization fails and `on_error` is `fail_close`
- **THEN** the proxy still falls back to raw scanning rather than blocking

### Requirement: An unsupported content type falls through silently

When a specialization reports an unsupported content type, the proxy SHALL fall through
to default scanning. It SHALL emit no log line and SHALL increment no error counter.
This is the normal case on the response direction, where a tracker answers with a pixel
or a 204.

#### Scenario: Tracker responds with an image

- **WHEN** a specialization is offered a `image/gif` response body
- **THEN** it reports an unsupported content type and nothing is logged or counted

### Requirement: A specialization failure is logged at a bounded rate and always counted

The proxy SHALL emit at most one log line per specialization per minute. The line SHALL
name the specialization and the failure category, and SHALL never carry payload
content. The proxy SHALL increment `pii_proxy_specialization_errors_total` on every
failure, with no rate limit.

#### Scenario: Many failures in one minute

- **WHEN** a specialization fails many times inside one minute
- **THEN** the proxy logs once and increments the counter once per failure

#### Scenario: A failure is logged

- **WHEN** the proxy logs a specialization failure
- **THEN** the line names the specialization and the reason, and carries no payload text
