## Purpose

These are the cross-cutting security invariants the proxy enforces in code. A PII value
must never leave the process, and the operational surface must not sit on the data-plane
port. Deployment guidance, such as a Kubernetes security context or a NetworkPolicy, is
not covered here. It lives in `ARCHITECTURE.md`, because the code does not enforce it.

## Requirements

### Requirement: A PII value never reaches a log

The proxy SHALL log the PII kind name and the match count only. No log line, at any
level, SHALL carry matched text, a body fragment, or a redaction input.

#### Scenario: A detection is logged

- **WHEN** the proxy logs a detection
- **THEN** the line names the kind and the count and carries no matched text

#### Scenario: A specialization fails to decode

- **WHEN** the proxy logs a specialization decode failure
- **THEN** the line names the specialization and the reason and carries no payload

### Requirement: A PII value never reaches a metric

Every metric label SHALL hold a kind name, a mode, a route, a direction, a method, a
status, a specialization, an outcome, or a reason. No label SHALL ever hold a matched
value.

#### Scenario: A detection increments a counter

- **WHEN** the proxy increments the detection counter
- **THEN** the `pii_kind` label holds the kind name and no value

### Requirement: A PII value never reaches an error response

A block response SHALL list detected kind names. It SHALL NOT carry the matched text. An
error response SHALL NOT echo the body that produced it.

#### Scenario: A request is blocked

- **WHEN** the proxy returns a 403 for a detection
- **THEN** the body lists the kinds and carries no matched value

#### Scenario: A body fails to parse

- **WHEN** the API returns 400 for a malformed body
- **THEN** the response does not echo the body content

### Requirement: Body buffers are released promptly

The proxy SHALL drop the buffered body once the scan and the actions are done. It SHALL
not hold a body longer than the request needs, and SHALL avoid an unnecessary copy.

#### Scenario: A request completes

- **WHEN** the proxy finishes forwarding a request
- **THEN** the buffered body is released

### Requirement: The admin surface sits on its own port

The admin listener SHALL bind an address separate from every data-plane listener. It
SHALL default to `127.0.0.1:9090`, so it is not reachable from outside the pod unless
the operator changes it.

#### Scenario: Default deployment

- **WHEN** the operator sets no admin address
- **THEN** the admin surface binds the loopback interface only

### Requirement: The scanner configuration is not exposed

The proxy SHALL NOT serve an endpoint that returns the scanner configuration. `/v1/info`
SHALL return the built-in kind labels and languages only, and SHALL NOT return the
configured detect list, ignore list, or custom patterns.

#### Scenario: A client queries the detection surface

- **WHEN** a client calls `/v1/info`
- **THEN** the response names the built-in kinds and languages, and no configured value

### Requirement: An invalid configuration stops the start

The proxy SHALL refuse to start on an invalid config. It SHALL NOT drop an invalid entry
and continue. Silently dropping a declared PII definition would weaken detection without
telling the operator.

#### Scenario: A custom pattern does not compile

- **WHEN** one `[[pii.custom]]` pattern fails to compile
- **THEN** the proxy exits with an error instead of running without that definition
