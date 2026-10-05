## Purpose

These are the cross-cutting security invariants the proxy enforces in code. A PII value
must never leave the process, and the operational surface must not sit on the data-plane
port. Deployment guidance, such as a Kubernetes security context or a NetworkPolicy, is
not covered here. It lives in `ARCHITECTURE.md`, because the code does not enforce it.

## Requirements

### Requirement: A log line never carries a PII value

The proxy SHALL log the PII kind name and the match count only. No log line, at any
level, SHALL carry matched text, a body fragment, or a redaction input.

#### Scenario: A detection is logged

- **WHEN** the proxy logs a detection
- **THEN** the line names the kind and the count and carries no matched text

#### Scenario: A scan failure is logged

- **WHEN** the proxy logs a scan failure
- **THEN** the line names the reason and carries no payload

### Requirement: A PII value never reaches a metric

Every metric label SHALL hold a kind name, a guard name, a mode, a route, a direction, a
method, a status, an outcome, or a reason. No label SHALL ever hold a matched value. A
guard name SHALL be the name configuration gave the guard, never a value taken from a
request, a response, or a detection.

#### Scenario: A detection increments a counter

- **WHEN** the proxy increments the detection counter
- **THEN** the `pii_kind` label holds the kind name and no value

#### Scenario: A guard detection increments a counter

- **WHEN** the proxy increments `voidwall_detections_total`
- **THEN** the `guard` label holds the guard's configured name and no value

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

The proxy SHALL drop the buffered body once the scan is done. It SHALL not hold a body
longer than the request needs, and SHALL avoid an unnecessary copy. A structured body
SHALL NOT be retained after parsing: the scanner reads the parsed fragments, so the
original document bytes are released when parsing ends.

#### Scenario: A request completes

- **WHEN** the proxy finishes forwarding a request
- **THEN** the buffered body is released

#### Scenario: A structured body is parsed

- **WHEN** a JSON or CSV body is parsed into fragments
- **THEN** the original document bytes are not held beyond the parse

### Requirement: The admin surface sits on its own port

The admin listener SHALL bind an address separate from every data-plane listener. It
SHALL default to `127.0.0.1:9090`, so it is not reachable from outside the pod unless
the operator changes it.

#### Scenario: Default deployment

- **WHEN** the operator sets no admin address
- **THEN** the admin surface binds the loopback interface only

### Requirement: The scanner configuration is not exposed

The proxy SHALL NOT serve an endpoint that returns the scanner configuration. The HTTP
API listener SHALL serve no route that reports the configured detect list, the ignore
list, the custom patterns, or the built-in detection surface.

#### Scenario: A client queries the detection surface

- **WHEN** a client calls a route that reports the detection surface or the scanner
  configuration
- **THEN** no such route exists on the API listener

### Requirement: The API listener sends no cross-origin header

The HTTP API listener SHALL NOT send an `Access-Control-Allow-Origin` header or any
other CORS response header. A browser on another origin therefore cannot call the
listener directly. Cross-origin access is the deployment's job, at the gateway that
already supplies the authentication the listener does not.

#### Scenario: A browser on another origin calls the API

- **WHEN** a client sends `POST /v1/scan` carrying an `Origin` header
- **THEN** the response carries no `Access-Control-Allow-Origin` header

#### Scenario: A browser sends a preflight request

- **WHEN** a client sends `OPTIONS /v1/scan`
- **THEN** the listener does not answer with CORS permission headers

### Requirement: An invalid configuration stops the start

The proxy SHALL refuse to start on an invalid config. It SHALL NOT drop an invalid entry
and continue. Silently dropping a declared PII definition would weaken detection without
telling the operator.

Enabling no guard SHALL NOT be treated as an invalid config. It SHALL warn at startup
instead, because it states a deployment with nothing to inspect rather than a
configuration the proxy cannot honour.

#### Scenario: A custom pattern does not compile

- **WHEN** one `[[builtin_guards.pii.custom]]` pattern fails to compile
- **THEN** the proxy exits with an error instead of running without that definition

#### Scenario: No guard is enabled

- **WHEN** the config enables a mode and no guard
- **THEN** the proxy starts and logs a warning naming the empty guard set
