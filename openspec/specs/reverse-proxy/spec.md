## Purpose

The reverse proxy accepts HTTP requests, inspects them for PII, applies the configured
actions, and forwards them to a configured upstream. It inspects the upstream response
on the way back.

## Requirements

### Requirement: Routing matches the longest path prefix

The proxy SHALL select the route whose `path_prefix` is the longest prefix of the
request path. It SHALL return 404 when no route matches. Routing SHALL use the path
only. The proxy SHALL NOT route on the Host header.

#### Scenario: Two prefixes both match

- **WHEN** the path matches `/api` and `/api/v2`, and the request path starts with
  `/api/v2`
- **THEN** the proxy selects the `/api/v2` route

#### Scenario: No route matches

- **WHEN** the request path matches no configured prefix
- **THEN** the proxy returns 404 and records the request metric with status 404

### Requirement: One pooled client per upstream

The proxy SHALL build one pooling HTTP client per distinct upstream. The idle timeout
SHALL be 30 seconds. Two routes naming the same upstream SHALL share one client.

#### Scenario: Two routes share an upstream

- **WHEN** two routes name the same upstream
- **THEN** the proxy builds one client and both routes use it

### Requirement: The request body is buffered before the scan

The proxy SHALL buffer the request body up to the route's `max_body_size` before it
scans. An oversize body SHALL follow the `on_error` policy.

#### Scenario: Body fits the limit

- **WHEN** the request body is within `max_body_size`
- **THEN** the proxy buffers it and scans it

### Requirement: Request and response are scanned independently

The proxy SHALL apply the request action list to the incoming request, and the response
action list to the upstream response. An empty action list for a direction SHALL
disable both the scan and the actions for that direction, and SHALL leave the other
direction untouched.

#### Scenario: Request actions only

- **WHEN** the request action list is non-empty and the response action list is empty
- **THEN** the proxy scans the request and forwards the upstream response untouched

#### Scenario: Response actions only

- **WHEN** the request action list is empty and the response action list is non-empty
- **THEN** the proxy forwards the request untouched and scans the upstream response

### Requirement: Body scanning respects the content type and the target flags

The proxy SHALL scan a body only when `scan.body` is true, the body is non-empty, and
the content type appears in `scan.content_types`.

#### Scenario: Content type is outside the allowlist

- **WHEN** a request body carries a content type outside `scan.content_types`
- **THEN** the proxy does not scan the body

#### Scenario: Body is empty

- **WHEN** a request carries no body bytes
- **THEN** the proxy does not scan the body

### Requirement: The URL path, the query, and listed headers are scannable

The proxy SHALL scan the URL path when `scan.url_path` is true, the query string when
`scan.query_params` is true, and each header named in `scan.headers`.

#### Scenario: PII sits in the query string

- **WHEN** `scan.query_params` is true and the query holds an email address
- **THEN** the proxy detects it and applies the request actions

### Requirement: Redaction rewrites the forwarded request

When the redact action applies, the proxy SHALL forward the redacted body, and SHALL
rebuild the request URI from the redacted path and the redacted query. It SHALL replace
each redacted header value.

#### Scenario: PII sits in the path and the body

- **WHEN** the scan redacts both the path and the body
- **THEN** the forwarded request carries the rebuilt URI and the redacted body

### Requirement: Hop-by-hop headers are stripped

The proxy SHALL remove the hop-by-hop headers before it forwards: `connection`,
`keep-alive`, `proxy-authenticate`, `proxy-authorization`, `te`, `trailers`,
`transfer-encoding`, and `upgrade`. The comparison SHALL ignore case.

#### Scenario: Client sends a hop-by-hop header

- **WHEN** a request carries `Transfer-Encoding`
- **THEN** the forwarded request does not carry it

### Requirement: A route may override the scan settings

A route-level `scan` table SHALL replace the mode defaults completely. A route without
one SHALL use the mode defaults.

#### Scenario: Route sets its own scan table

- **WHEN** a route declares `scan`
- **THEN** that route uses it alone, with no merge against the mode defaults

### Requirement: Every request records metrics

The proxy SHALL record a request metric carrying the mode, the route, the method, and
the status. It SHALL observe the request duration per mode and route.

#### Scenario: A request completes

- **WHEN** the proxy answers a request
- **THEN** it increments the request counter and observes the duration

### Requirement: The proxy serves plain HTTP only

The reverse proxy listener SHALL accept plain HTTP. TLS termination is not built. The
`tls` table parses and validates, and nothing reads it.

#### Scenario: TLS is enabled in the config

- **WHEN** `reverse_proxy.tls.enabled` is true
- **THEN** the listener still accepts plain HTTP, because the TLS path does not exist

### Requirement: The proxy shuts down gracefully

The proxy SHALL stop when the shutdown token is cancelled, and SHALL drain the requests
in flight.

#### Scenario: Shutdown signal arrives

- **WHEN** the cancellation token is triggered
- **THEN** the listener stops accepting connections and the in-flight requests finish
