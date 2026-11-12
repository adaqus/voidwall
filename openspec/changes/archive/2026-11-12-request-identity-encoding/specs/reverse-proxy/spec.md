## ADDED Requirements

### Requirement: The proxy asks the upstream for an uncompressed response

When `reverse_proxy.response.scan` is on, the proxy SHALL forward every request with
exactly one `Accept-Encoding` header, whose value is `identity`, on every route and both
route formats. It SHALL replace every `Accept-Encoding` value the client sent, and SHALL
add the header when the client sent none. When `reverse_proxy.response.scan` is off, the
proxy SHALL forward the client's `Accept-Encoding` unchanged, and SHALL add none.

#### Scenario: The client asks for a compressed response

- **WHEN** response scan is on and a client sends `Accept-Encoding: gzip, deflate, br`
- **THEN** the upstream receives `Accept-Encoding: identity` and no other
  `Accept-Encoding` value

#### Scenario: The client sends no Accept-Encoding

- **WHEN** response scan is on and a client sends no `Accept-Encoding` header
- **THEN** the upstream receives `Accept-Encoding: identity`

#### Scenario: An openai-chat route

- **WHEN** response scan is on and a client sends `Accept-Encoding: gzip` to a route with
  `format = "openai-chat"`
- **THEN** the upstream receives `Accept-Encoding: identity`

#### Scenario: A route that selects no guard

- **WHEN** response scan is on and a client sends `Accept-Encoding: gzip` to a route with
  `guards = []`
- **THEN** the upstream receives `Accept-Encoding: identity`

#### Scenario: Response scan off

- **WHEN** response scan is off and a client sends `Accept-Encoding: gzip`
- **THEN** the upstream receives `Accept-Encoding: gzip`

#### Scenario: Response scan off, no Accept-Encoding

- **WHEN** response scan is off and a client sends no `Accept-Encoding` header
- **THEN** the upstream receives no `Accept-Encoding` header

### Requirement: A compressed response body is unscannable content

When response scan is on and the route scans the response body, a non-empty upstream
response body with a `Content-Encoding` other than `identity` SHALL be unscannable
content, on both route formats. A route scans the response body when a guard it selects
reads body units and, on a route without `format`, the body's content type is in
`content_types`. The proxy SHALL decide this from the response headers, before it reads
the body. Under `fail_close` the proxy SHALL
answer 422 and no part of the upstream body SHALL reach the client: on a route without
`format` the body is exactly `{"error":"unscannable content"}`, and on a route with
`format = "openai-chat"` it is the OpenAI error shape with `error.code`
`unscannable_content`. Under `fail_open` the proxy SHALL forward the response unscanned,
as it does with response scan off. Either way `voidwall_errors_total` SHALL increment
with `reason="unscannable_content"` and the `outcome` the message took.

A route that scans no response body, such as a route with `guards = []`, or a route
without `format` that gets a body type not in `content_types`, SHALL forward a
compressed response body as it forwards any other.

#### Scenario: Compressed JSON on a route without format, under fail_close

- **WHEN** the upstream answers `Content-Type: application/json` with
  `Content-Encoding: gzip` on a route without `format`, and `on_error` is `fail_close`
- **THEN** the proxy answers 422 with the body `{"error":"unscannable content"}`
- **AND** `voidwall_errors_total` increments with `outcome="blocked"` and
  `reason="unscannable_content"`

#### Scenario: Compressed JSON on a route without format, under fail_open

- **WHEN** the upstream answers `Content-Type: application/json` with
  `Content-Encoding: gzip` on a route without `format`, and `on_error` is `fail_open`
- **THEN** the client receives the upstream status, headers, and compressed body
  unchanged
- **AND** `voidwall_errors_total` increments with `outcome="passed"` and
  `reason="unscannable_content"`

#### Scenario: Compressed JSON on an openai-chat route, under fail_close

- **WHEN** the upstream answers `Content-Type: application/json` with
  `Content-Encoding: br` on a route with `format = "openai-chat"`, and `on_error` is
  `fail_close`
- **THEN** the proxy answers 422 with `error.code` `unscannable_content`

#### Scenario: Compressed JSON on an openai-chat route, under fail_open

- **WHEN** the upstream answers `Content-Type: application/json` with
  `Content-Encoding: br` on a route with `format = "openai-chat"`, and `on_error` is
  `fail_open`
- **THEN** the client receives the upstream body unchanged
- **AND** `voidwall_errors_total` increments with `outcome="passed"` and
  `reason="unscannable_content"`

#### Scenario: Identity is not compressed

- **WHEN** the upstream answers clean JSON with `Content-Encoding: identity`
- **THEN** the proxy scans the body and the client receives it unchanged

#### Scenario: A route that selects no guard

- **WHEN** the upstream answers with `Content-Encoding: gzip` on a route with
  `guards = []` and `on_error` is `fail_close`
- **THEN** the client receives the upstream body unchanged
- **AND** no `voidwall_errors_total` sample carries `reason="unscannable_content"`

#### Scenario: A compressed body of a type not in content_types

- **WHEN** the upstream answers `Content-Type: image/png` with `Content-Encoding: gzip`
  on a route without `format`, and `on_error` is `fail_close`
- **THEN** the client receives the upstream body unchanged

#### Scenario: A compressed response without a body

- **WHEN** the upstream answers 204 with `Content-Encoding: gzip`
- **THEN** the client receives the 204

## MODIFIED Requirements

### Requirement: A clean message is forwarded unchanged

When a scan detects nothing, the proxy SHALL forward the message unchanged and SHALL
increment no detection metric. The proxy SHALL NOT rewrite a body, a URL path, a query
string, or a header value at any point, with one exception: when response scan is on,
it sets `Accept-Encoding` on the forwarded request, as "The proxy asks the upstream for
an uncompressed response" states.

#### Scenario: A clean request

- **WHEN** a scan of the request detects nothing
- **THEN** the request reaches the upstream as it arrived, minus the hop-by-hop headers,
  and with `Accept-Encoding: identity` when response scan is on

#### Scenario: A clean response

- **WHEN** a scan of the upstream response detects nothing
- **THEN** the client receives the upstream body unchanged
