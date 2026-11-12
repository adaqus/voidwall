## MODIFIED Requirements

### Requirement: A compressed stream is unscannable content

A stream on an `openai-chat` route with response scan on and a `Content-Encoding` other
than `identity` SHALL be unscannable content in both modes, when the route scans the
response body. It SHALL follow `on_error` as a response the route cannot inspect does.
A route that scans no response body, such as a route with `guards = []`, SHALL forward
a compressed stream unscanned and SHALL count no unscannable content.

#### Scenario: A compressed stream under fail_close

- **WHEN** the upstream answers `text/event-stream` with `Content-Encoding: gzip` and
  `on_error` is `fail_close`
- **THEN** the proxy answers 422 with `error.code` `unscannable_content` and no body byte
  reaches the client

#### Scenario: A compressed stream under fail_open

- **WHEN** the upstream answers `text/event-stream` with `Content-Encoding: gzip` and
  `on_error` is `fail_open`
- **THEN** the client receives the stream unscanned
- **AND** `voidwall_errors_total` increments with `outcome="passed"` and
  `reason="unscannable_content"`

#### Scenario: A compressed stream on a route that selects no guard

- **WHEN** the upstream answers `text/event-stream` with `Content-Encoding: gzip` on a
  route with `guards = []`, and `on_error` is `fail_close`
- **THEN** the client receives the upstream body unchanged
- **AND** no `voidwall_errors_total` sample carries `reason="unscannable_content"`
