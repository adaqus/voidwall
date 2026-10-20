## MODIFIED Requirements

### Requirement: The upstream exchange has a time limit

The reverse proxy SHALL limit the upstream exchange to `upstream_timeout_secs` seconds.
The limit SHALL start when the proxy sends the request to the upstream. It SHALL cover the
wait for the response headers. When response scan is on, it SHALL also cover the read of
the response body, except for a stream on a route with `format = "openai-chat"`, whose
body the idle timeout of the `openai-chat-streaming` capability limits instead. When
response scan is off, the body streams to the client and the limit SHALL NOT apply to it.

When the limit expires, the proxy SHALL answer 504, whatever `on_error` says. On a route
without `format` the body SHALL be exactly `{"error":"upstream timeout"}`. On a route
with `format = "openai-chat"` the body SHALL be the OpenAI error shape that the
`openai-chat-proxy` capability states. The body SHALL carry no detail of the failure.

#### Scenario: The upstream does not send headers in time

- **WHEN** the proxy forwards a clean request on a route without `format` and the
  upstream sends no response headers within `upstream_timeout_secs`
- **THEN** the proxy answers 504
- **AND** the body is exactly `{"error":"upstream timeout"}`

#### Scenario: The upstream body is slow under response scan

- **WHEN** response scan is on and the upstream sends its headers in time but does not
  finish the body within `upstream_timeout_secs` of the request
- **THEN** the proxy answers 504 and no part of the upstream body reaches the client

#### Scenario: A stream outlives the upstream timeout

- **WHEN** response scan is on, the route has `format = "openai-chat"`, and the upstream
  sends a clean `text/event-stream` body that lasts longer than `upstream_timeout_secs`,
  with no gap longer than `stream_idle_timeout_secs`
- **THEN** the client receives the whole stream

#### Scenario: on_error does not change the timeout answer

- **WHEN** the upstream exchange times out and `on_error` is `fail_open`
- **THEN** the proxy answers 504

#### Scenario: The upstream answers in time

- **WHEN** the upstream answers within `upstream_timeout_secs`
- **THEN** the client receives the upstream response

### Requirement: The buffered upstream response body has a size limit

When response scan is on, the reverse proxy SHALL read at most `max_body_size` bytes of
the upstream response body. When the body is larger, the proxy SHALL stop the read and
answer 502, whatever `on_error` says. On a route without `format` the body SHALL be
exactly `{"error":"upstream error"}`. On a route with `format = "openai-chat"` the body
SHALL be the OpenAI error shape that the `openai-chat-proxy` capability states. A stream
on a route with `format = "openai-chat"` SHALL follow the size limit of the
`openai-chat-streaming` capability instead. When response scan is off, the proxy SHALL
NOT limit the size of the response body.

#### Scenario: The upstream response is too large under response scan

- **WHEN** response scan is on, the route has no `format`, and the upstream response
  body is larger than `max_body_size`
- **THEN** the proxy answers 502 with the body `{"error":"upstream error"}`
- **AND** no part of the upstream body reaches the client

#### Scenario: on_error does not change the oversize answer

- **WHEN** response scan is on, the upstream response body is larger than
  `max_body_size`, and `on_error` is `fail_open`
- **THEN** the proxy answers 502

#### Scenario: The response body is at the limit

- **WHEN** response scan is on and the upstream response body is exactly
  `max_body_size` bytes
- **THEN** the proxy scans it and forwards it when nothing is detected

#### Scenario: A large response without response scan

- **WHEN** response scan is off and the upstream response body is larger than
  `max_body_size`
- **THEN** the client receives the whole upstream body
