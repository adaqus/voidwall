## ADDED Requirements

### Requirement: The upstream exchange has a time limit

The reverse proxy SHALL limit the upstream exchange to `upstream_timeout_secs` seconds.
The limit SHALL start when the proxy sends the request to the upstream. It SHALL cover the
wait for the response headers. When response scan is on, it SHALL also cover the read of
the response body. When response scan is off, the body streams to the client and the
limit SHALL NOT apply to it.

When the limit expires, the proxy SHALL answer 504 with the body exactly
`{"error":"upstream timeout"}`, whatever `on_error` says. The body SHALL carry no detail
of the failure.

#### Scenario: The upstream does not send headers in time

- **WHEN** the proxy forwards a clean request and the upstream sends no response headers
  within `upstream_timeout_secs`
- **THEN** the proxy answers 504
- **AND** the body is exactly `{"error":"upstream timeout"}`

#### Scenario: The upstream body is slow under response scan

- **WHEN** response scan is on and the upstream sends its headers in time but does not
  finish the body within `upstream_timeout_secs` of the request
- **THEN** the proxy answers 504 and no part of the upstream body reaches the client

#### Scenario: on_error does not change the timeout answer

- **WHEN** the upstream exchange times out and `on_error` is `fail_open`
- **THEN** the proxy answers 504

#### Scenario: The upstream answers in time

- **WHEN** the upstream answers within `upstream_timeout_secs`
- **THEN** the client receives the upstream response

### Requirement: The buffered upstream response body has a size limit

When response scan is on, the reverse proxy SHALL read at most `max_body_size` bytes of
the upstream response body. When the body is larger, the proxy SHALL stop the read and
answer 502 with the body exactly `{"error":"upstream error"}`, whatever `on_error` says.
When response scan is off, the proxy SHALL NOT limit the size of the response body.

#### Scenario: The upstream response is too large under response scan

- **WHEN** response scan is on and the upstream response body is larger than
  `max_body_size`
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

## MODIFIED Requirements

### Requirement: Hop-by-hop headers are stripped

The proxy SHALL remove the hop-by-hop headers before it forwards: `connection`,
`keep-alive`, `proxy-authenticate`, `proxy-authorization`, `te`, `trailers`,
`transfer-encoding`, and `upgrade`. The comparison SHALL ignore case.

The proxy SHALL keep every value of a header that is not hop-by-hop and appears more than
once, in its original order.

#### Scenario: Client sends a hop-by-hop header

- **WHEN** a request carries `Transfer-Encoding`
- **THEN** the forwarded request does not carry it

#### Scenario: The upstream sets two cookies

- **WHEN** the upstream response carries two `Set-Cookie` headers
- **THEN** the client receives both `Set-Cookie` headers, in the same order
