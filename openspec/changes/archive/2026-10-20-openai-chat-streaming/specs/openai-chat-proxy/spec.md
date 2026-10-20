## MODIFIED Requirements

### Requirement: Every other answer uses the OpenAI error shape

On an `openai-chat` route, every answer the proxy makes instead of the upstream's SHALL
keep the status the reverse proxy states for it, and SHALL carry a JSON body with one key,
`error`, whose value SHALL be an object with exactly the keys `message`, `type`, `param`,
and `code`. `param` SHALL be `null`. The other keys SHALL be:

| Status | Cause | `message` | `type` | `code` |
|---|---|---|---|---|
| 400 | Malformed body | `body parse failed` | `invalid_request_error` | `malformed_body` |
| 413 | Oversize body | `request body too large` | `invalid_request_error` | `body_too_large` |
| 413 | Window limit | `tokenized content too long to scan` | `invalid_request_error` | `content_too_long` |
| 422 | Unscannable content | `unscannable content` | `invalid_request_error` | `unscannable_content` |
| 500 | Scanner or inference failure | `internal error` | `server_error` | `internal_error` |
| 502 | Upstream failure, oversize response, or oversize stream | `upstream error` | `server_error` | `upstream_error` |
| 504 | Upstream timeout or idle stream | `upstream timeout` | `server_error` | `upstream_timeout` |

No body SHALL carry a detail of the failure, a matched value, or a fragment of the
scanned message. After the first byte of a stream, the same body SHALL go in the error
event that the `openai-chat-streaming` capability states.

A response the upstream sends and the proxy forwards SHALL reach the client unchanged.

#### Scenario: A scanner failure under fail_close

- **WHEN** a guard fails, no guard reports a finding, and `on_error` is `fail_close`
- **THEN** the proxy answers 500 with
  `{"error":{"message":"internal error","type":"server_error","param":null,"code":"internal_error"}}`
  in any key order

#### Scenario: The upstream cannot be reached

- **WHEN** the proxy forwards a clean request and the upstream connection fails
- **THEN** the proxy answers 502 with `error.code` `upstream_error`

#### Scenario: The upstream times out

- **WHEN** the upstream sends no response headers within `upstream_timeout_secs`
- **THEN** the proxy answers 504 with `error.code` `upstream_timeout`

#### Scenario: An oversize request under fail_close

- **WHEN** a request body is larger than `max_body_size` and `on_error` is `fail_close`
- **THEN** the proxy answers 413 with `error.code` `body_too_large`

#### Scenario: An upstream error is forwarded

- **WHEN** the upstream answers 429 with a JSON error body that holds no PII
- **THEN** the client receives the upstream status and body unchanged

## REMOVED Requirements

### Requirement: A stream is unscannable

**Reason**: A `text/event-stream` response on an `openai-chat` route is now scanned, as
the `openai-chat-streaming` capability states. A request with `"stream": true` is scanned
and forwarded as any other request.

**Migration**: None for clients: a `stream: true` request that answered 422 under
`fail_close` now streams, scanned. Dashboards that read `reason="unscannable_stream"`
lose that series.
