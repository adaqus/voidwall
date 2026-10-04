## Why

A reverse proxy 500 or 502 puts the internal failure text in the body, for example
`{"error":"scanner pool overloaded"}` or `{"error":"upstream error: connection refused"}`.
The client cannot act on it, and it shows how the proxy works inside. The 500 and 502
bodies must be fixed and carry no failure details. The details belong in the log.

## What Changes

- Every 500 that the `Error` type produces answers the fixed body
  `{"error":"internal error"}`. This covers the scanner error and the configuration
  error.
- Every 502 that the `Error` type produces answers the fixed body
  `{"error":"upstream error"}`. This covers the proxy error and the I/O error.
- The reverse proxy answers these fixed bodies for a scanner failure under `fail_close`
  and for every 502.
- The REST API scanner failure under `fail_close` changes its body from
  `{"error":"scanner failure"}` to `{"error":"internal error"}`. **BREAKING** for a client
  that matches on the old text.
- A failure to read the request body now writes an `error!` log line with the details.
  It is the only 502 path that logs nothing today. Its status stays 502.
- The other logging does not change. The 400, 413, and 415 bodies do not change.

## Capabilities

### New Capabilities

None.

### Modified Capabilities

- `reverse-proxy`: the 500 for a scanner failure carries the fixed body
  `{"error":"internal error"}`. Every 502 carries the fixed body
  `{"error":"upstream error"}`.
- `http-api`: the 500 for a scanner failure carries the fixed body
  `{"error":"internal error"}`.

## Impact

- Code: `crates/voidwall/src/error.rs` (`IntoResponse for Error`),
  `crates/voidwall/src/http_api.rs` (`handle_scanner_failure`),
  `crates/voidwall/src/reverse_proxy.rs` (`buffer_body` log line).
- Tests: unit tests in `error.rs`, the 500 and 502 integration tests in
  `crates/voidwall/tests/reverse_proxy_integration.rs`, and the 500 integration test in
  `crates/voidwall/tests/http_api_integration.rs`.
- API: the REST API 500 body text changes. The OpenAPI 500 entry keeps the
  `ErrorResponse` schema.
- No configuration, metric, or dependency change.
