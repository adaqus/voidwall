## Why

The security audit found two high findings in the reverse proxy that are still open. The
proxy waits for the upstream with no time limit, and with response scan on it reads the
upstream response body with no size limit. A slow or hostile upstream can hold
connections forever or exhaust memory. Both must be fixed before the repository is
public. The same audit found that the proxy drops all but the last value of a repeated
response header, such as `Set-Cookie`.

## What Changes

- New top-level config key `upstream_timeout_secs`, default 300, range 1 to 3600. A
  value outside the range is rejected at startup.
- The timeout covers the whole upstream exchange: from sending the request until the
  response headers arrive, plus the body read when response scan buffers the body. When
  response scan is off, the body streams to the client and the timeout covers the headers
  only.
- When the timeout expires, the proxy answers 504 with the fixed body
  `{"error":"upstream timeout"}`.
- With response scan on, the proxy stops reading the upstream response body when it
  exceeds `max_body_size` and answers 502 `{"error":"upstream error"}`. This is always a
  block; `on_error` does not apply. With response scan off, the body is not buffered and
  no limit applies.
- `voidwall_errors_total` increments with `outcome="blocked"` and
  `reason="upstream_timeout"` or `reason="response_too_large"` for these two errors.
- The proxy keeps every value of a repeated response header, such as `Set-Cookie`, when
  it strips hop-by-hop headers.

## Capabilities

### New Capabilities

None.

### Modified Capabilities

- `reverse-proxy`: the upstream exchange has a time limit and a response body size limit;
  repeated response headers survive; the 504 status is added to the error statuses.
- `configuration`: new top-level key `upstream_timeout_secs` with validation.
- `metrics`: two new `reason` values for `voidwall_errors_total`.

## Impact

- Code: `crates/voidwall/src/config.rs`, `crates/voidwall/src/reverse_proxy.rs`,
  `crates/voidwall/src/error.rs`.
- Tests: unit tests in those files; integration tests in
  `crates/voidwall/tests/` against a slow and an oversize upstream.
- Docs: `docker/voidwall.toml` lists the top-level keys and gets the new one.
  `docs/openapi.json` is not affected, because the REST API does not call an upstream.
- Behavior: an upstream exchange longer than 300 s now fails with 504. An operator with a
  slower upstream must raise `upstream_timeout_secs`.
