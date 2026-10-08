## ADDED Requirements

### Requirement: Upstream limit errors carry their own reasons

An upstream timeout SHALL increment `voidwall_errors_total` with `outcome="blocked"` and
`reason="upstream_timeout"`. An upstream response body larger than `max_body_size` under
response scan SHALL increment it with `outcome="blocked"` and
`reason="response_too_large"`.

#### Scenario: The upstream times out

- **WHEN** the reverse proxy answers 504 because the upstream exchange timed out
- **THEN** `voidwall_errors_total` increments with `outcome="blocked"` and
  `reason="upstream_timeout"`

#### Scenario: The upstream response is too large

- **WHEN** the reverse proxy answers 502 because the upstream response body is larger
  than `max_body_size`
- **THEN** `voidwall_errors_total` increments with `outcome="blocked"` and
  `reason="response_too_large"`
