## ADDED Requirements

### Requirement: The request duration histogram has fixed bucket bounds

`voidwall_request_duration_seconds` SHALL have these bucket upper bounds, in seconds:
0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30, 60, 120, and 300, followed
by `+Inf`. The bounds SHALL NOT depend on configuration.

#### Scenario: Prometheus scrapes the histogram

- **WHEN** a request has been recorded and a client scrapes the admin metrics endpoint
- **THEN** the `voidwall_request_duration_seconds_bucket` samples of that series carry
  exactly the `le` values `0.005`, `0.01`, `0.025`, `0.05`, `0.1`, `0.25`, `0.5`, `1`,
  `2.5`, `5`, `10`, `30`, `60`, `120`, `300`, and `+Inf`

#### Scenario: A request longer than 10 seconds

- **WHEN** a request that takes 45 seconds is recorded
- **THEN** the bucket with `le="60"` counts it, and the bucket with `le="30"` does not
