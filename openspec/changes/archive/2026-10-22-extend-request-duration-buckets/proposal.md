## Why

`voidwall_request_duration_seconds` uses the default buckets of the `prometheus` crate,
whose highest finite bound is 10 seconds. A request through the reverse proxy to an LLM
upstream often takes longer, so it falls into `+Inf` only, and `histogram_quantile`
reports 10 seconds for every percentile above that bound.

## What Changes

- `voidwall_request_duration_seconds` gets four more bucket bounds: 30, 60, 120, and 300
  seconds. The default bounds from 0.005 to 10 seconds stay.
- The full bound list becomes 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10,
  30, 60, 120, 300, then `+Inf`.
- The metric name, its labels, and what it measures do not change.

## Capabilities

### New Capabilities

None.

### Modified Capabilities

- `metrics`: the request duration histogram has a fixed, stated list of bucket bounds.

## Impact

- `crates/voidwall/src/metrics.rs`: the histogram registration.
- Only the reverse proxy records the histogram today, so its series get the new bounds.
- Prometheus output: each `mode`/`route` series pair gets four more `_bucket` samples.
  Queries over the old bounds keep their results.
