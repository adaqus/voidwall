## 1. Buckets

- [x] 1.1 Give `voidwall_request_duration_seconds` the bucket bounds of the spec delta in
  `crates/voidwall/src/metrics.rs`. Verify: `cargo check --workspace` passes.
- [x] 1.2 Add a unit test in `metrics.rs` that reads the histogram's bucket bounds and
  checks the full list. Verify: the test fails before 1.1 and passes after it.
- [x] 1.3 Add a unit test that records 45 seconds and checks that the `le="60"` bucket
  counts it and the `le="30"` bucket does not. Verify: `cargo test -p voidwall metrics`
  passes.

## 2. Checks

- [x] 2.1 Run `cargo test --workspace` and `cargo clippy --workspace --all-targets`.
  Verify: both pass with no warnings.
- [x] 2.2 Scrape a running proxy after one request. Verify: the bucket samples carry the
  16 `le` values of the spec delta.
