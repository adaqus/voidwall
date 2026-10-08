## 1. Configuration

- [x] 1.1 Add `upstream_timeout_secs: NonZeroU64` to `AppConfig` with default 300 and a
      doc comment; set it in `Default`
- [x] 1.2 Unit tests in `config.rs`: absent → 300, set to 60 → 60, `0` rejected naming the
      key, `-1` rejected naming the key
- [x] 1.4 Replace `NonZeroU64` with an `UpstreamTimeout` newtype that accepts 1 to 3600
      (`#[serde(try_from = "u64")]`); unit tests: 3600 accepted, 3601 rejected naming the
      key
- [x] 1.3 Add `upstream_timeout_secs = 300` to `docker/voidwall.toml` beside the other
      top-level keys

## 2. Errors

- [x] 2.1 Add `Error::UpstreamTimeout` (504, fixed `UPSTREAM_TIMEOUT` text
      `"upstream timeout"`) and `Error::ResponseTooLarge` (502, `UPSTREAM_ERROR` text) with
      `Display` arms
- [x] 2.2 Unit tests in `error.rs`: status and exact body for both variants

## 3. Reverse proxy

- [x] 3.1 Carry the timeout as a `Duration` in `ReverseProxyState`
- [x] 3.2 Compute one deadline before the upstream request; wrap the request in
      `tokio::time::timeout_at`; on expiry log, increment `voidwall_errors_total`
      (`blocked`, `upstream_timeout`), and answer `Error::UpstreamTimeout`
- [x] 3.3 Under response scan, read the body through `http_body_util::Limited` at
      `max_body_size` and under the same deadline; on the limit log, increment
      `voidwall_errors_total` (`blocked`, `response_too_large`), and answer
      `Error::ResponseTooLarge`; on expiry answer as in 3.2; keep other read errors as the
      existing 502
- [x] 3.4 Use `HeaderMap::append` in `strip_hop_by_hop` and in the request header copy
- [x] 3.5 Unit test: `strip_hop_by_hop` keeps two `Set-Cookie` values in order and drops a
      hop-by-hop header

## 4. Integration tests (`crates/voidwall/tests/reverse_proxy_integration.rs`)

- [x] 4.1 Upstream that delays its headers past a 1 s timeout → 504 with body
      `{"error":"upstream timeout"}`, also under `fail_open`
- [x] 4.2 Response scan on, upstream sends headers then stalls the body past the timeout →
      504
- [x] 4.3 Response scan on, upstream body larger than `max_body_size` → 502
      `{"error":"upstream error"}`, also under `fail_open`; body exactly `max_body_size` →
      forwarded
- [x] 4.4 Response scan off, upstream body larger than `max_body_size` → client gets the
      whole body
- [x] 4.5 Upstream sets two `Set-Cookie` headers → client receives both in order
- [x] 4.6 Assert `voidwall_errors_total` reasons `upstream_timeout` and
      `response_too_large` with `outcome="blocked"`, and that `voidwall_blocked_total`
      does not change, where the test harness exposes metrics

## 5. Verify

- [x] 5.1 `cargo test --workspace` passes
- [x] 5.2 `cargo clippy --workspace --all-targets` has no warnings
- [x] 5.4 Add the 504 for an upstream timeout to the error rules in `CLAUDE.md`
- [x] 5.3 Mark item 2 done in
      `voidwall-internal/research/open-source/backlog.md`
