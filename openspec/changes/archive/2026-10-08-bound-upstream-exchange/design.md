## Context

See proposal.md for the motivation. Today `reverse_proxy.rs` sends the upstream request
with `client.request(..).await` and no deadline. The hyper client only sets
`pool_idle_timeout(30s)`, which governs idle pooled connections, not a request. With
response scan on, the proxy calls `upstream_resp.into_body().collect()` with no size
bound. `strip_hop_by_hop` copies headers with `HeaderMap::insert`, which replaces earlier
values of the same name.

The existing 502 for an unreachable upstream does not increment `voidwall_errors_total`
or `voidwall_blocked_total`. This change keeps that as it is.

## Goals / Non-Goals

**Goals:**

- Bound the time and the memory one upstream exchange can take.
- Make invalid timeout values unrepresentable after parsing.

**Non-Goals:**

- A per-route timeout. It can come later as an override.
- Separate connect, header, and body timeouts.
- A timeout or a size limit on a streamed response (response scan off).
- A limit on the request body under `fail_open`, or a client read timeout. These are other
  audit findings.

## Decisions

### One deadline around the whole exchange

Wrap the upstream call in one `tokio::time::timeout`. With response scan on, the deadline
also covers the body read: compute one `Instant` deadline before the request and use
`tokio::time::timeout_at` for the request and for the body read. One deadline gives the
operator one number to reason about.

Alternative: hyper-util connector timeouts. Rejected because they cover the connect phase
only and do not bound the header wait or the body read.

### `upstream_timeout_secs: UpstreamTimeout`

The field type is a newtype, `UpstreamTimeout`, that deserializes with
`#[serde(try_from = "u64")]` and accepts 1 to 3600 only. Serde rejects a value outside
the range at parse, so validation cannot forget the check and the rest of the code never
sees one. The TOML error names the key, so the failure is a `schema` failure, as for any
value of the wrong shape. The field lives on `AppConfig` beside `shutdown_timeout_secs`
and gives `ReverseProxyState` a `Duration`.

The upper bound keeps `Instant::now() + timeout` from overflowing. Without it, a value
near the largest TOML integer passes startup and the addition panics on every request.
3600 s is far above the slowest expected LLM completion.

Alternatives: `NonZeroU64`, rejected because it allows the overflow; `u64` plus a check
in `validate`, rejected because CLAUDE.md asks the type system to make invalid
configuration unrepresentable.

### Response body limit with `http_body_util::Limited`

Read the upstream body through `http_body_util::Limited::new(body, max_body_size)`.
`Limited` fails the read as soon as the body passes the limit, so memory stays bounded at
`max_body_size` plus one frame. A `LengthLimitError` maps to the oversize answer; any
other read error stays the existing 502.

Alternative: check `Content-Length` first. Rejected as the only check because a chunked
response has no length. It can be added later as a fast path.

### New `Error` variants

- `Error::UpstreamTimeout` → 504, body `{"error":"upstream timeout"}`, fixed text in a
  new `UPSTREAM_TIMEOUT` constant beside `UPSTREAM_ERROR`.
- `Error::ResponseTooLarge` → 502, body `{"error":"upstream error"}`.

The proxy increments `voidwall_errors_total` (`blocked`, `upstream_timeout` or
`response_too_large`) where it maps the failure, before it answers. Neither answer
increments `voidwall_blocked_total`: that counter counts messages a guard or an ingest
limit stopped, and the spec already excludes the upstream 502.

### `strip_hop_by_hop` uses `append`

Replace `insert` with `append`. The request path builds its header map with the same
`insert` loop; switch it to `append` too, so a repeated request header also survives.

## Risks / Trade-offs

- [An upstream that needs more than 300 s fails with 504] → The default is set high for
  long LLM completions; the operator can raise `upstream_timeout_secs`.
- [A streamed response (response scan off) can still trickle forever] → Out of scope; no
  memory grows because the body is not buffered.
- [Under response scan, a large but legitimate response is now blocked] → The limit is
  the same `max_body_size` the request already uses; the operator raises it for both.

## Migration Plan

No config change is required. Existing configs get the 300 s default. Rollback is a
revert of the change.
