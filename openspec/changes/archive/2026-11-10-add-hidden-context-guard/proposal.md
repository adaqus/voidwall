## Why

OWASP LLM08:2026 Hidden Context Exposure covers a model that repeats what the operator
put in its context: the system prompt, internal codenames, and other text the user must
not see. Voidwall blocks leaked secrets of known shapes today, but it cannot block a leak
of text that only the operator knows. A canary planted in the system prompt cannot be a
custom PII rule, because the system message is scanned on the request side and the
canary would block every request.

## What Changes

- A new built-in guard, `[builtin_guards.hidden_context]`, holds a list of markers: plain
  text that must never leave in a response. It reports the fixed kind `HIDDEN_CONTEXT`
  when a response body holds a marker, so the proxy blocks the response as it blocks any
  detection.
- A marker matches without regard to case, by Unicode simple case folding. No setting
  changes this.
- The guard reports at most one finding per unit.
- The guard scans the response body only. It never scans a request, a URL path, a query
  string, or a header value, and it has no `surface` table.
- A guard's interest gains a direction. The engine passes a guard only the units of a
  direction it wants. The `pii` guard and model guards keep both directions.
- Validation rejects a `hidden_context` section that is enabled with no marker, an empty
  marker, a duplicate marker, more than 64 markers, and a marker whose longest possible
  match is longer than `stream_holdback_bytes`. A validation error never quotes a marker.
- `POST /v1/scan` takes a `direction` query parameter, `request` or `response`. Without
  it, the scan is a request scan, as today. An unknown value answers 400.
- The guard matches inline in `detect`, with no worker thread. `CLAUDE.md` and
  `ARCHITECTURE.md` state this exception to the threading rule.
- The image's default configuration does not declare the guard.

## Capabilities

### New Capabilities

- `hidden-context-guard`: the `hidden_context` guard, its markers, how it matches, what
  it reports, and which units it scans.

### Modified Capabilities

- `guard-configuration`: `hidden_context` joins `pii` in the set of built-in names, and a
  guard without a scan surface becomes possible.
- `http-api`: `/v1/scan` takes the `direction` parameter, and `matches_count` counts the
  findings of the `hidden_context` guard.
- `metrics`: a `/v1/scan` scan with `direction=response` records `direction="response"`.

## Impact

- Code: `crates/voidwall/src/config.rs` (section, validation), `crates/voidwall/src/engine/`
  (direction in `Interest` and `Engine::guard`, the new guard), `reverse_proxy.rs` and
  `http_api.rs` (pass the direction).
- API: `/v1/scan` gains an optional query parameter. A caller that does not send it sees
  no change. The OpenAPI document changes.
- Dependencies: `regex-syntax`, already in the tree through `regex`, becomes a direct
  dependency of `voidwall`.
- Metrics: no new family and no new label. The guard reaches `voidwall_detections_total`
  as `guard="hidden_context"`.
- Docs: `CLAUDE.md` and `ARCHITECTURE.md` (threading exception), proxy documentation
  under `docs/` (the new section and the parameter).
- Not in this change: the website's LLM08 coverage row, and any detection of a paraphrased
  or encoded leak.
