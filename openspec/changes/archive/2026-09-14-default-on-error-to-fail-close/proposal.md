## Why

A guardrails engine that forwards traffic it could not inspect is not a guardrail. Today
`scan.on_error` defaults to `fail_open`, so an operator who never reads the config setting
gets a proxy that passes a message through whenever the scanner fails or a limit is hit.
The safe posture must be the one you get by doing nothing.

Flipping the default makes the error paths visible for the first time, and two of them
answer with the wrong status. The reverse proxy returns 502 Bad Gateway both when a client
sends malformed JSON and when our own scanner pool breaks. Neither is the upstream's
fault. `/v1/scan` already answers 400 and 500 for the same two causes, so the two surfaces
disagree.

## What Changes

- **BREAKING** `scan.on_error` defaults to `fail_close`. A scanner failure or a limit
  violation now blocks the message instead of forwarding it. An operator who wants the old
  behaviour must set `on_error = "fail_open"` explicitly.
- **BREAKING** A body that fails to parse blocks with 400 Bad Request in the reverse
  proxy, not 502. The client declared the content type and sent a body that does not match
  it, so the fault is the client's. This matches what `/v1/scan` already answers.
- **BREAKING** A scanner failure blocks with 500 Internal Server Error in the reverse
  proxy, not 502. The scanner is ours, not the upstream's. This matches `/v1/scan`.
- An oversize body keeps answering 413 Payload Too Large. No change.
- `Error::Proxy` and `Error::Io` keep answering 502. A real upstream failure is the only
  thing that earns Bad Gateway.
- Correct a wrong sentence in the `pii-scanning` spec: a body whose content type sits
  outside `scan.content_types` is skipped silently. The `on_error` policy does not apply
  and no error metric increments. The code has always behaved this way. Under a
  `fail_close` default the wrong sentence would read as an instruction to block every
  binary upload.
- `docker/voidwall.toml` drops its explicit `on_error` line so the shipped example
  demonstrates the shipped default.
- The bench configs under `crates/voidwall/benches/configs/` keep `on_error = "fail_open"`
  pinned, so load-test numbers stay comparable across this change.

Out of scope: `scan.max_body_size` keeps its 1048576 byte default. Splitting `on_error`
into a fault policy and a separate oversize policy is recorded as a rejected alternative
in `design.md`, not built here.

## Capabilities

### New Capabilities

None.

### Modified Capabilities

- `pii-scanning`: the `on_error` default flips from `fail_open` to `fail_close`. The
  content type allowlist requirement drops its incorrect claim that `on_error` applies to
  a skipped body.
- `reverse-proxy`: a new requirement fixes the status code the proxy answers for each
  blocking cause under `fail_close`.

## Impact

Code:

- `crates/voidwall/src/config.rs` — `default_on_error()` and `impl Default for ScanConfig`
  return `OnError::FailClose`. Unit tests that assert the default move with it.
- `crates/voidwall/src/error.rs` — a new `Error::BodyParse` variant answers 400.
  `Error::Scanner` remaps from 502 to 500. Five producers in `scanner.rs` and
  `engine/regex_pii.rs` and the `From<voidwall_pii::PiiError>` impl all describe our own
  failure, so 500 fits every one of them.
- `crates/voidwall/src/reverse_proxy.rs` — `classify_scan_body` builds `Error::BodyParse`
  instead of borrowing `Error::Scanner` for a client mistake.
- `docker/voidwall.toml` — drop the `on_error` line so the example inherits the default.
- `AGENTS.md` and `openspec/config.yaml` — name `fail_close` as the default and record the
  status that each blocking cause answers.

Tests. Every test that could already reach an error path pinned `on_error` explicitly, or
asserted a status `/v1/scan` returns whatever the policy says, so none of them changed
outcome. Ten tests were added, one assertion was tightened, and the `error.rs` tables
gained two rows and had one corrected:

- `reverse_proxy_integration.rs` — a scanner failure answers 500 under `fail_close` and
  forwards under `fail_open`; a default configuration blocks; an unlisted content type is
  still forwarded; an unreachable upstream still answers 502; no error body carries a
  fragment of the scanned message.
- `http_api_integration.rs` — `TestApi::start_with_pii` lets a test own a failing pool, and
  the two `on_error` branches of `/v1/scan` each get a test for the first time.
- `structured_scanning_integration.rs` — the parse-failure test asserts 400 exactly instead
  of any client or server error.
- `config.rs` — an explicit `fail_open` still wins, and a route override does not inherit
  `on_error` from `[scan]`.
- `error.rs` — two rows for `Error::BodyParse`, and the `Error::Scanner` row corrected to
  500.

Metrics: no change. `voidwall_errors_total{outcome,reason}` keeps its label set. The
`outcome` label shifts from `passed` to `blocked` in a default deployment, which is the
point of the change.

Upgrade note for operators. This repository keeps no separate changelog, so the note
lives here.

- `scan.on_error` now defaults to `fail_close`. If you never wrote the field, your proxy
  changes from forwarding a message it could not inspect to blocking it.
- To keep the old behaviour, write `on_error = "fail_open"` under `[scan]`, or under the
  route's own `scan` table. A per-route override replaces the defaults whole, so a route
  that already overrides `scan` must name `on_error` itself.
- `scan.max_body_size` keeps its 1048576 byte default, but it now rejects rather than
  skips. A body above the limit answers 413 instead of passing through unscanned. Raise
  the limit, or set `fail_open` on the route that carries large bodies.
- Three status codes changed on the reverse proxy, all of them under `fail_close` only:
  a body that does not parse answers 400 where it answered 502, a scanner failure answers
  500 where it answered 502, and an oversize body still answers 413.
- `/v1/scan` keeps its status mapping, which already used 400 and 500 for these causes,
  but the default flip still changes what it answers. A scanner failure now returns 500
  where it used to return 200 carrying `detected: false` and an empty `kinds` array. A
  caller that treats 200 as "no PII found" was reading a clean verdict from a scan that
  never ran, which is why the default moved. Check your `/v1/scan` consumers for 5xx
  handling before upgrading.
- 502 now means the upstream failed, and nothing else.
- An operator who takes the `fail_open` rollback never meets any of the new statuses,
  because that path produces no error response at all.
