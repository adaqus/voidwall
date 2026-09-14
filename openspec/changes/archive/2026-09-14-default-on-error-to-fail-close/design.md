## Context

See `proposal.md` — Why.

`scan.on_error` has one value that covers three unrelated causes. `buffer_body` raises
`body_too_large` when a body passes `max_body_size`. `classify_scan_body` raises
`body_parse_failed` when a declared content type does not match the bytes.
`Engine::guard` raises `scanner_failure` when the pool is overloaded or its threads are
dead. Only the third is a fault of ours. The first is ordinary traffic and the second is a
client mistake.

Under `fail_open` none of this was visible, because every cause took the same silent
forward path. Flipping the default puts all three on the response path at once, so the
status each one answers now matters.

The reverse proxy currently borrows `Error::Scanner` for the parse case, and
`Error::Scanner` maps to 502 in `error.rs`. `/v1/scan` does not use that mapping — it
writes 400 and 500 inline. The two surfaces have disagreed since they were written.

## Goals / Non-Goals

**Goals:**

- The posture an operator gets by writing no configuration is the safe one.
- One cause, one status, the same on both surfaces.
- 502 means the upstream failed, and nothing else.

**Non-Goals:**

- No change to `voidwall_errors_total`, its labels, or its call sites.
- No change to the 403 detection response. That path is untouched.
- No new configuration field. The knob count stays where it is.
- No change to `/v1/scan`, which already answers the statuses this change adopts.

## Decisions

**Flip the default rather than drop it.** A required `on_error` would force every operator
to choose, which is the most honest option. It also refuses to start every existing
configuration file, which turns a posture change into an outage on upgrade. A flipped
default gets the same safe posture for anyone who has not thought about it, and the people
who did think about it already wrote the field.

**Add `Error::BodyParse` rather than special-case the status where it is raised.** The
reverse proxy could keep building `Error::Scanner` and override the status at the call
site. That hides the real point: a malformed body is not a scanner failure, and the two
deserve separate variants. A variant also makes the 400 reachable from anywhere the parse
step moves to later.

**Remap `Error::Scanner` from 502 to 500 globally, not only in the reverse proxy.** Every
producer is our own code — three sites in `scanner.rs`, the pool errors in
`engine/regex_pii.rs`, and `From<voidwall_pii::PiiError>`. None of them describes an
upstream failure, so none of them earned 502. A local override would leave the variant
lying in every other place it is used.

**Keep `max_body_size` at 1048576 bytes.** Under `fail_close` this stops being a scan
limit and becomes a transfer limit, which is a real change in what the number means.
Raising it in the same change would mix two default flips in one diff and make the
blocking behaviour hard to review. The number stays, and the release note says what it now
does.

**Reject splitting `on_error` into a fault policy and an oversize policy.** An oversize
body is not an error, so folding it under an error policy is a category mistake, and
`fail_close` makes that mistake louder. The fix is a second configuration field, with its
own validation, defaults, and per-route override semantics. That is a change of its own.
This one records the tension and leaves the knob alone.

**Drop `on_error` from `docker/voidwall.toml`, keep it in the bench configs.** The Docker
file is the example an operator copies, so it must show the shipped posture. The bench
configs exist to produce comparable numbers, and a run that starts blocking oversize
bodies measures something different from the last one.

## Risks / Trade-offs

**Scanner pool saturation becomes an outage instead of a degradation.** Under `fail_open`
an overloaded pool quietly passed traffic. Under `fail_close` it answers 500 to everyone.
→ This is the posture the change is asking for, so the mitigation is visibility, not
softening: `voidwall_errors_total{outcome="blocked",reason="scanner_failure"}` already
exists and is the signal to alert on. The release note names pool sizing as the thing to
check before upgrading.

**A body over 1 MiB is rejected by default.** An operator who never set `max_body_size`
and never sent a large body will meet a 413 the first time one arrives.
→ The release note names both escapes: raise `max_body_size`, or set
`on_error = "fail_open"` on the route that carries large bodies.

**`Error::Scanner` changes a status code that callers may already handle.** 502 becomes
500 on every path that surfaces that variant.
→ The blast radius is five producers and one `IntoResponse` arm, all covered by the
`error.rs` table tests. `Error::Proxy` and `Error::Io` keep 502, so genuine upstream
failures are unaffected.

**Existing tests that build a default `ScanConfig` change outcome silently.** A test that
relied on the old default now exercises the blocking path.
→ The integration tests pin `on_error` explicitly in every error case already. The task
list calls for a sweep of default-constructed configs rather than trusting that.

**The no-increment claim is proven by structure, not by a runtime assertion.** The
requirement says a skipped content type does not increment `voidwall_errors_total`. The
Prometheus registry is process-wide and the tests in one binary run in parallel, so a
before-and-after delta asserting "did not change" would flake against any other test that
records an error. `inc_error` has nine call sites in `crates/voidwall/src/`, none of them
on the content-type branch, and that is what holds the claim up. The scenario asserts the
half a test can own: the message is forwarded under `fail_close`.

## Migration Plan

1. Ship the flip with a release note that states the new default, names
   `on_error = "fail_open"` as the opt-out, and explains that `max_body_size` now rejects
   rather than skips.
2. Rollback for an operator is one line of configuration, not a downgrade. Setting
   `on_error = "fail_open"` restores the previous behaviour exactly, including the status
   codes, because the old path never produced a response at all.
3. The status-code corrections have no opt-out. They apply under `fail_close` only, so an
   operator who takes the rollback never sees them.

## Open Questions

- Should an oversize body stop counting as an error and get its own outcome label, once it
  is a transfer limit rather than a scan limit? Answering this later changes only the
  metric vocabulary, not these specs or this task list.
