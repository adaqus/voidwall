## Context

See proposal.md for the motivation. `IP_ADDRESS` has two patterns in
`crates/voidwall-pii/src/hyperscan_detector.rs`:

- IPv4: `\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b`, check `ip_check`.
- IPv6: a nine-branch expression with the edge rule `ipv6_edges_clear`, check
  `ipv6_check`.

`validate_as([IpAddress], span)` passes when either check accepts the span
(`kind_validators.rs`). Today `ip_check` accepts any text with no dot, so `validate_as`
for `IP_ADDRESS` accepts almost everything.

Facts checked on 2026-11-05 with rustc 1.99.1:

- `Ipv6Addr::from_str` accepts every shape the IPv6 expression matches, including
  `1:2:3:4:5:6:7::` and `::2:3:4:5:6:7`.
- `Ipv4Addr::from_str` rejects a part with a leading zero, such as `192.168.001.001`.
- `"+5".parse::<u32>()` is `Ok(5)`, so today `ip_check` accepts `+1.+2.+3.+4`.
- These range helpers are stable: `Ipv4Addr::{is_loopback, is_private, is_link_local,
  is_multicast, is_broadcast, is_documentation, is_unspecified}` and
  `Ipv6Addr::{is_loopback, is_unspecified, is_multicast, is_unique_local,
  is_unicast_link_local}`. `Ipv4Addr::is_reserved` and `Ipv6Addr::is_documentation` are
  not stable.

## Goals / Non-Goals

**Goals:**

- One rule for `IP_ADDRESS`, the same for the regex guard and `validate_as`.
- No new dependency.

**Non-Goals:**

- No range is excluded beyond the list in the spec. For example, `100.64.0.0/10`,
  `198.18.0.0/15`, `2001::/32`, and `2002::/16` stay reported.
- No change to the two expressions or to `ipv6_edges_clear`.
- No change to the default `[guards.pii_ml]` config.
- No change to the AI4Privacy eval or its label mapping.

## Decisions

### D1. One check parses `std::net::IpAddr`, and both patterns use it

`ip_check` and `ipv6_check` are replaced by one check. It parses the text as `IpAddr` and
then applies the range rule of its family. The parse gives the shape: four parts for IPv4,
digits only, no leading zero, and every part 0 to 255.

- Alternative: keep one check per family, each with its own parse. Rejected: two
  functions hold one rule, and `validate_as` gains nothing from the split.
- Alternative: a hand-written IPv4 check that allows a leading zero. Rejected: the
  `IpAddr` parse was agreed, and with it `192.168.001.001` is no longer reported.

### D2. Ranges come from `std` helpers where they are stable

- IPv4: `is_unspecified` covers only `0.0.0.0`, so the check tests the first octet for
  `0.0.0.0/8`. `is_reserved` is not stable, so the check tests the first octet for
  `240.0.0.0/4`. The rest use `is_loopback`, `is_private`, `is_link_local`,
  `is_multicast`, and `is_documentation`.
- IPv6: the check tests the first segment for `2000::/3` (`0x2000..=0x3fff`) and the first
  two segments for `2001:db8::/32`. Every other excluded IPv6 range is outside
  `2000::/3`, so it needs no helper of its own.

### D3. The range rule replaces the IPv6 digit rule

The digit rule rejected `dead::beef` and `Add::add`. The range rule rejects them too,
because they are outside `2000::/3`. Every address in `2000::/3` starts with `2` or `3`, so
the range rule already implies the digit rule. `ipv6_edges_clear` stays: it stops a match
that starts inside a code path such as `std::cell`, before any check runs.

### D4. Positive fixtures move to public addresses

Many tests use `192.168.x.x`, `10.x.x.x`, or documentation addresses as values that must
be reported. They move to public addresses outside every excluded range, for example
`109.4.61.213`, which the tests already use, and `2a00:1450:4001:82a::200e`. Tests that
assert an address is not reported use the excluded ranges.

## Risks / Trade-offs

- [The AI4Privacy IP recall drops by about half, because its IP values are random] →
  Accepted. Record the before and after IP numbers in this file.
- [An operator who wants private addresses blocked loses that] → The `custom-pii` rules
  can match them.
- [The default `[guards.pii_ml]` reports `IP_ADDRESS` with threshold 0 and no
  `validate_as`, so in the shipped image a private, loopback, or documentation address
  can still block the message as `IP_ADDRESS` when the model tags it] → Accepted: the
  default config is out of this change. `docs/backlog.md` §3 holds the follow-up.
- [Version numbers in a public range, such as `2.7.18.1`, are still reported] → Not
  addressed here. Only `0.x.x.x` versions stop matching.
- [An IPv4-mapped IPv6 address, such as `::ffff:808:808`, is outside `2000::/3`, so it is
  not reported, whatever IPv4 address it holds] → Follows from the agreed IPv6 rule.
- [A model span loses `:` at its edges to the span trim, so `2001:4860::` is checked as
  `2001:4860` and fails] → Matters only when `validate_as` lists `IP_ADDRESS`, which the
  default config does not.

## AI4Privacy eval

`docker/ctl ai4p-eval`, all six languages, 177,677 rows. IP row:

| Run | n | det R | det P | typed R | typed P |
|---|---:|---:|---:|---:|---:|
| Base (`fb3d273`) | 51,724 | 99.8% | 97.9% | 99.6% | 93.2% |
| After | 51,724 | 50.2% | 98.2% | 49.9% | 96.6% |

The recall drop matches the gold values: 49.6% of them are in an excluded range. Typed
recall of every other label is unchanged. Their untyped recall (`det R`) falls a little,
for example SOCIALNUMBER from 16.9% to 13.4%: those annotations were overlapped only by an
`IP_ADDRESS` prediction of the wrong kind. Predictions fall from 378,971 to 350,450. Micro
detection F1 falls from 0.425 to 0.396, and macro detection recall from 0.428 to 0.397.

## Migration Plan

None. A rollback is a revert of the change.
