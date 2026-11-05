## Why

The two `IP_ADDRESS` checks accept almost any text. The IPv4 check accepts any text with
no dot, and the IPv6 check accepts any text with a decimal digit. The regex guard is safe
only because its expressions give the shape. A model span has no shape, so
`validate_as` for `IP_ADDRESS` accepts "hello", "12345", and "1.2.3.4.5", and the default
`[guards.pii_ml]` cannot use it. Separately, the regex guard reports addresses that
identify no person, such as `127.0.0.1`, private addresses, and the version `0.11.0.0`.

## What Changes

- A value counts as an IP address only when it parses as a complete IPv4 or IPv6 address.
  An IPv4 part with a leading zero, such as `192.168.001.001`, no longer parses.
- **BREAKING** (detector output): the `IP_ADDRESS` kind no longer reports an address in a
  range that names no public host:
  - IPv4: `0.0.0.0/8`, loopback `127.0.0.0/8`, private `10.0.0.0/8`, `172.16.0.0/12`,
    `192.168.0.0/16`, link-local `169.254.0.0/16`, multicast `224.0.0.0/4`, reserved
    `240.0.0.0/4` (with broadcast `255.255.255.255`), and documentation `192.0.2.0/24`,
    `198.51.100.0/24`, `203.0.113.0/24`.
  - IPv6: every address outside global unicast `2000::/3`, which includes `::`, `::1`,
    unique-local `fc00::/7`, link-local `fe80::/10`, and multicast `ff00::/8`; and
    documentation `2001:db8::/32`.
- The IPv6 range rule replaces the current rule that an IPv6 value must hold a decimal
  digit. Code tokens made of hex letters, such as `dead::beef` and `Add::add`, stay
  unreported because they fall outside `2000::/3`.
- The same rules apply to the regex guard and to `validate_as` with `IP_ADDRESS`.
- The AI4Privacy eval's IP recall drops by about half. Its IP values are random:
  42.3% of its 51,724 gold IP values are IPv6 outside `2000::/3`, and 6.7% are IPv4
  multicast or `240.0.0.0/4`. This drop is expected and accepted.
- `docs/backlog.md` §3 loses the `IP_ADDRESS` validator item and the `0.11.0.0` false
  positive. `docs/model-guards.md` no longer calls `IP_ADDRESS` a poor `validate_as`
  choice.

Not in this change: the default `[guards.pii_ml]` keeps no `validate_as` for
`IP_ADDRESS`.

## Capabilities

### New Capabilities

- `ip-address-detection`: which values the `IP_ADDRESS` kind reports, and which address
  ranges it does not report.

### Modified Capabilities

None.

## Impact

- `crates/voidwall-pii`: the `IP_ADDRESS` checks in `validators.rs`; positive test
  fixtures that use private or documentation addresses in `scanner.rs`,
  `hyperscan_detector.rs`, and `benches/pii_benchmark.rs`.
- `crates/voidwall`: integration tests that expect an `IP_ADDRESS` block from such an
  address. Bench payloads that hold one, such as `benches/payloads/pii_nested.json`.
- Operators: the regex `pii` guard no longer reports a loopback, private, link-local, or
  documentation address as `IP_ADDRESS`. The default `[guards.pii_ml]` still reports
  `IP_ADDRESS` with no `validate_as`, so in the shipped image such an address can still
  block the message when the model tags it.
- No new dependency: the parse and the ranges use `std::net`.
