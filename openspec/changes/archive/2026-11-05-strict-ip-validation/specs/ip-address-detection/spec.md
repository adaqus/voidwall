## Purpose

Defines which values the `IP_ADDRESS` kind reports: a complete IPv4 or IPv6 address that
can name a public host. It also defines the address ranges that the kind does not report.

## ADDED Requirements

### Requirement: An IP address is a complete address

The `pii` guard SHALL report a value as `IP_ADDRESS` only when the value is a complete
IPv4 or IPv6 address. An IPv4 address SHALL have exactly four dot-separated parts. Each
part SHALL be one to three ASCII digits with no leading zero, and its value SHALL be 0 to
255. An IPv6 address SHALL be a valid text form of an IPv6 address.

#### Scenario: A public IPv4 address

- **WHEN** a message holds `109.4.61.213`
- **THEN** the guard reports `IP_ADDRESS`

#### Scenario: A part over 255

- **WHEN** a message holds `192.168.1.256` and no other address
- **THEN** the guard reports no `IP_ADDRESS`

#### Scenario: A part with a leading zero

- **WHEN** a message holds `109.004.061.213` and no other address
- **THEN** the guard reports no `IP_ADDRESS`

#### Scenario: A public IPv6 address

- **WHEN** a message holds `2a00:1450:4001:82a::200e`
- **THEN** the guard reports `IP_ADDRESS`

### Requirement: An address that names no public host is not reported

The `pii` guard SHALL NOT report an IPv4 address in any of these ranges as `IP_ADDRESS`:

| Range | Use |
|---|---|
| `0.0.0.0/8` | this network |
| `127.0.0.0/8` | loopback |
| `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16` | private |
| `169.254.0.0/16` | link-local |
| `224.0.0.0/4` | multicast |
| `240.0.0.0/4` | reserved, with broadcast `255.255.255.255` |
| `192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24` | documentation |

The `pii` guard SHALL report an IPv6 address as `IP_ADDRESS` only when it is in global
unicast `2000::/3` and not in documentation `2001:db8::/32`.

#### Scenario: Loopback

- **WHEN** a message holds `127.0.0.1` and no other address
- **THEN** the guard reports no `IP_ADDRESS`

#### Scenario: A private address

- **WHEN** a message holds `192.168.1.1` and no other address
- **THEN** the guard reports no `IP_ADDRESS`

#### Scenario: A documentation address

- **WHEN** a message holds `203.0.113.45` and no other address
- **THEN** the guard reports no `IP_ADDRESS`

#### Scenario: A version number in the this-network range

- **WHEN** a message holds the version `0.11.0.0` and no other address
- **THEN** the guard reports no `IP_ADDRESS`

#### Scenario: A netmask

- **WHEN** a message holds `255.255.255.0` and no other address
- **THEN** the guard reports no `IP_ADDRESS`

#### Scenario: IPv6 loopback and link-local

- **WHEN** a message holds `::1` or `fe80::1` and no other address
- **THEN** the guard reports no `IP_ADDRESS`

#### Scenario: IPv6 unique-local

- **WHEN** a message holds `fd12:3456:789a::1` and no other address
- **THEN** the guard reports no `IP_ADDRESS`

#### Scenario: IPv6 documentation

- **WHEN** a message holds `2001:db8::8a2e:370:7334` and no other address
- **THEN** the guard reports no `IP_ADDRESS`

#### Scenario: A code token made of hex letters

- **WHEN** a message holds `dead::beef` or `Add::add` and no other address
- **THEN** the guard reports no `IP_ADDRESS`

### Requirement: Validation as IP_ADDRESS applies the same rules

A model guard span validated as `IP_ADDRESS` SHALL pass only when the whole trimmed span
is an address that the `pii` guard would report as `IP_ADDRESS`.

#### Scenario: A span that is not an address

- **WHEN** a guard sets `validate_as.IP_ADDRESS = ["IP_ADDRESS"]` and an `IP_ADDRESS` span
  is `hello`, `12345`, or `1.2.3.4.5`
- **THEN** the guard reports no finding for that span

#### Scenario: A span that is a private address

- **WHEN** the same guard decodes an `IP_ADDRESS` span `10.0.0.1`
- **THEN** the guard reports no finding for that span

#### Scenario: A span that is a public address

- **WHEN** the same guard decodes an `IP_ADDRESS` span `109.4.61.213`
- **THEN** the guard reports the finding
