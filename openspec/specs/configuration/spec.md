## Purpose

Configuration is a single TOML file. It selects the modes, the PII settings, the scan
targets, and the actions. The proxy validates the whole file at startup and refuses to
start when a rule fails.

## Requirements

### Requirement: Config is a TOML file named on the command line

The proxy SHALL read one TOML file. `--config <PATH>` SHALL name it. The environment
variable `PII_PROXY_CONFIG` SHALL provide the same value. The proxy SHALL exit with
status 2 when neither is present.

#### Scenario: No config path is given

- **WHEN** the proxy starts with neither `--config` nor `PII_PROXY_CONFIG`
- **THEN** it prints an error naming both options and exits with status 2

### Requirement: Loading validates before returning

Loading SHALL read the file, parse the TOML, deserialize it, and then run the full
validation. It SHALL return an error when any stage fails.

#### Scenario: Config file fails a validation rule

- **WHEN** the config parses but breaks a validation rule
- **THEN** loading returns an error and the proxy does not start

### Requirement: At least one mode must be enabled

Validation SHALL fail when `reverse_proxy`, `forward_proxy`, and `http_api` are all
disabled.

#### Scenario: Every mode is disabled

- **WHEN** no mode has `enabled = true`
- **THEN** validation fails naming the missing mode

### Requirement: Enabled listeners must not share an address

Validation SHALL fail when two enabled listeners bind the same host and port.

#### Scenario: Two modes share a port

- **WHEN** two enabled modes name the same `listen` address
- **THEN** validation fails naming the conflicting address

### Requirement: Scanner thread count

`pii.scanner_threads` SHALL be at least 1 when it is set. When it is absent, the
effective count SHALL come from the available parallelism: the core count capped at 4
when there are 8 cores or fewer, and half the core count otherwise.

#### Scenario: Explicit zero

- **WHEN** `scanner_threads` is 0
- **THEN** validation fails

#### Scenario: Setting is absent

- **WHEN** `scanner_threads` is absent
- **THEN** the effective count is at least 1 and follows the core-count rule

### Requirement: detect and ignore are mutually exclusive

`pii.detect` and `pii.ignore` SHALL NOT both be set. Every kind named in `detect` SHALL
be reachable from the configured countries.

#### Scenario: Both lists are set

- **WHEN** the config sets `detect` and `ignore`
- **THEN** validation fails

#### Scenario: A kind is unreachable from the countries

- **WHEN** `detect` names a kind no configured country can produce
- **THEN** validation fails naming that kind

### Requirement: User-defined PII entries are validated

Validation SHALL accept at most 64 `[[pii.custom]]` entries. Each entry SHALL carry a
non-empty label and a non-empty pattern. A label SHALL NOT collide with a built-in kind
label, and SHALL NOT repeat inside the file.

#### Scenario: Too many entries

- **WHEN** the config holds more than 64 custom entries
- **THEN** validation fails naming the count and the cap

#### Scenario: Empty label or pattern

- **WHEN** a custom entry carries an empty label, or an empty pattern
- **THEN** validation fails naming the entry

#### Scenario: Label collides with a built-in kind

- **WHEN** a custom label equals a built-in `PiiKind` label
- **THEN** validation fails naming the collision

#### Scenario: Duplicate custom label

- **WHEN** two custom entries carry the same label
- **THEN** validation fails naming the duplicate

### Requirement: Block and header cannot share a direction

Validation SHALL fail when one direction's action list holds both `block` and `header`.
A blocked message is not forwarded, so a header serves no purpose.

#### Scenario: Both actions in one direction

- **WHEN** a direction lists `block` and `header`
- **THEN** validation fails naming that direction

### Requirement: The header action is restricted by direction

`header` SHALL be valid only in `reverse_proxy.request` and `forward_proxy.response`.

#### Scenario: Header in a reverse proxy response

- **WHEN** `reverse_proxy.response` lists `header`
- **THEN** validation fails naming that direction

#### Scenario: Header in a forward proxy request

- **WHEN** `forward_proxy.request` lists `header`
- **THEN** validation fails naming that direction

### Requirement: Redact requires a strategy, and char requires a mask character

Validation SHALL fail when a direction lists `redact` without `redact_strategy`. It
SHALL fail when `redact_strategy` is `char` without `mask_char`. The same rule SHALL
apply to the HTTP API settings.

#### Scenario: Redact without a strategy

- **WHEN** a direction lists `redact` and sets no `redact_strategy`
- **THEN** validation fails naming that direction

#### Scenario: Char strategy without a mask character

- **WHEN** `redact_strategy` is `char` and `mask_char` is absent
- **THEN** validation fails

### Requirement: Reverse proxy routes are validated

A `path_prefix` SHALL be unique across the routes. An `upstream` SHALL parse as a URI
carrying an `http` or `https` scheme and an authority. A named `specialization` SHALL
match a built-in specialization.

#### Scenario: Duplicate path prefix

- **WHEN** two routes carry the same `path_prefix`
- **THEN** validation fails naming the prefix

#### Scenario: Upstream lacks a scheme or an authority

- **WHEN** a route names an upstream with no `http` or `https` scheme, or no authority
- **THEN** validation fails naming the upstream

#### Scenario: Unknown specialization

- **WHEN** a route names a specialization that does not exist
- **THEN** validation fails naming the route and the specialization

### Requirement: A per-route scan override fully replaces the defaults

A route-level `scan` table SHALL replace the mode defaults completely. The proxy SHALL
NOT merge the two.

#### Scenario: Route sets one scan field

- **WHEN** a route's `scan` table sets one field only
- **THEN** every other field takes its own default, not the mode-level value

### Requirement: Actions are set at the mode level only

A reverse proxy route SHALL NOT carry `request` or `response` action overrides. Actions
belong to the mode. Deploy separate instances for separate action policies.

#### Scenario: Route declares an action override

- **WHEN** a route declares a `request` or `response` table
- **THEN** the schema rejects the file

### Requirement: Forward proxy and TLS settings parse but do not run

The config schema SHALL accept a `forward_proxy` table and a `tls` table, and SHALL
validate their action rules. The forward proxy runtime is not built. The proxy SHALL log
one warning at startup when `forward_proxy.enabled` is true, and SHALL continue with the
other modes.

#### Scenario: Forward proxy is enabled

- **WHEN** `forward_proxy.enabled` is true
- **THEN** the proxy logs a warning that the mode is not yet implemented
- **AND** the proxy continues to start every other enabled mode

#### Scenario: Forward proxy direction rules still apply

- **WHEN** `forward_proxy.request` lists `header`
- **THEN** validation fails, even though the mode does not run

### Requirement: Pre-flight validation runs offline

The proxy SHALL accept `--validate <PATH>`. It SHALL run the full pipeline and exit
without starting. `--validate` and `--config` SHALL be mutually exclusive. Exit code 0
SHALL mean valid, and a non-zero code SHALL mean invalid.

#### Scenario: Valid config file

- **WHEN** the operator runs `--validate` on a valid file
- **THEN** the proxy prints a success line and exits 0

#### Scenario: Invalid config file

- **WHEN** the operator runs `--validate` on an invalid file
- **THEN** the proxy prints a categorised diagnostic and exits non-zero

### Requirement: Validation binds nothing and starts nothing

In validate mode the proxy SHALL NOT bind a listener, SHALL NOT spawn a scanner thread,
SHALL NOT open TLS material, and SHALL NOT build an upstream client. It SHALL build a
scanner once, to exercise regex and Vectorscan compilation, and then discard it.

#### Scenario: Validate mode runs

- **WHEN** the proxy runs in validate mode
- **THEN** no socket is bound and no scanner thread is spawned
- **AND** a scanner is built and discarded, so a bad pattern is caught

### Requirement: A validation failure is categorised

A validation failure SHALL carry one of five categories: `file`, `toml parse`, `schema`,
`semantic`, or `scanner build`. The message SHALL name the category and the cause.

#### Scenario: The file is missing

- **WHEN** the named path does not exist
- **THEN** the failure carries the `file` category

#### Scenario: The TOML does not parse

- **WHEN** the file holds a TOML syntax error
- **THEN** the failure carries the `toml parse` category

#### Scenario: A field is missing or of the wrong type

- **WHEN** the TOML parses but does not match the schema
- **THEN** the failure carries the `schema` category

#### Scenario: A rule fails

- **WHEN** the schema matches but a validation rule fails
- **THEN** the failure carries the `semantic` category

#### Scenario: A custom pattern does not compile

- **WHEN** a `[[pii.custom]]` pattern fails to compile
- **THEN** the failure carries the `scanner build` category and names the label

### Requirement: There is no partial start

The proxy SHALL NOT skip an invalid entry and continue. An invalid config SHALL stop
the start. Dropping a declared PII definition silently is a security regression.

#### Scenario: One custom entry is invalid

- **WHEN** one `[[pii.custom]]` entry fails validation
- **THEN** the proxy refuses to start, rather than dropping that entry
