## ADDED Requirements

### Requirement: A direction is scanned when its scan flag is set

A `request` or `response` table SHALL carry one key, `scan`. It SHALL default to true.
`scan = false` SHALL disable inspection for that direction and SHALL leave the other
direction untouched. There SHALL be no action list, no redaction setting, and no block
response setting in the table.

#### Scenario: A direction table is omitted

- **WHEN** a mode declares no `request` table
- **THEN** that direction is scanned, because `scan` defaults to true

#### Scenario: A direction is turned off

- **WHEN** `reverse_proxy.response` sets `scan = false`
- **THEN** the upstream response is not inspected and the request is still inspected

#### Scenario: A retired key is present

- **WHEN** a direction table carries `actions`, `redact_strategy`, `mask_char`,
  `block_status`, `block_body`, or `block_headers`
- **THEN** validation fails, naming the unknown key

### Requirement: Scanning is set at the mode level only

A reverse proxy route SHALL NOT carry `request` or `response` overrides. Whether a
direction is scanned belongs to the mode. Deploy separate instances for separate
policies.

#### Scenario: Route declares a direction override

- **WHEN** a route declares a `request` or `response` table
- **THEN** the schema rejects the file

### Requirement: Forward proxy and TLS settings parse but the mode does not run

The config schema SHALL accept a `forward_proxy` table and a `tls` table, and SHALL
validate them. The forward proxy runtime is not built. The proxy SHALL log one warning at
startup when `forward_proxy.enabled` is true, and SHALL continue with the other modes.

#### Scenario: Forward proxy is enabled

- **WHEN** `forward_proxy.enabled` is true
- **THEN** the proxy logs a warning that the mode is not yet implemented
- **AND** the proxy continues to start every other enabled mode

#### Scenario: Forward proxy schema rules still apply

- **WHEN** `forward_proxy.request` carries a key the schema does not define
- **THEN** validation fails, even though the mode does not run

## REMOVED Requirements

### Requirement: Actions are set at the mode level only

**Reason**: There is no action list to place. The rule survives as *Scanning is set at the
mode level only*, which keeps the same prohibition on route-level `request` and `response`
tables.
**Migration**: None. A route that declares a direction table is still rejected.

### Requirement: Forward proxy and TLS settings parse but do not run

**Reason**: The requirement mandated validation of "their action rules", and its scenario
rejected `header` in `forward_proxy.request`. Neither exists. The rule survives as
*Forward proxy and TLS settings parse but the mode does not run*, which keeps the warning,
the continued startup, and validation of the tables under the current schema.
**Migration**: None. An unparseable `forward_proxy` table still fails at startup.

### Requirement: Block and header cannot share a direction

**Reason**: The header action is deleted, so no direction can list it.
**Migration**: Remove `header` from every action list. The action list itself is gone.

### Requirement: The header action is restricted by direction

**Reason**: The header action is deleted, so there is no position to restrict.
**Migration**: Remove `header` from every action list.

### Requirement: Redact requires a strategy, and char requires a mask character

**Reason**: Redaction is deleted, so there is no strategy to require and no mask character
to validate.
**Migration**: Remove `redact_strategy` and `mask_char` from every direction table and
from `[http_api]`.
