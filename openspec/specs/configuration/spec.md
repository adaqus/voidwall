## Purpose

Configuration is a single TOML file. It selects the modes, the PII settings, the scan
targets, and the actions. The proxy validates the whole file at startup and refuses to
start when a rule fails.

## Requirements

### Requirement: Config is a TOML file named on the command line

The proxy SHALL read one TOML file. `--config <PATH>` SHALL name it. The environment
variable `VOIDWALL_CONFIG` SHALL provide the same value. The proxy SHALL exit with
status 2 when neither is present.

#### Scenario: No config path is given

- **WHEN** the proxy starts with neither `--config` nor `VOIDWALL_CONFIG`
- **THEN** it prints an error naming both options and exits with status 2

### Requirement: Loading validates before returning

Loading SHALL read the file, parse the TOML, deserialize it, and then run the full
validation. It SHALL return an error when any stage fails.

#### Scenario: Config file fails a validation rule

- **WHEN** the config parses but breaks a validation rule
- **THEN** loading returns an error and the proxy does not start

### Requirement: At least one mode must be enabled

Validation SHALL fail when `reverse_proxy` and `http_api` are both disabled. The forward
proxy is not a mode that can be enabled, so it does not count.

#### Scenario: Every mode is disabled

- **WHEN** no mode has `enabled = true`
- **THEN** validation fails naming the missing mode

### Requirement: Enabled listeners must not share an address

Validation SHALL fail when two enabled listeners bind the same host and port.

#### Scenario: Two modes share a port

- **WHEN** two enabled modes name the same `listen` address
- **THEN** validation fails naming the conflicting address

### Requirement: Scanner thread count

`builtin_guards.pii.scanner_threads` SHALL be at least 1 when it is set. When it is
absent, the effective count SHALL come from the available parallelism: the core count
capped at 4 when there are 8 cores or fewer, and half the core count otherwise.

The setting SHALL belong to the guard that owns the scanner, not to a global section.

#### Scenario: Explicit zero

- **WHEN** `scanner_threads` is 0
- **THEN** validation fails

#### Scenario: Setting is absent

- **WHEN** `scanner_threads` is absent
- **THEN** the effective count is at least 1 and follows the core-count rule

#### Scenario: The setting sits outside the guard

- **WHEN** `scanner_threads` is set at the top level rather than under the guard
- **THEN** the schema rejects the file

### Requirement: detect and ignore are mutually exclusive

`builtin_guards.pii.detect` and `builtin_guards.pii.ignore` SHALL NOT both be set. Every
kind named in `detect` SHALL be reachable from the countries configured for that guard.

#### Scenario: Both lists are set

- **WHEN** the guard sets `detect` and `ignore`
- **THEN** validation fails

#### Scenario: A kind is unreachable from the countries

- **WHEN** `detect` names a kind no configured country can produce
- **THEN** validation fails naming that kind

### Requirement: User-defined PII entries are validated

Validation SHALL accept at most 64 `[[builtin_guards.pii.custom]]` entries. Each entry
SHALL carry a non-empty label and a non-empty pattern. A label SHALL NOT collide with a
built-in kind label, and SHALL NOT repeat inside the file.

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

### Requirement: An unknown configuration key is rejected

Every table in the configuration file SHALL accept only the keys its schema defines. A key
the schema does not define SHALL fail validation at startup, naming the key. The proxy SHALL
NOT start on such a file.

#### Scenario: A misspelled key

- **WHEN** a configuration file carries a key no table defines
- **THEN** validation fails naming the key and the proxy does not start

#### Scenario: A retired key

- **WHEN** a reverse-proxy route carries `specialization`
- **THEN** validation fails naming the key and the proxy does not start

#### Scenario: Every defined key is accepted

- **WHEN** a configuration file carries only keys the schema defines
- **THEN** validation passes and the proxy starts

### Requirement: Reverse proxy route identity and upstream are validated

A `path_prefix` SHALL be unique across the routes. An `upstream` SHALL parse as a URI
carrying an `http` or `https` scheme and an authority.

#### Scenario: Duplicate path prefix

- **WHEN** two routes carry the same `path_prefix`
- **THEN** validation fails naming the prefix

#### Scenario: Upstream lacks a scheme or an authority

- **WHEN** a route names an upstream with no `http` or `https` scheme, or no authority
- **THEN** validation fails naming the upstream

### Requirement: Scanning is set at the mode level only

A reverse proxy route SHALL NOT carry `request` or `response` overrides. Whether a
direction is scanned belongs to the mode. Deploy separate instances for separate
policies.

#### Scenario: Route declares a direction override

- **WHEN** a route declares a `request` or `response` table
- **THEN** the schema rejects the file

### Requirement: Forward proxy and TLS settings parse but the mode does not run

The config schema SHALL accept a `forward_proxy` table and a `tls` table, and SHALL
validate them. The forward proxy runtime is not built, so validation SHALL fail when
`forward_proxy.enabled` is true. The failure SHALL carry the `semantic` category and SHALL
name the key. This check SHALL run before the check that at least one mode is enabled.
TLS is not built either, so validation SHALL reject a `tls` table that sets `enabled` to
true.

#### Scenario: Forward proxy is enabled

- **WHEN** `forward_proxy.enabled` is true and another mode is enabled
- **THEN** validation fails with the `semantic` category naming `forward_proxy.enabled`
- **AND** the proxy does not start

#### Scenario: Only the forward proxy is enabled

- **WHEN** `forward_proxy.enabled` is true and no other mode is enabled
- **THEN** validation fails naming `forward_proxy.enabled`, not the missing mode

#### Scenario: A disabled forward proxy table parses

- **WHEN** a `forward_proxy` table sets `enabled = false` and names `listen`, `request`,
  and `response`
- **THEN** validation passes

#### Scenario: Forward proxy schema rules still apply

- **WHEN** `forward_proxy.request` carries a key the schema does not define
- **THEN** validation fails, even though the mode does not run

#### Scenario: A disabled TLS table parses

- **WHEN** a `tls` table sets `enabled = false` and names `cert_path` and `key_path`
- **THEN** validation passes

### Requirement: Model guard settings are validated at startup

Validation SHALL reject a `[guards.<name>]` section that cannot describe a runnable guard,
and SHALL name the guard and the cause. The following SHALL each fail the start:

- an empty `labels` list
- a `labels` entry listed more than once
- a `text_classifier` guard whose `labels` does not hold exactly one entry
- a `max_tokens` below 10
- a `thresholds` key absent from that guard's `labels`
- a threshold outside the score range the adapter declares
- a `surface` that disables every target
- a guard name outside the permitted character set or over the length cap
- a guard name the build reserves for a built-in guard
- `threads = 0`
- an `overlap_tokens` above `max_tokens / 2`
- `adapter = "text_multilabel_classifier"`, because its run side is not built

An `adapter` the build does not ship SHALL fail the start through the schema rather than
through a semantic rule. The set of adapter names is fixed by the build, so the schema can
state it, and the diagnostic SHALL name the rejected value and the names the build ships.

A `labels` entry SHALL NOT be checked against a vocabulary of finding kinds. The build has
no closed set of kinds to check a label against, so a label is whatever the operator
writes.

Validation SHALL report a missing `model_path` or `tokenizer_path` file with the path that
was expected, so an operator can see which artifact the deployment lacks.

Validation SHALL NOT read, parse, or execute a model artifact. The tensor contract is
checked when the guard loads its model at startup.

#### Scenario: The adapter is unknown

- **WHEN** a guard sets `adapter` to a value the build does not ship
- **THEN** the proxy refuses to start, naming the rejected value and the adapter names the
  build ships

#### Scenario: The multilabel adapter is named

- **WHEN** a guard sets `adapter = "text_multilabel_classifier"`
- **THEN** validation fails naming the guard and the adapter as not built, also under
  `--validate`

#### Scenario: The labels list is empty

- **WHEN** a guard sets `labels = []`
- **THEN** the proxy refuses to start, naming the guard

#### Scenario: A label is listed twice

- **WHEN** a guard lists one label at two output positions
- **THEN** the proxy refuses to start, naming the guard and the repeated label

#### Scenario: A text classifier lists two labels

- **WHEN** a `text_classifier` guard lists two labels
- **THEN** the proxy refuses to start, naming the guard and the one-label rule

#### Scenario: The token window is too small

- **WHEN** a guard sets `max_tokens` below 10
- **THEN** the proxy refuses to start, naming the guard and the minimum

#### Scenario: A threshold names a kind the guard does not declare

- **WHEN** a guard sets a threshold for a kind absent from its `labels`
- **THEN** the proxy refuses to start, naming the guard and the kind

#### Scenario: An artifact file is missing

- **WHEN** a guard's `model_path` names a file that does not exist
- **THEN** the proxy refuses to start, naming the guard and the expected path

#### Scenario: A threshold is out of range

- **WHEN** a guard sets a threshold outside the range its adapter declares
- **THEN** the proxy refuses to start, naming the guard, the kind, and the range

#### Scenario: Zero threads

- **WHEN** a guard sets `threads = 0`
- **THEN** the proxy refuses to start, naming the guard and `threads`

#### Scenario: Overlap above the bound

- **WHEN** a guard sets `max_tokens = 16` and `overlap_tokens = 9`
- **THEN** the proxy refuses to start, naming the guard, the overlap 9, and the bound 8

#### Scenario: Overlap at the bound

- **WHEN** a guard sets `max_tokens = 16` and `overlap_tokens = 8`
- **THEN** validation passes

#### Scenario: Validation does not open the model

- **WHEN** a guard names an artifact file that exists but holds no valid model
- **THEN** validation passes, because validation does not read the artifact

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
SHALL NOT open TLS material, SHALL NOT build an upstream client, and SHALL NOT load a
model. It SHALL build a scanner once, to exercise regex and Vectorscan compilation, and
then discard it.

#### Scenario: Validate mode runs

- **WHEN** the proxy runs in validate mode
- **THEN** no socket is bound and no scanner thread is spawned
- **AND** a scanner is built and discarded, so a bad pattern is caught

#### Scenario: Validate mode with a model guard

- **WHEN** the proxy runs in validate mode on a config with a model guard whose model file
  exists but does not parse as ONNX
- **THEN** validation passes, and no model is loaded

### Requirement: A validation failure is categorised

A validation failure SHALL carry one of five categories: `file`, `toml parse`, `schema`,
`semantic`, or `scanner build`. The message SHALL name the category and the cause.

A reserved guard name, an unknown guard in a route's `guards` list, and an unknown
built-in guard name SHALL each carry the `semantic` category.

A guard name outside the permitted character set or over the length cap, an empty or
repeating `labels` list, a `max_tokens` below the floor, a threshold key absent from
`labels`, a threshold outside its adapter's range, and a surface that disables every
target SHALL each carry the `semantic` category. An unknown `adapter` SHALL carry the
`schema` category, because the build fixes the set of adapter names. A missing model or
tokenizer artifact SHALL carry the `file` category and SHALL name the expected path.

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

#### Scenario: A route names an unknown guard

- **WHEN** a route's `guards` list names a guard that is not enabled
- **THEN** the failure carries the `semantic` category and names the guard

#### Scenario: A custom pattern does not compile

- **WHEN** a `[[builtin_guards.pii.custom]]` pattern fails to compile
- **THEN** the failure carries the `scanner build` category and names the label

#### Scenario: A guard name holds a character outside the set

- **WHEN** the config declares a guard named `injection.v2`
- **THEN** the failure carries the `semantic` category and names the guard

#### Scenario: An adapter is unknown

- **WHEN** a guard sets `adapter` to a value the build does not ship
- **THEN** the failure carries the `schema` category and names the rejected value

#### Scenario: A model artifact is missing

- **WHEN** a guard's `tokenizer_path` names a file that does not exist
- **THEN** the failure carries the `file` category and names the expected path

### Requirement: There is no partial start

The proxy SHALL NOT skip an invalid entry and continue. An invalid config SHALL stop
the start. Dropping a declared PII definition silently is a security regression.

#### Scenario: One custom entry is invalid

- **WHEN** one `[[builtin_guards.pii.custom]]` entry fails validation
- **THEN** the proxy refuses to start, rather than dropping that entry

### Requirement: Ingest limits are set once for every guard

`max_body_size`, `content_types`, and `on_error` SHALL be top-level keys. They SHALL
govern how a message is admitted and decoded before any guard sees it, so they SHALL
apply to every guard alike and SHALL NOT be set per guard.

`max_body_size` SHALL default to 1048576 bytes. `on_error` SHALL default to
`fail_close`.

#### Scenario: Limits are shared

- **WHEN** the config sets `max_body_size` at the top level and enables a guard
- **THEN** that limit applies to every guard, in every mode

#### Scenario: A limit is set under a guard

- **WHEN** a guard section sets `max_body_size`
- **THEN** the schema rejects the file

### Requirement: A model guard that fails to load stops the start

At startup, every configured model guard SHALL load its model before any data-plane
listener binds. When one load fails, the proxy SHALL log the error with the guard's name
and SHALL exit non-zero. It SHALL NOT start without that guard.

#### Scenario: The model file is not ONNX

- **WHEN** a model guard's `model_path` names a file that does not parse as an ONNX model
- **THEN** the proxy logs an error naming the guard and the model path, and exits non-zero
- **AND** no data-plane listener binds

#### Scenario: The overlap leaves no room in the window

- **WHEN** a model guard's tokenizer adds so many special tokens that the window is not
  longer than the overlap
- **THEN** the proxy logs an error naming the guard, the window, and the overlap, and
  exits non-zero

### Requirement: The upstream timeout is a top-level key

`upstream_timeout_secs` SHALL be a top-level key. It SHALL be a whole number of seconds
from 1 to 3600 and SHALL default to 300. A value outside that range SHALL fail
validation with the `schema` category and prevent startup.

#### Scenario: The key is absent

- **WHEN** the config does not set `upstream_timeout_secs`
- **THEN** the upstream timeout is 300 seconds

#### Scenario: The key is set

- **WHEN** the config sets `upstream_timeout_secs = 60`
- **THEN** the upstream timeout is 60 seconds

#### Scenario: The key is zero

- **WHEN** the config sets `upstream_timeout_secs = 0`
- **THEN** validation fails naming `upstream_timeout_secs` and the proxy does not start

#### Scenario: The key is negative

- **WHEN** the config sets `upstream_timeout_secs = -1`
- **THEN** validation fails naming `upstream_timeout_secs` and the proxy does not start

#### Scenario: The key is at the upper bound

- **WHEN** the config sets `upstream_timeout_secs = 3600`
- **THEN** the upstream timeout is 3600 seconds

#### Scenario: The key is above the upper bound

- **WHEN** the config sets `upstream_timeout_secs = 3601`
- **THEN** validation fails naming `upstream_timeout_secs` and the proxy does not start

### Requirement: Enabling TLS fails validation

Validation SHALL fail when `reverse_proxy.tls.enabled` or `forward_proxy.tls.enabled` is
true, whether or not that mode is enabled. The failure SHALL carry the `semantic`
category and SHALL name the key. The proxy SHALL NOT start and serve plaintext in place
of the TLS the config asks for.

#### Scenario: Reverse proxy TLS is enabled

- **WHEN** `reverse_proxy.tls.enabled` is true
- **THEN** validation fails with the `semantic` category naming `reverse_proxy.tls.enabled`
- **AND** the proxy does not start

#### Scenario: Forward proxy TLS is enabled

- **WHEN** `forward_proxy.tls.enabled` is true
- **THEN** validation fails with the `semantic` category naming `forward_proxy.tls.enabled`
- **AND** the proxy does not start

#### Scenario: TLS is enabled for a disabled mode

- **WHEN** `forward_proxy.enabled` is false and `forward_proxy.tls.enabled` is true
- **THEN** validation fails naming `forward_proxy.tls.enabled`

### Requirement: Each HTTP API route has its own switch

`http_api.scan.enabled` SHALL turn the `POST /v1/scan` route on or off.
`http_api.litellm.enabled` SHALL turn the LiteLLM Generic Guardrail API route on or off.
Each SHALL be a boolean and SHALL default to true. A value that is not a boolean SHALL
fail config loading with the `schema` category. A key under `http_api.scan` or
`http_api.litellm` other than `enabled` SHALL fail it as an unknown key.

`http_api.enabled` SHALL start the listener. While it is false, the route switches SHALL
have no effect and SHALL be valid whatever they say. While it is true, validation SHALL
fail with the `semantic` category when every route switch is false.

#### Scenario: Both tables are absent

- **WHEN** the config enables `http_api` and has no `http_api.scan` or `http_api.litellm`
  table
- **THEN** validation passes and both routes are on

#### Scenario: Only the LiteLLM route

- **WHEN** the config enables `http_api` and sets `http_api.scan.enabled = false`
- **THEN** validation passes, the LiteLLM route is on, and `/v1/scan` is off

#### Scenario: Only the scan route

- **WHEN** the config enables `http_api` and sets `http_api.litellm.enabled = false`
- **THEN** validation passes, `/v1/scan` is on, and the LiteLLM route is off

#### Scenario: Every route is off

- **WHEN** the config enables `http_api` and sets both `http_api.scan.enabled` and
  `http_api.litellm.enabled` to false
- **THEN** validation fails with the `semantic` category and names both switches

#### Scenario: The value is not a boolean

- **WHEN** the config sets `http_api.litellm.enabled = "yes"`
- **THEN** loading fails with the `schema` category and the proxy does not start

#### Scenario: An unknown key in a route table

- **WHEN** the config sets `http_api.litellm.path = "/x"`
- **THEN** loading fails naming the unknown key

#### Scenario: The HTTP API is disabled

- **WHEN** the config sets `http_api.enabled = false`, sets both route switches to false,
  and enables the reverse proxy
- **THEN** validation passes and no HTTP API route is served

### Requirement: A reverse proxy route's format is validated

A reverse proxy route MAY set `format`. Its only valid value SHALL be the string
`openai-chat`. A route without `format` SHALL keep the generic body scan. Any other value,
or a value that is not a string, SHALL fail config loading with the `schema` category,
and the proxy SHALL NOT start.

#### Scenario: format is absent

- **WHEN** a route sets no `format`
- **THEN** validation passes and the route scans bodies generically

#### Scenario: format is openai-chat

- **WHEN** a route sets `format = "openai-chat"`
- **THEN** validation passes and the route decodes bodies as Chat Completions

#### Scenario: An unknown format

- **WHEN** a route sets `format = "anthropic-messages"`
- **THEN** loading fails with the `schema` category and the proxy does not start

#### Scenario: format is not a string

- **WHEN** a route sets `format = true`
- **THEN** loading fails with the `schema` category and the proxy does not start
