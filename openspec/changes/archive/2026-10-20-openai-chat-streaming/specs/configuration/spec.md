## ADDED Requirements

### Requirement: The stream keys are top-level keys

`stream_idle_timeout_secs`, `stream_holdback_bytes`, `stream_context_bytes`, and
`stream_scan_bytes` SHALL be top-level keys. They SHALL apply to every route with
`format = "openai-chat"`.

- `stream_idle_timeout_secs` SHALL be a whole number of seconds from 1 to 3600 and
  SHALL default to 60.
- `stream_holdback_bytes` SHALL be a whole number of bytes from 1 to `max_body_size`
  and SHALL default to 512.
- `stream_context_bytes` SHALL be a whole number of bytes from 1 to `max_body_size` and
  SHALL default to 512.
- `stream_scan_bytes` SHALL be a whole number of bytes from 1 to
  `stream_holdback_bytes` and SHALL default to 256.

A value below 1, above a fixed upper bound, or of the wrong type SHALL fail validation
with the `schema` category. A value above the bound another key sets SHALL fail
validation with the `semantic` category. Either failure SHALL name the key and SHALL
prevent startup.

#### Scenario: The keys are absent

- **WHEN** the config sets none of the stream keys
- **THEN** the idle timeout is 60 seconds, the hold-back is 512 bytes, the context is
  512 bytes, and the scan step is 256 bytes

#### Scenario: The keys are set

- **WHEN** the config sets `stream_idle_timeout_secs = 30`, `stream_holdback_bytes = 1024`,
  `stream_context_bytes = 768`, and `stream_scan_bytes = 128`
- **THEN** the proxy uses those values

#### Scenario: The idle timeout is zero

- **WHEN** the config sets `stream_idle_timeout_secs = 0`
- **THEN** validation fails with the `schema` category naming `stream_idle_timeout_secs`
  and the proxy does not start

#### Scenario: The idle timeout is at the upper bound

- **WHEN** the config sets `stream_idle_timeout_secs = 3600`
- **THEN** the idle timeout is 3600 seconds

#### Scenario: The idle timeout is above the upper bound

- **WHEN** the config sets `stream_idle_timeout_secs = 3601`
- **THEN** validation fails with the `schema` category naming `stream_idle_timeout_secs`
  and the proxy does not start

#### Scenario: A byte key is zero

- **WHEN** the config sets `stream_holdback_bytes = 0`
- **THEN** validation fails with the `schema` category naming `stream_holdback_bytes` and
  the proxy does not start

#### Scenario: The hold-back is larger than max_body_size

- **WHEN** the config sets `max_body_size = 2048` and `stream_holdback_bytes = 4096`
- **THEN** validation fails with the `semantic` category naming `stream_holdback_bytes`
  and the proxy does not start

#### Scenario: The context is larger than max_body_size

- **WHEN** the config sets `max_body_size = 2048` and `stream_context_bytes = 4096`
- **THEN** validation fails with the `semantic` category naming `stream_context_bytes`
  and the proxy does not start

#### Scenario: The scan step is larger than the hold-back

- **WHEN** the config sets `stream_holdback_bytes = 256` and `stream_scan_bytes = 512`
- **THEN** validation fails with the `semantic` category naming `stream_scan_bytes` and
  the proxy does not start

#### Scenario: The scan step equals the hold-back

- **WHEN** the config sets `stream_holdback_bytes = 256` and `stream_scan_bytes = 256`
- **THEN** validation passes

### Requirement: A reverse proxy route's stream mode is validated

A reverse proxy route MAY set `stream`. Its valid values SHALL be the strings
`holdback` and `buffer`. A route with `format = "openai-chat"` and no `stream` SHALL use
`holdback`. Any other value, or a value that is not a string, SHALL fail config loading
with the `schema` category. A route that sets `stream` without `format = "openai-chat"`
SHALL fail validation with the `semantic` category. Either failure SHALL prevent startup.

#### Scenario: stream is absent on an openai-chat route

- **WHEN** a route sets `format = "openai-chat"` and no `stream`
- **THEN** validation passes and the route uses hold-back mode

#### Scenario: stream is buffer

- **WHEN** a route sets `format = "openai-chat"` and `stream = "buffer"`
- **THEN** validation passes and the route uses buffer mode

#### Scenario: An unknown stream mode

- **WHEN** a route sets `format = "openai-chat"` and `stream = "chunked"`
- **THEN** loading fails with the `schema` category and the proxy does not start

#### Scenario: stream is not a string

- **WHEN** a route sets `format = "openai-chat"` and `stream = true`
- **THEN** loading fails with the `schema` category and the proxy does not start

#### Scenario: stream without the openai-chat format

- **WHEN** a route sets `stream = "buffer"` and no `format`
- **THEN** validation fails with the `semantic` category naming the route and the proxy
  does not start
