## MODIFIED Requirements

### Requirement: Body size limit

The scanner SHALL not scan a body larger than `scan.max_body_size`. That limit SHALL
default to 1048576 bytes. An oversize body SHALL follow the `on_error` policy and SHALL
increment `voidwall_errors_total`.

#### Scenario: Body exceeds the limit under fail_open

- **WHEN** a body is larger than `max_body_size` and `on_error` is `fail_open`
- **THEN** the proxy forwards the message unscanned and increments the error metric

#### Scenario: Body exceeds the limit under fail_close

- **WHEN** a body is larger than `max_body_size` and `on_error` is `fail_close`
- **THEN** the proxy blocks the message and increments the error metric

### Requirement: Overlap resolution runs before every use of the matches

The scanner SHALL pass every `mark_piis` and `mark_piis_structured` result through
`voidwall_pii::resolve_overlaps` before it counts, redacts, or reports a match. Every
count, kind list, and metric SHALL derive from the resolved set. The same value at two
distinct byte offsets SHALL stay two matches.

#### Scenario: Two detectors match overlapping spans

- **WHEN** two detectors report overlapping spans over the same bytes
- **THEN** the resolved set holds one match, and the count reflects the resolved set

#### Scenario: One value appears twice

- **WHEN** the same value appears at two distinct byte offsets
- **THEN** the resolved set holds two matches

### Requirement: The scanner runs on dedicated OS threads

The scanner pool SHALL spawn dedicated OS threads. Each thread SHALL own its own
`voidwall_pii::Scanner`. The scanner SHALL never run on the tokio async runtime. The
thread count SHALL come from the effective scanner thread setting.

#### Scenario: Pool starts

- **WHEN** the proxy builds the scanner pool
- **THEN** it spawns one named OS thread per configured scanner thread
- **AND** each thread holds its own scanner instance
