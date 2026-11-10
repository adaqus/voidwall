## Purpose

States the built-in `hidden_context` guard: the operator lists text that must never leave
in a response, such as a canary planted in a system prompt or an internal codename, and
the guard reports a response body that holds it.

## ADDED Requirements

### Requirement: The guard is declared with a list of markers

The `hidden_context` guard SHALL be declared under `[builtin_guards.hidden_context]`. Its
section SHALL hold `markers`, an array of strings. A marker SHALL be plain text, not a
pattern. An absent section SHALL build no `hidden_context` guard.

#### Scenario: The guard is declared

- **WHEN** the config holds `[builtin_guards.hidden_context]` with
  `markers = ["vw-canary-0000"]`
- **THEN** the proxy builds the `hidden_context` guard

#### Scenario: A marker holds pattern characters

- **WHEN** a marker is `a.b`
- **THEN** a response body holding `a.b` is reported, and a body holding `axb` is not

#### Scenario: The section is absent

- **WHEN** the config holds no `[builtin_guards.hidden_context]` table
- **THEN** no `hidden_context` guard is built

### Requirement: Markers are validated at startup

Validation SHALL reject a `hidden_context` section that is enabled and holds no marker.
It SHALL reject an empty marker, more than 64 markers, and two markers that are equal
after Unicode simple case folding. It SHALL reject a marker whose longest possible match,
in bytes, is longer than `stream_holdback_bytes`. A validation error SHALL name a marker
by its position in `markers` and SHALL NOT quote it.

#### Scenario: Enabled with no marker

- **WHEN** `[builtin_guards.hidden_context]` holds `markers = []` and is enabled
- **THEN** validation fails naming the guard

#### Scenario: Disabled with no marker

- **WHEN** `[builtin_guards.hidden_context]` holds `markers = []` and sets
  `enabled = false`
- **THEN** validation passes

#### Scenario: An empty marker

- **WHEN** a marker is the empty string
- **THEN** validation fails naming its position, without quoting it

#### Scenario: Too many markers

- **WHEN** the section holds 65 markers
- **THEN** validation fails naming the count and the cap

#### Scenario: Two markers differ only in case

- **WHEN** the section holds `Bluefin` and `BLUEFIN`
- **THEN** validation fails naming the position of the second, without quoting either

#### Scenario: A marker longer than the hold-back

- **WHEN** `stream_holdback_bytes` is 512 and a marker's longest possible match is 513
  bytes
- **THEN** validation fails naming its position and `stream_holdback_bytes`, without
  quoting it

#### Scenario: Case folding makes a match longer than the marker

- **WHEN** `stream_holdback_bytes` is 64 and a marker is 30 ASCII `k` characters, whose
  case folding admits the 3-byte Kelvin sign
- **THEN** validation fails, because the longest possible match is 90 bytes

### Requirement: A marker matches without regard to case

A marker SHALL match a text that equals it under Unicode simple case folding, anywhere in
the text, with no word boundary. No setting SHALL change this.

#### Scenario: Different ASCII case

- **WHEN** a marker is `Project Bluefin` and a response body holds `project BLUEFIN`
- **THEN** the guard reports a finding

#### Scenario: Different non-ASCII case

- **WHEN** a marker is `Żubr` and a response body holds `ŻUBR`
- **THEN** the guard reports a finding

#### Scenario: Inside a longer word

- **WHEN** a marker is `bluefin` and a response body holds `bluefins`
- **THEN** the guard reports a finding

### Requirement: The guard scans the response body only

The guard SHALL be passed the body unit of a response and no other unit. It SHALL NOT
be passed a request unit, a URL path, a query string, or a header value. A request that
holds a marker SHALL NOT be reported by this guard.

For a structured body, the guard SHALL match each parsed value on its own. A marker split
across two values SHALL NOT match.

#### Scenario: The marker is in the system message of a request

- **WHEN** a request to an `openai-chat` route carries a marker in its system message
- **THEN** the `hidden_context` guard reports nothing and the request is forwarded

#### Scenario: The marker is in a response header

- **WHEN** a route names the header `x-debug` for scanning and an upstream response
  carries a marker in it, with a clean body
- **THEN** the `hidden_context` guard reports nothing

#### Scenario: The marker is in a JSON response value

- **WHEN** a generic route's upstream answers a JSON body whose value holds a marker
- **THEN** the guard reports a finding

#### Scenario: The LiteLLM request side

- **WHEN** a LiteLLM guardrail call with `input_type` `request` holds a marker
- **THEN** the `hidden_context` guard reports nothing

#### Scenario: The LiteLLM response side

- **WHEN** a LiteLLM guardrail call with `input_type` `response` holds a marker in `texts`
- **THEN** the guard reports a finding and the route answers `BLOCKED`

### Requirement: The guard reports one HIDDEN_CONTEXT finding per unit

The guard SHALL report the kind `HIDDEN_CONTEXT` for every marker. It SHALL report at most
one finding per unit, however many markers, and however many times, the unit holds.

#### Scenario: One marker three times

- **WHEN** a response body holds one marker three times
- **THEN** the guard reports one `HIDDEN_CONTEXT` finding

#### Scenario: Two markers

- **WHEN** a response body holds two different markers
- **THEN** the guard reports one `HIDDEN_CONTEXT` finding

### Requirement: A response holding a marker is blocked

A finding of the guard SHALL block the response as any detection does. A generic route
SHALL answer the fixed 403 with `kinds` holding `HIDDEN_CONTEXT`. An `openai-chat` route
SHALL answer the fixed 400 with `code` `content_filter` and the same `kinds`.

On a stream in hold-back mode, no byte of a marker SHALL reach the client, also when the
marker arrives split across two events.

#### Scenario: Generic route

- **WHEN** a generic route's upstream answers a body holding a marker
- **THEN** the client receives 403 with `kinds` `["HIDDEN_CONTEXT"]`, and the body does
  not hold the marker

#### Scenario: openai-chat route

- **WHEN** an `openai-chat` route's upstream answers a completion holding a marker
- **THEN** the client receives 400 with `code` `content_filter` and `kinds`
  `["HIDDEN_CONTEXT"]`

#### Scenario: A marker split across stream events

- **WHEN** a stream on an `openai-chat` route in hold-back mode carries the first half of
  a marker in one event and the rest in the next
- **THEN** the proxy stops the stream, and no event the client received holds any byte
  of the marker

### Requirement: A marker never leaves Voidwall

A marker SHALL NOT appear in a log line, a metric label, an error response, or a
validation message. This SHALL hold for a matched text too.

#### Scenario: A response is blocked

- **WHEN** the guard blocks a response
- **THEN** no log line, metric sample, or response body holds the marker or the matched
  text

#### Scenario: Startup logs the configuration

- **WHEN** the proxy starts with the guard enabled
- **THEN** no startup log line holds a marker
