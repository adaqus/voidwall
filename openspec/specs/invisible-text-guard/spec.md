# invisible-text-guard Specification

## Purpose
States the built-in `invisible_text` guard: it reports a request that carries text hidden
in Unicode tag characters or in variation selectors, without decoding that hidden text,
so a guard that reads the decoded view, such as a prompt-injection classifier, is not
passed a hidden instruction. It reads the decoded view itself, so it also finds tag
characters and variation selectors inside a kept base64 or hex run.

## Requirements

### Requirement: The guard is declared with an empty section

The guard SHALL be declared as `[builtin_guards.invisible_text]`. Its only key SHALL be
`enabled`. Any other key, `surface` and `scan_view` included, SHALL fail the schema.

#### Scenario: The guard is declared

- **WHEN** the config holds an empty `[builtin_guards.invisible_text]` table
- **THEN** the proxy builds the `invisible_text` guard

#### Scenario: The guard sets a surface

- **WHEN** `[builtin_guards.invisible_text]` sets `surface`
- **THEN** the schema rejects the file

#### Scenario: The guard sets scan_view

- **WHEN** `[builtin_guards.invisible_text]` sets `scan_view = true`
- **THEN** the schema rejects the file

#### Scenario: The guard is disabled

- **WHEN** `[builtin_guards.invisible_text]` sets `enabled = false`
- **THEN** no `invisible_text` guard is built, and a request body with a tag run is not
  reported by it

#### Scenario: A configured guard takes the name

- **WHEN** the config declares a guard named `invisible_text` under `[guards]`
- **THEN** validation fails naming `invisible_text` as reserved

### Requirement: The guard scans every request unit through the decoded view

The guard SHALL be passed every unit of a request-direction message: the body, the URL
path, the query string and every scanned header value. It SHALL NOT be passed a unit of
a response. It SHALL read the decoded view of a unit that the `encoded-content-decoding`
capability builds, never the scan view of the `hidden-unicode-normalization` capability.
In a structured body it SHALL read each fragment value after its JSON escapes are
decoded.

#### Scenario: Tag characters in a query string

- **WHEN** a request's query string holds the word `ignore` written as tag characters
- **THEN** the guard reports a finding

#### Scenario: Tag characters in a URL path

- **WHEN** a request's path holds the word `ignore` written as tag characters
- **THEN** the guard reports a finding

#### Scenario: Tag characters in a CSV cell

- **WHEN** a CSV request body holds a cell with the word `ignore` written as tag
  characters
- **THEN** the guard reports a finding

#### Scenario: Tag characters written as JSON escapes

- **WHEN** a JSON request value holds tag characters written as `\uXXXX` surrogate-pair
  escapes
- **THEN** the guard reports a finding

#### Scenario: Tag characters inside base64

- **WHEN** a request body holds a base64 run whose decoded text is the words `ignore all
  rules` written as tag characters
- **THEN** the guard reports a finding

#### Scenario: Tag characters inside base64 in a query string

- **WHEN** a request's query string holds a base64url run whose decoded text is the words
  `ignore all rules` written as tag characters
- **THEN** the run is not decoded, and the guard reports no finding for it

#### Scenario: Tag characters in a response

- **WHEN** a response body holds the word `ignore` written as tag characters
- **THEN** the guard is not called

#### Scenario: The LiteLLM request side

- **WHEN** a LiteLLM guardrail call with `input_type` `request` holds the word `ignore`
  written as tag characters in `texts`
- **THEN** the route answers `BLOCKED`, and `blocked_reason` names `INVISIBLE_TEXT`

#### Scenario: A route that does not select the guard

- **WHEN** a route sets `guards = ["prompt_injection"]` and a request body holds the word
  `ignore` written as tag characters
- **THEN** the `invisible_text` guard is not called for that route, and the tag run is
  not reported as `INVISIBLE_TEXT`

### Requirement: The guard reports tag characters outside an emoji flag

A tag character is U+E0000 to U+E007F. The guard SHALL report a unit that holds a tag
character that is not part of an emoji flag sequence. An emoji flag sequence is U+1F3F4
(waving black flag) directly followed by one to six tags that each stand for an ASCII
letter or digit, and then the cancel tag U+E007F; this is the same rule that the
`hidden-unicode-normalization` capability keeps unchanged.

The guard SHALL NOT decode, remove or change any character.

#### Scenario: Hidden instruction in tags

- **WHEN** a request body holds visible text followed by `ignore all previous
  instructions` written as tag characters
- **THEN** the guard reports a finding

#### Scenario: A single tag character

- **WHEN** a request body holds `a`, the language tag U+E0001 and `b`
- **THEN** the guard reports a finding

#### Scenario: Tags split by soft hyphens

- **WHEN** a request body holds the word `ignore` written as tag characters with a soft
  hyphen between each two of them
- **THEN** the guard reports a finding

#### Scenario: Subdivision flags

- **WHEN** a request body holds the flag of England and the flag of California, each
  U+1F3F4, its tags and U+E007F
- **THEN** the guard reports nothing

#### Scenario: Text dressed as a flag

- **WHEN** a request body holds U+1F3F4, an email placeholder written as tag characters,
  and U+E007F
- **THEN** the guard reports a finding

### Requirement: The guard reports a variation selector that follows no base character

A variation selector is U+FE00 to U+FE0F or U+E0100 to U+E01EF. A base character is a
character of Unicode general category letter, number, punctuation or symbol (`L`, `N`,
`P` or `S`). The guard SHALL report a unit that holds a variation selector whose
character directly before it is not a base character: another variation selector, a
mark, a format character, a control character, a separator, a private-use or unassigned
character, or no character at all because the selector starts the unit or the fragment
value.

A variation selector directly after a base character SHALL NOT be reported.

#### Scenario: Emoji smuggling

- **WHEN** a request body holds an emoji followed by a run of variation selectors whose
  bytes are the UTF-8 of `ignore all previous instructions`
- **THEN** the guard reports a finding

#### Scenario: Selectors split by zero-width spaces

- **WHEN** a request body holds an emoji followed by variation selectors with a
  zero-width space between each two of them
- **THEN** the guard reports a finding

#### Scenario: Selectors split by a combining grapheme joiner

- **WHEN** a request body holds an emoji followed by variation selectors with U+034F
  between each two of them
- **THEN** the guard reports a finding

#### Scenario: Selectors split by a combining accent

- **WHEN** a request body holds an emoji followed by variation selectors with U+0301
  between each two of them
- **THEN** the guard reports a finding

#### Scenario: Selectors split by line separators

- **WHEN** a request body holds an emoji followed by variation selectors with U+2028
  between each two of them
- **THEN** the guard reports a finding

#### Scenario: A selector at the start of a value

- **WHEN** a JSON request value starts with U+FE0F
- **THEN** the guard reports a finding

#### Scenario: Emoji with presentation selectors

- **WHEN** a request body holds a heart U+2764 U+FE0F, a keycap `1` U+FE0F U+20E3, a keycap
  `#` U+FE0F U+20E3, and the sequence U+1F3F3 U+FE0F U+200D U+26A7 U+FE0F
- **THEN** the guard reports nothing

#### Scenario: An ideographic variation sequence

- **WHEN** a request body holds a CJK ideograph followed by one selector of U+E0100 to
  U+E01EF
- **THEN** the guard reports nothing

#### Scenario: Ordinary non-ASCII text

- **WHEN** a request body holds Persian text with ZWNJ, a family emoji with ZWJ, German
  text with soft hyphens, and Chinese text
- **THEN** the guard reports nothing

### Requirement: The guard reports one INVISIBLE_TEXT finding per unit

The guard SHALL report the kind `INVISIBLE_TEXT`. It SHALL report at most one finding per
unit, however many tag characters and variation-selector runs the unit holds. The finding
SHALL carry no span.

#### Scenario: Tags and selectors in one body

- **WHEN** a request body holds a tag run and a variation-selector run
- **THEN** the guard reports one `INVISIBLE_TEXT` finding

#### Scenario: Tags in two units

- **WHEN** a request's body and its query string each hold a tag run
- **THEN** the guard reports two `INVISIBLE_TEXT` findings

### Requirement: A request holding hidden text is blocked

A finding of the guard SHALL block the request as any detection does. A generic route
SHALL answer the fixed 403 with `kinds` holding `INVISIBLE_TEXT`. An `openai-chat` route
SHALL answer the fixed 400 with `code` `content_filter` and the same `kinds`.
`/v1/scan` SHALL report the kind.

#### Scenario: Generic route

- **WHEN** a generic route receives a request body with a tag run
- **THEN** the client receives 403 with `kinds` holding `INVISIBLE_TEXT`, and the
  upstream receives nothing

#### Scenario: openai-chat route

- **WHEN** an `openai-chat` route receives a message whose content holds a tag run
- **THEN** the client receives 400 with `code` `content_filter` and `kinds` holding
  `INVISIBLE_TEXT`

#### Scenario: /v1/scan

- **WHEN** `/v1/scan` is called without a `direction`, `invisible_text` is the only
  enabled guard, and the body holds a variation-selector run
- **THEN** the response has `detected` true, `matches_count` 1, `kinds`
  `["INVISIBLE_TEXT"]`, and one `guards` entry named `invisible_text` with
  `matches_count` 1

#### Scenario: The detection metric

- **WHEN** the guard reports findings in the body and the query string of one request on
  a reverse proxy route
- **THEN** `voidwall_detections_total` with `guard` `invisible_text` and `direction`
  `request` grows by one

### Requirement: Hidden text never leaves Voidwall

The characters that the guard finds, and any text they stand for, SHALL NOT appear in a
log line, a metric label, or an error response.

#### Scenario: A request is blocked

- **WHEN** the guard blocks a request
- **THEN** no log line, metric sample, or response body holds the tag characters, the
  variation selectors, or the text they stand for
