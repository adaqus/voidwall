## MODIFIED Requirements

### Requirement: Request units have a normalized scan view

Before any guard runs, the engine SHALL build a scan view of each unit of a
request-direction message that a selected guard reads through the scan view. Whether a
guard reads the scan view or the decoded view of the `encoded-content-decoding`
capability is the guard's `scan_view` setting, as the `guard-configuration` capability
states. This SHALL apply at every request entry point: a reverse proxy request on any
route format, `/v1/scan` with `direction=request` (the default), and the request side of
the LiteLLM guardrail route.

The scan view SHALL be built from the text of the unit as it is received: the body, the
URL path, the query string and every scanned header value. In a structured unit (a JSON
or CSV body), the scan view SHALL be built for each fragment value, after its JSON escapes
are decoded. The key path SHALL NOT be normalized. Bytes that are not valid UTF-8 SHALL
stay in the scan view unchanged. The scan view of a body unit SHALL also hold its decoded
runs, in the order that the `encoded-content-decoding` capability states.

A guard that reads the scan view SHALL scan only the scan view. A guard that does not read
the scan view SHALL scan the decoded view that the `encoded-content-decoding` capability
states. The forwarded message SHALL NOT change. The regex PII detectors keep the decoding
step they had before this capability, on top of what they read: they remove U+200B to
U+200D and decode percent-encoding and HTML entities. A hidden character that is written
percent-encoded or as an HTML entity is therefore not normalized.

Units of a response-direction message SHALL NOT be normalized: every guard reads the raw
text of a response, whatever its `scan_view` setting, and `/v1/scan` with
`direction=response` SHALL scan the raw text.

The scan view has no setting of its own. The scan view SHALL be the raw text when no rule
below applies to it and no run is decoded.

In the scenarios of this capability, a "hidden" placeholder is a placeholder of a PII
value that no guard reports in its raw form, such as an IBAN placeholder with a soft
hyphen U+00AD between two of its digits. The `pii` guard reads the scan view unless a
scenario says otherwise.

#### Scenario: A hidden value in a plain request body

- **WHEN** a plain-text request body holds an IBAN placeholder with a soft hyphen between
  two digits
- **THEN** the proxy blocks the request and the kinds name the IBAN kind

#### Scenario: A hidden value in a JSON request value

- **WHEN** a JSON request body holds an IBAN placeholder with a soft hyphen written as
  `\u00ad` between two digits
- **THEN** the proxy blocks the request and the kinds name the IBAN kind

#### Scenario: A hidden value in a CSV request body

- **WHEN** a CSV request body holds a cell with an IBAN placeholder with a soft hyphen
  between two digits
- **THEN** the proxy blocks the request and the kinds name the IBAN kind

#### Scenario: A hidden value in a query string

- **WHEN** a request's query string holds an IBAN placeholder with the two raw bytes of a
  soft hyphen between two digits, and a guard scans the query string
- **THEN** the proxy blocks the request and the kinds name the IBAN kind

#### Scenario: A hidden value in a URL path

- **WHEN** a request's path holds an IBAN placeholder with the two raw bytes of a soft
  hyphen between two digits, and a guard scans the path
- **THEN** the proxy blocks the request and the kinds name the IBAN kind

#### Scenario: A hidden value in an openai-chat request

- **WHEN** a Chat Completions request holds a message whose content is an IBAN
  placeholder with a soft hyphen between two digits
- **THEN** the route answers 400 with `code` `content_filter` and the kinds name the IBAN
  kind

#### Scenario: A hidden value sent to /v1/scan

- **WHEN** `/v1/scan` is called without a `direction` and the body holds an IBAN
  placeholder with a soft hyphen between two digits
- **THEN** the response names the IBAN kind

#### Scenario: A hidden value in the LiteLLM request side

- **WHEN** the LiteLLM guardrail route receives request-side texts that hold an IBAN
  placeholder with a soft hyphen between two digits
- **THEN** the route answers `BLOCKED`, and `blocked_reason` names the IBAN kind

#### Scenario: A guard set to read the raw text

- **WHEN** a reverse proxy route selects only the `pii` guard, the guard sets
  `scan_view = false`, and a plain-text request body holds an IBAN placeholder with a
  soft hyphen between two digits
- **THEN** the proxy forwards the request

#### Scenario: No guard reads the scan view

- **WHEN** every guard selected for a request reads the decoded view
- **THEN** no scan view is built for that request

#### Scenario: The response direction is not normalized

- **WHEN** `/v1/scan` is called with `direction=response` and the body holds an IBAN
  placeholder with a soft hyphen between two digits
- **THEN** the response names no IBAN kind

#### Scenario: The forwarded request is unchanged

- **WHEN** a request body that passes every guard holds a soft hyphen and a full-width
  letter
- **THEN** the upstream receives the body byte for byte as the client sent it

#### Scenario: Ordinary non-ASCII text is unchanged

- **WHEN** a request body holds precomposed Polish text, Cyrillic text, Chinese text and
  an emoji, and none of the characters named by the rules below
- **THEN** the scan view is the raw text

#### Scenario: An invalid byte next to a hidden character

- **WHEN** a plain-text request body holds one byte that is not valid UTF-8 and, later, a
  soft hyphen
- **THEN** the scan view holds the invalid byte unchanged and no soft hyphen

### Requirement: Normalization alone never blocks

Normalization SHALL NOT produce a finding. A message SHALL be blocked only when a guard
reports a finding, in the scan view or in the decoded view, whichever that guard reads.

#### Scenario: Invisible characters with no detected content

- **WHEN** a request body holds ordinary text with soft hyphens, bidi controls and a
  backspace, and no guard reports a finding in its scan view
- **THEN** the proxy forwards the request

### Requirement: A span in a normalized unit names the raw bytes it came from

The span of a finding that a guard reports in the scan view SHALL be a byte range of the
raw message. It SHALL start at the first raw byte of the first scan-view character of the finding and end
after the last raw byte of its last scan-view character. A removed character between two
characters of the finding is inside the span. A removed character directly before the
first character or directly after the last character is outside it.

A scan-view character that came from a decoded tag run or variation-selector run SHALL
map to the whole run, with the removed characters inside it. Two findings inside one
decoded run SHALL have the same span and SHALL stay two findings. A scan-view character
that came from a decoded base64 or hex run SHALL map to the whole encoded run, as the
`encoded-content-decoding` capability states.

In a JSON fragment the span SHALL map through the normalization and then through the
escape decoding, so it names bytes of the raw document. The findings of every guard that
reads the scan view SHALL follow this rule. A finding of a guard that reads the decoded
view SHALL follow the span rule of the `encoded-content-decoding` capability.

#### Scenario: A finding after removed characters

- **WHEN** a plain request body holds soft hyphens, then ordinary text, and then an email
  placeholder that a guard reports
- **THEN** the finding's span is the byte range of the placeholder in the raw body

#### Scenario: A finding that holds a removed character

- **WHEN** a plain request body holds an IBAN placeholder with a soft hyphen between two
  digits
- **THEN** the finding's span starts at the first byte of the placeholder and ends after
  its last byte in the raw body, and the two bytes of the soft hyphen are inside it

#### Scenario: Removed characters at the edges of a finding

- **WHEN** a plain request body holds an IBAN placeholder with a soft hyphen directly
  before its first character and directly after its last character
- **THEN** the finding's span is the byte range of the placeholder without the two soft
  hyphens

#### Scenario: A finding inside a decoded run

- **WHEN** a plain request body holds an email placeholder written as Unicode tag
  characters
- **THEN** the finding's span covers the bytes of the whole tag run in the raw body

#### Scenario: Two findings inside one decoded run

- **WHEN** a plain request body holds two different email placeholders, separated by a
  space, written as one run of Unicode tag characters
- **THEN** the result holds two email findings with the same span, and the match count is
  two

#### Scenario: A finding in a JSON value with an escaped hidden character

- **WHEN** a JSON request value holds an IBAN placeholder with `\u00ad` between two
  digits
- **THEN** the finding's span starts at the first byte of the placeholder and ends after
  its last byte in the raw body, and the six bytes of `\u00ad` are inside it

#### Scenario: A finding in a base64 run with a hidden character

- **WHEN** a plain request body holds a soft hyphen inside a base64 run whose decoded text
  is an email placeholder
- **THEN** the finding's span covers the bytes of the whole base64 run in the raw body,
  with the soft hyphen inside it

### Requirement: The rules apply in a fixed order

The normalization of a unit SHALL be the result of these steps, each applied to the
result of the step before it:

1. characters that carry no content are removed;
2. backspaces are applied and the other control characters are removed;
3. Unicode tag runs and variation-selector runs are decoded;
4. full-width ASCII is folded;
5. ZWJ and ZWNJ between ASCII characters are removed;
6. combining marks used as decoration are removed.

The scan view of a unit SHALL be its normalization. For a body unit, the scan view SHALL
then hold its decoded base64, base64url and hex runs, in the order that the
`encoded-content-decoding` capability states.

Each step is one requirement below. A character that an earlier step removed SHALL NOT
separate two characters for a later step.

A run that is split by a character that no step removes, such as visible text or a
combining mark, SHALL be decoded piece by piece. The `invisible_text` guard reports such a
split run of variation selectors, and any tag character outside an emoji flag, in the
decoded view of the `encoded-content-decoding` capability, which keeps these characters.

#### Scenario: A removed character inside a tag run

- **WHEN** a request body holds the word `ignore` written as tag characters, with a soft
  hyphen between each two tag characters
- **THEN** the scan view holds a space, `ignore` and a space where the run was

#### Scenario: A removed character inside a variation-selector run

- **WHEN** a request body holds an emoji followed by variation selectors whose bytes are
  the UTF-8 of an email placeholder, with a zero-width space between each two selectors
- **THEN** the proxy blocks the request and the kinds name the email kind

#### Scenario: A combining grapheme joiner inside a variation-selector run

- **WHEN** a request body holds an emoji followed by variation selectors whose bytes are
  the UTF-8 of an email placeholder, with U+034F between each two selectors
- **THEN** the proxy blocks the request and the kinds name the email kind

#### Scenario: A backspace inside a tag run

- **WHEN** a request body holds the tag characters for `igx`, a backspace, and the tag
  characters for `nore`
- **THEN** the scan view holds a space, `ignore` and a space where the run was

#### Scenario: A full-width letter next to a ZWJ

- **WHEN** a request body holds a full-width `ｉ`, a ZWJ U+200D and `gnore`
- **THEN** the scan view holds `ignore`

