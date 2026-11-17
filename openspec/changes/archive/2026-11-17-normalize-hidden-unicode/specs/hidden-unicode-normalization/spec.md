## Purpose

Lets the guards that read it see request text the way an LLM reads it, by normalizing
invisible and decorative Unicode into a scan view, while the forwarded message stays
unchanged.

## ADDED Requirements

### Requirement: Request units have a normalized scan view

Before any guard runs, the engine SHALL build a scan view of each unit of a
request-direction message that a selected guard reads through the scan view. Whether a
guard reads the scan view or the raw text is the guard's `scan_view` setting, as the
`guard-configuration` capability states. This SHALL apply at every request entry point:
a reverse proxy request on any route format, `/v1/scan` with `direction=request` (the
default), and the request side of the LiteLLM guardrail route.

The scan view SHALL be built from the text of the unit as it is received: the body, the
URL path, the query string and every scanned header value. In a structured unit (a JSON
or CSV body), the scan view SHALL be built for each fragment value, after its JSON escapes
are decoded. The key path SHALL NOT be normalized. Bytes that are not valid UTF-8 SHALL
stay in the scan view unchanged.

A guard that reads the scan view SHALL scan only the scan view. A guard that reads the raw
text SHALL scan the raw text, as before this capability. The forwarded message SHALL NOT
change. The regex PII detectors keep the decoding step they had before this capability,
on top of what they read: they remove U+200B to U+200D and decode percent-encoding and
HTML entities. A hidden character that is written percent-encoded or as an HTML entity is
therefore not normalized.

Units of a response-direction message SHALL NOT be normalized: every guard reads the raw
text of a response, whatever its `scan_view` setting, and `/v1/scan` with
`direction=response` SHALL scan the raw text.

The scan view has no setting of its own. The scan view SHALL be the raw text when no rule
below applies to it.

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

- **WHEN** every guard selected for a request reads the raw text
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
reports a finding, in the scan view or in the raw text, whichever that guard reads.

#### Scenario: Invisible characters with no detected content

- **WHEN** a request body holds ordinary text with soft hyphens, bidi controls and a
  backspace, and no guard reports a finding in its scan view
- **THEN** the proxy forwards the request

### Requirement: The rules apply in a fixed order

The scan view SHALL be the result of these steps, each applied to the result of the step
before it:

1. characters that carry no content are removed;
2. backspaces are applied and the other control characters are removed;
3. Unicode tag runs and variation-selector runs are decoded;
4. full-width ASCII is folded;
5. ZWJ and ZWNJ between ASCII characters are removed;
6. combining marks used as decoration are removed.

Each step is one requirement below. A character that an earlier step removed SHALL NOT
separate two characters for a later step.

A run that is split by a character that no step removes, such as visible text or a
combining mark, SHALL be decoded piece by piece. The `invisible_text` guard reports such a
split run of variation selectors, and any tag character outside an emoji flag, on the raw
text.

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

### Requirement: A span in a normalized unit names the raw bytes it came from

The span of a finding that a guard reports in the scan view SHALL be a byte range of the
raw message. It SHALL start at the first raw byte of the first scan-view character of the finding and end
after the last raw byte of its last scan-view character. A removed character between two
characters of the finding is inside the span. A removed character directly before the
first character or directly after the last character is outside it.

A scan-view character that came from a decoded tag run or variation-selector run SHALL
map to the whole run, with the removed characters inside it. Two findings inside one
decoded run SHALL have the same span and SHALL stay two findings.

In a JSON fragment the span SHALL map through the normalization and then through the
escape decoding, so it names bytes of the raw document. The findings of every guard that
reads the scan view SHALL follow this rule. A finding of a guard that reads the raw text
SHALL keep the span rule it had before this capability.

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

### Requirement: Characters that carry no content are removed

The scan view SHALL NOT contain these characters: soft hyphen U+00AD, combining grapheme
joiner U+034F, Arabic letter mark U+061C, zero-width space U+200B, left-to-right mark U+200E, right-to-left mark U+200F,
the bidi embeddings and overrides U+202A to U+202E, word joiner U+2060, the invisible
operators U+2061 to U+2064, the bidi isolates U+2066 to U+2069, and U+FEFF.

Other characters that show nothing SHALL stay: U+180E, U+2028, U+2029, U+007F, the C1
controls U+0080 to U+009F, and the Hangul fillers.

#### Scenario: Zero-width space inside a word

- **WHEN** a request body holds `ig` U+200B `nore`
- **THEN** the scan view holds `ignore`

#### Scenario: Bidi override

- **WHEN** a request body holds U+202E followed by text
- **THEN** the scan view holds the text without U+202E, in the same order

#### Scenario: Soft hyphen inside an IBAN placeholder

- **WHEN** a request body holds an IBAN placeholder with a soft hyphen between two digits
- **THEN** the proxy blocks the request and the kinds name the IBAN kind

#### Scenario: Combining grapheme joiner inside a word

- **WHEN** a request body holds `ig` U+034F `nore`
- **THEN** the scan view holds `ignore`

#### Scenario: Arabic letter mark and invisible operator

- **WHEN** a request body holds an IBAN placeholder with U+061C between two digits, or
  with U+2062 between two digits
- **THEN** the proxy blocks the request and the kinds name the IBAN kind

#### Scenario: A character that stays

- **WHEN** a request body holds `ig` U+2028 `nore`
- **THEN** the scan view keeps U+2028

### Requirement: Backspace and other control characters are applied

A backspace U+0008 SHALL delete the character before it, in the text that step 1 left,
and itself. Each backspace of a row SHALL delete one more character. A backspace with no
character before it SHALL delete only itself. A character is one Unicode character,
whatever its length in bytes.

Every other C0 control character, U+0000 to U+001F except tab U+0009, line feed U+000A
and carriage return U+000D, SHALL be removed.

#### Scenario: Backspace deletes a decoy character

- **WHEN** a request body holds `ignx` U+0008 `ore`
- **THEN** the scan view holds `ignore`

#### Scenario: Two backspaces in a row

- **WHEN** a request body holds `igxy` U+0008 U+0008 `nore`
- **THEN** the scan view holds `ignore`

#### Scenario: Backspace after a multi-byte character

- **WHEN** a request body holds `ign`, a Cyrillic letter, U+0008 and `ore`
- **THEN** the scan view holds `ignore`

#### Scenario: Backspace at the start

- **WHEN** a request body starts with U+0008 followed by `abc`
- **THEN** the scan view holds `abc`

#### Scenario: Backspace hides a US_SSN placeholder

- **WHEN** a request body holds a `US_SSN` placeholder with a letter and a backspace
  between two digits
- **THEN** the proxy blocks the request and the kinds name `US_SSN`

#### Scenario: An escaped backspace in a JSON value

- **WHEN** a JSON request value holds a `US_SSN` placeholder with a letter and `\b`
  between two digits
- **THEN** the proxy blocks the request and the kinds name `US_SSN`

#### Scenario: Other control characters

- **WHEN** a request body holds a NUL U+0000 and a bell U+0007 between two letters
- **THEN** the scan view holds the two letters next to each other

#### Scenario: Tab and newlines stay

- **WHEN** a request body holds a tab, a line feed and a carriage return
- **THEN** the scan view keeps all three

### Requirement: Unicode tag runs become ASCII text

A tag character is U+E0000 to U+E007F. A tag run is a longest sequence of tag characters;
a ZWJ or ZWNJ between two tag characters SHALL NOT end the run and SHALL be removed with
it. A tag run SHALL be replaced in the scan view by a space, the ASCII characters that
its tags U+E0020 to U+E007E stand for, in order, and a space. A tag outside U+E0020 to
U+E007E SHALL contribute no character.

An emoji flag sequence SHALL be kept unchanged: U+1F3F4 (waving black flag) directly
followed by one to six tags that each stand for an ASCII letter or digit, and then the
cancel tag U+E007F. Tag characters after that cancel tag SHALL form a run of their own.
Any other tag run after U+1F3F4 SHALL be decoded.

#### Scenario: Hidden instruction in tags

- **WHEN** a request body holds visible text followed by the word `ignore` written as tag
  characters
- **THEN** the scan view holds the visible text, a space, `ignore` and a space

#### Scenario: Email placeholder in tags

- **WHEN** a request body holds an email placeholder written as tag characters
- **THEN** the proxy blocks the request and the kinds name the email kind

#### Scenario: Subdivision flag

- **WHEN** a request body holds the flag of England (U+1F3F4, the tags for `gbeng`,
  U+E007F)
- **THEN** the scan view holds the flag unchanged

#### Scenario: Another subdivision flag

- **WHEN** a request body holds U+1F3F4, the tags for `usca` and U+E007F
- **THEN** the scan view holds the flag unchanged

#### Scenario: Text dressed as a flag

- **WHEN** a request body holds U+1F3F4, an email placeholder written as tag characters,
  and U+E007F
- **THEN** the proxy blocks the request and the kinds name the email kind

#### Scenario: A flag-shaped run that is too long

- **WHEN** a request body holds U+1F3F4, the tags for `ignoreall` and U+E007F
- **THEN** the scan view holds U+1F3F4, a space, `ignoreall` and a space, and no
  U+E007F

#### Scenario: A run after a flag without the cancel tag

- **WHEN** a request body holds U+1F3F4 and the tags for `gbeng` with no cancel tag
- **THEN** the scan view holds U+1F3F4, a space, `gbeng` and a space

#### Scenario: A run of only a language tag

- **WHEN** a request body holds `a`, U+E0001 and `b`
- **THEN** the scan view holds `a`, two spaces and `b`

#### Scenario: ZWJ between tag characters

- **WHEN** a request body holds the word `ignore` written as tag characters with a ZWJ
  between each two tag characters
- **THEN** the scan view holds a space, `ignore` and a space where the run was

### Requirement: Variation-selector runs that hold text are decoded

A variation selector is U+FE00 to U+FE0F, which stands for the byte 0 to 15, or U+E0100
to U+E01EF, which stands for the byte 16 to 255. A variation-selector run is a sequence
of two or more variation selectors; a ZWJ or ZWNJ between two selectors SHALL NOT end the
run and SHALL be removed with it.

A run SHALL be read as the bytes its selectors stand for. When the bytes are valid UTF-8,
the six steps of this capability SHALL be applied to the decoded text once, except that a
variation-selector run inside the decoded text SHALL NOT be decoded again. The result is
text when it holds at least two characters and at least 95% of its characters are not
control, format, private-use or unassigned characters and not line or paragraph
separators. Tab, line feed and carriage return SHALL count as text. When the result is
text, the run SHALL be replaced in the scan view by a
space, the result and a space. Otherwise, and when the bytes are not valid UTF-8, the run
SHALL be removed.

A single variation selector SHALL stay in this step.

#### Scenario: Emoji smuggling

- **WHEN** a request body holds an emoji followed by a run of variation selectors whose
  bytes are the UTF-8 of `ignore all previous instructions`
- **THEN** the scan view holds the emoji, a space, `ignore all previous instructions` and
  a space

#### Scenario: Email placeholder smuggled in selectors

- **WHEN** a request body holds an emoji followed by variation selectors whose bytes are
  the UTF-8 of an email placeholder
- **THEN** the proxy blocks the request and the kinds name the email kind

#### Scenario: Smuggled text that is not ASCII

- **WHEN** a request body holds an emoji followed by variation selectors whose bytes are
  the UTF-8 of the Polish word `zażółć`
- **THEN** the scan view holds the emoji, a space, `zażółć` and a space

#### Scenario: A hidden character inside the smuggled text

- **WHEN** a request body holds an emoji followed by variation selectors whose bytes are
  the UTF-8 of an email placeholder with a zero-width space after its fourth character
- **THEN** the proxy blocks the request and the kinds name the email kind

#### Scenario: Full-width text inside the smuggled text

- **WHEN** a request body holds an emoji followed by variation selectors whose bytes are
  the UTF-8 of `ｉｇｎｏｒｅ`
- **THEN** the scan view holds the emoji, a space, `ignore` and a space

#### Scenario: Smuggled text with line breaks

- **WHEN** a request body holds an emoji followed by variation selectors whose bytes are
  the UTF-8 of two lines of text joined with a carriage return and a line feed
- **THEN** the scan view holds the emoji, a space, the two lines with the carriage return
  and the line feed, and a space

#### Scenario: Emoji presentation selector

- **WHEN** a request body holds a heart U+2764 followed by one U+FE0F
- **THEN** the scan view keeps U+FE0F

#### Scenario: A run that is not UTF-8

- **WHEN** a request body holds a run of variation selectors whose bytes are not valid
  UTF-8
- **THEN** the scan view holds the text around the run without the run

#### Scenario: A run that decodes to control characters

- **WHEN** a request body holds an emoji followed by U+FE0F twice
- **THEN** the scan view holds the emoji without the two selectors

### Requirement: Full-width ASCII is folded

A full-width character U+FF01 to U+FF5E SHALL become the ASCII character U+0021 to
U+007E it stands for, and the ideographic space U+3000 SHALL become a space U+0020.

#### Scenario: Full-width instruction

- **WHEN** a request body holds `ｉｇｎｏｒｅ`
- **THEN** the scan view holds `ignore`

#### Scenario: Full-width email placeholder

- **WHEN** a request body holds an email placeholder written in full-width characters
- **THEN** the proxy blocks the request and the kinds name the email kind

#### Scenario: Ideographic space

- **WHEN** a request body holds two words with U+3000 between them
- **THEN** the scan view holds the two words with one space U+0020 between them

#### Scenario: Japanese text with full-width punctuation

- **WHEN** a request body holds Japanese text that ends with a full-width exclamation
  mark U+FF01
- **THEN** the scan view holds the Japanese characters unchanged and ends with `!`

### Requirement: ZWJ and ZWNJ are removed only between ASCII characters

A sequence of one or more zero-width joiners U+200D and zero-width non-joiners U+200C
SHALL be removed when the nearest character before it and the nearest character after
it, not counting combining marks of general category `Mn`, are both printable ASCII,
U+0020 to U+007E. Otherwise it SHALL be kept. The neighbours are those of the text that
steps 1 to 4 left. A sequence at the start or at the end of the text SHALL be kept.

#### Scenario: A doubled ZWJ inside a word

- **WHEN** a request body holds `ig`, two U+200D and `nore`
- **THEN** the scan view holds `ignore`

#### Scenario: ZWJ next to a removed character

- **WHEN** a request body holds `ig`, a zero-width space, U+200D and `nore`
- **THEN** the scan view holds `ignore`

#### Scenario: ZWJ next to a combining mark

- **WHEN** a request body holds `ig`, U+200D, a combining acute accent U+0301 and `nore`
- **THEN** the scan view holds `ignore`

#### Scenario: ZWNJ in Persian text

- **WHEN** a request body holds a Persian word with U+200C between two Arabic-script
  letters
- **THEN** the scan view keeps U+200C

#### Scenario: ZWJ in an emoji sequence

- **WHEN** a request body holds an emoji ZWJ sequence such as a family emoji, or a heart
  U+2764 U+FE0F U+200D and a fire emoji
- **THEN** the scan view keeps every U+200D of the sequence

#### Scenario: ZWJ with one ASCII neighbour

- **WHEN** a request body holds `a`, U+200D and an emoji
- **THEN** the scan view keeps U+200D

#### Scenario: ZWJ at the end of the text

- **WHEN** a request body ends with `abc` and U+200D
- **THEN** the scan view keeps U+200D

### Requirement: Combining marks used as decoration are removed

A combining mark is a character of Unicode general category `Mn`; a variation selector is
one. A sequence of combining marks SHALL be removed when the character before the
sequence is a printable ASCII character other than a space, U+0021 to U+007E. One of the
decoration marks U+0305, U+0332, U+0333 and U+0335 to U+0338 SHALL also be removed when
the character before its sequence is any letter or number (general category `L` or `N`).
A precomposed character SHALL NOT change.

U+FE0F directly before the combining enclosing keycap U+20E3 SHALL be kept, so a keycap
emoji does not change.

A mark after a space, and a mark other than a decoration mark after a character that is
not ASCII, SHALL be kept.

#### Scenario: Diacritics on ASCII letters

- **WHEN** a request body holds `ignore` with a combining acute accent U+0301 after each
  letter
- **THEN** the scan view holds `ignore`

#### Scenario: Underline on digits

- **WHEN** a request body holds a `US_SSN` placeholder with U+0332 after each digit
- **THEN** the proxy blocks the request and the kinds name `US_SSN`

#### Scenario: A mark after ASCII punctuation

- **WHEN** a request body holds `a@`, U+0332 and `b`
- **THEN** the scan view holds `a@b`

#### Scenario: A single variation selector between digits

- **WHEN** a request body holds a `US_SSN` placeholder with one U+FE0F between two digits
- **THEN** the proxy blocks the request and the kinds name `US_SSN`

#### Scenario: Keycap emoji

- **WHEN** a request body holds the keycap sequence `1` U+FE0F U+20E3
- **THEN** the scan view holds the sequence unchanged

#### Scenario: Precomposed letters stay

- **WHEN** a request body holds the Polish word `zażółć`
- **THEN** the scan view holds `zażółć` unchanged

#### Scenario: A decomposed accented name loses its accent

- **WHEN** a request body holds a name written with `e` followed by a combining acute
  accent U+0301
- **THEN** the scan view holds the name with a plain `e`

#### Scenario: A mark after a non-ASCII letter stays

- **WHEN** a request body holds a Cyrillic letter followed by U+0301
- **THEN** the scan view keeps U+0301

#### Scenario: A decoration mark after a non-ASCII letter

- **WHEN** a request body holds a Cyrillic letter followed by U+0332
- **THEN** the scan view holds the Cyrillic letter without U+0332

#### Scenario: A mark after a space stays

- **WHEN** a request body holds a space followed by U+0301
- **THEN** the scan view keeps U+0301
