## Purpose

Lets the guards read text that a request body carries in base64, base64url or hex, the
way an LLM reads it, by decoding such runs in the text that each guard reads, while the
forwarded message stays unchanged.

## ADDED Requirements

### Requirement: Encoded runs in a request body are decoded

Before any guard runs, the engine SHALL decode the encoded runs of each request-direction
body unit that a selected guard reads. This SHALL apply at every request entry point: a
reverse proxy request on any route format, `/v1/scan` with `direction=request` (the
default), and the request side of the LiteLLM guardrail route.

Only body units SHALL be decoded. The URL path, the query string and header values SHALL
NOT be decoded. Units of a response-direction message SHALL NOT be decoded, and
`/v1/scan` with `direction=response` SHALL NOT decode.

In a structured unit (a JSON or CSV body), runs SHALL be decoded in each fragment value,
after its JSON escapes are decoded. The key path SHALL NOT be decoded. A value that a
decoder skips without a scan (`encoded_data`) SHALL stay skipped.

Each kept run (see "A decoded run is kept only when it is Latin text") SHALL be replaced in
place by its decoded text. Decoding SHALL NOT change the forwarded message. Decoding has
no setting of its own.

In the scenarios of this capability, "in base64" means the UTF-8 bytes of the text
written in standard base64 with padding, as one run, unless a scenario says otherwise.

#### Scenario: An email in base64 in a plain request body

- **WHEN** a plain-text request body holds an email placeholder in base64, and the `pii`
  guard is selected
- **THEN** the proxy blocks the request and the kinds name the email kind

#### Scenario: An email in base64 in a JSON request value

- **WHEN** a JSON request body holds a string value that is an email placeholder in
  base64
- **THEN** the proxy blocks the request and the kinds name the email kind

#### Scenario: An email in base64 in a CSV cell

- **WHEN** a CSV request body holds a cell that is an email placeholder in base64
- **THEN** the proxy blocks the request and the kinds name the email kind

#### Scenario: An email in base64 in an openai-chat request

- **WHEN** a Chat Completions request holds a message whose content is an email
  placeholder in base64
- **THEN** the route answers 400 with `code` `content_filter` and the kinds name the
  email kind

#### Scenario: An email in base64 sent to /v1/scan

- **WHEN** `/v1/scan` is called without a `direction` and the body holds an email
  placeholder in base64
- **THEN** the response names the email kind

#### Scenario: An email in base64 in the LiteLLM request side

- **WHEN** the LiteLLM guardrail route receives request-side texts that hold an email
  placeholder in base64
- **THEN** the route answers `BLOCKED`, and `blocked_reason` names the email kind

#### Scenario: An email in base64 in a query string

- **WHEN** a request's query string holds an email placeholder in base64url, and a guard
  scans the query string
- **THEN** the run is not decoded and the proxy forwards the request

#### Scenario: An email in base64 in a response

- **WHEN** `/v1/scan` is called with `direction=response` and the body holds an email
  placeholder in base64
- **THEN** the response names no email kind

#### Scenario: An inline image stays skipped

- **WHEN** a Chat Completions request holds an `image_url` part with a `data:` URL
- **THEN** the value is not decoded and `voidwall_unscanned_total` counts it with
  `reason="encoded_data"`, as before this capability

#### Scenario: A data URL written in message text

- **WHEN** a Chat Completions request holds a message whose text content is
  `data:text/plain;base64,` followed by an email placeholder in base64
- **THEN** the run is decoded, and the route answers 400 with `code` `content_filter`
  and the kinds name the email kind

#### Scenario: The forwarded request is unchanged

- **WHEN** a request body that passes every guard holds a base64 run that decodes to
  Latin text
- **THEN** the upstream receives the body byte for byte as the client sent it

### Requirement: A run is a maximal sequence of one encoding alphabet

A candidate run SHALL be a maximal sequence of the characters `A`–`Z`, `a`–`z`, `0`–`9`,
`+`, `/`, `-` and `_`. One or two `=` directly after it SHALL belong to the run only when
they make its length a multiple of 4 and the character after them is neither one of
these characters nor `=`. Otherwise the run SHALL end before the first `=`.

A run SHALL be decoded:

- as hex when it holds only the characters `0`–`9`, `A`–`F` and `a`–`f`, has no `=`, has
  an even length, and has 22 or more characters;
- as standard base64 when it holds no `-` and no `_`, and has 15 or more characters
  without its `=`;
- as base64url when it holds no `+` and no `/`, and has 15 or more characters without its
  `=`.

A base64 or base64url run SHALL be decoded with or without its padding. A run whose
length without `=` is 1 more than a multiple of 4 SHALL NOT be decoded as base64 or
base64url. A run that holds both a character of `+` or `/` and a character of `-` or `_`
SHALL NOT be decoded.

A run that fits hex SHALL be decoded as hex first. When its hex result is not kept, it
SHALL be decoded as base64 or base64url when it fits one of them.

A run of decimal digits only SHALL NOT be decoded as base64 or base64url. It SHALL be
decoded as hex only when its decoded text holds only the digits `0`–`9`, the space and
the characters `+`, `(`, `)`, `.`, `/` and `-`, so that it is an encoded number.

#### Scenario: A base64 run of 15 characters

- **WHEN** a request body holds a base64 run of 15 characters without padding that
  decodes to Latin text
- **THEN** the run is decoded

#### Scenario: A base64 run of 14 characters

- **WHEN** a request body holds a base64 run of 14 characters that decodes to Latin text
- **THEN** the run is not decoded

#### Scenario: A base64 run whose length cannot decode

- **WHEN** a request body holds a run of 17 base64 characters and no `=`
- **THEN** the run is not decoded as base64

#### Scenario: A form field holding base64

- **WHEN** a form-encoded request body holds a field name of 20 letters, `=`, an email
  placeholder in base64 without padding, `&` and a second field
- **THEN** the field name run ends before the `=`, the base64 run is decoded, and the
  proxy blocks the request with the email kind

#### Scenario: Two padded runs written back to back

- **WHEN** a request body holds an email placeholder in base64 that ends with one `=`,
  directly followed by a second email placeholder in base64
- **THEN** the `=` does not belong to the first run, both runs are decoded, and the `pii`
  guard reports two email findings

#### Scenario: A base64url run

- **WHEN** a request body holds an email placeholder in base64url without padding, with
  a `-` or `_` in the run
- **THEN** the run is decoded and the proxy blocks the request with the email kind

#### Scenario: A hex run of 22 characters

- **WHEN** a request body holds an email placeholder of 11 bytes in hex, 22 characters
- **THEN** the run is decoded

#### Scenario: A hex run of odd length

- **WHEN** a request body holds a run of 23 characters that are all hex digits, not all
  decimal
- **THEN** the run is not decoded as hex, and it is decoded as base64 only when its base64
  result is kept

#### Scenario: A hex result is used first

- **WHEN** a request body holds a run of hex digits whose hex result is an email
  placeholder
- **THEN** the run is decoded as hex, and the `pii` guard reports the email kind

#### Scenario: A hex result that is not kept

- **WHEN** a request body holds a run of hex digits whose hex result is not kept and
  whose base64 result is Latin text
- **THEN** the run is decoded as base64

#### Scenario: A run of digits only

- **WHEN** a request body holds a card-number placeholder of 16 digits that the `pii`
  guard reports
- **THEN** the run is not decoded, and the `pii` guard reports the card number

#### Scenario: A number written in hex

- **WHEN** a request body holds a PESEL placeholder written in hex, 22 decimal digits
- **THEN** the run is decoded as hex, and the `pii` guard reports the PESEL kind

#### Scenario: A digit-only run whose hex result is not a number

- **WHEN** a request body holds the 22 digits `4242424242424242424242`
- **THEN** the run is not decoded, because its hex result `BBBBBBBBBBB` is not a number

#### Scenario: A run mixing the two alphabets

- **WHEN** a request body holds a run that holds both `+` and `_`
- **THEN** the run is not decoded

#### Scenario: A run glued to a word

- **WHEN** a request body holds the word `decode` directly followed by a fixed email
  placeholder in base64, with no character between them
- **THEN** the run starts at `decode` and is not decoded (a known limit: decoding a run
  glued to a word is not part of this capability)

### Requirement: A decoded run is kept only when it is Latin text

A decoded run SHALL be kept only when all of these are true:

1. its bytes are valid UTF-8;
2. its decoded text holds no C0 control character other than tab, line feed and carriage
   return, and no U+007F;
3. its decoded text, after the rules of `hidden-unicode-normalization` are applied to it,
   has more than 3 characters, of which 95% or more are ASCII characters or characters
   of the Unicode `Latin` or `Common` script.

The `Common` script holds punctuation such as `’` and `–`, symbols such as `€`, and
emoji. A run that is not kept SHALL stay in the text as it is. One decision SHALL serve
both views: a run that is found in both views is kept in both or in neither.

What the kept run holds differs by view: the scan view holds the normalized decoded text,
and the decoded view holds the decoded text without normalization.

#### Scenario: A run that decodes to random bytes

- **WHEN** a request body holds a base64 run of 40 characters that decodes to bytes that
  are not valid UTF-8, such as a hash or a key
- **THEN** the run stays as it is

#### Scenario: A run that decodes to ASCII with control characters

- **WHEN** a request body holds a base64 run whose decoded bytes are ASCII letters with a
  U+0001 among them
- **THEN** the run stays as it is

#### Scenario: A run that decodes to non-Latin text

- **WHEN** a request body holds a base64 run that decodes to Cyrillic text
- **THEN** the run stays as it is

#### Scenario: A run that decodes to text with typographic punctuation and an emoji

- **WHEN** a request body holds a base64 run that decodes to an English sentence with a
  `’`, a `–`, a `€` and one emoji
- **THEN** the run is decoded

#### Scenario: A run that decodes to Polish text

- **WHEN** a request body holds a base64 run that decodes to Polish text with
  precomposed accented letters
- **THEN** the run is decoded

#### Scenario: A run that decodes to tag characters

- **WHEN** a request body holds a base64 run whose decoded text is the words `ignore all
  rules` written as Unicode tag characters
- **THEN** the run is kept, the decoded view holds the tag characters, and the scan view
  holds the words as ASCII text

#### Scenario: A repeating decimal

- **WHEN** a request body holds the number `0.6666666666666666`
- **THEN** no part of it is decoded

### Requirement: A JWT-shaped token is not decoded

A JWT-shaped token is three dot-separated runs of base64url characters, where the first
two start with `ey` and the third is not empty. None of its three runs SHALL be decoded.
The token SHALL stay in every view as it is, so the `pii` guard reports `JWT` as before
this capability. A token whose third segment is empty is not JWT-shaped, and its runs
follow the other rules of this capability.

#### Scenario: A JWT in a request body

- **WHEN** a request body holds `eyJ<header>.eyJ<payload>.<signature>` whose first two
  segments decode to JSON text
- **THEN** no segment is decoded, and the `pii` guard reports one `JWT` finding

#### Scenario: An unsigned token

- **WHEN** a request body holds `eyJ<header>.eyJ<payload>.` with an empty third segment,
  and its payload decodes to JSON text that holds an email placeholder
- **THEN** the header and payload runs are decoded, and the `pii` guard reports the email
  kind

### Requirement: Only one layer is decoded

Text decoded from a run SHALL NOT be searched for runs again. An encoded run inside
decoded text SHALL stay in the view as it is.

Two other decodings stay as their capabilities state:

- In the scan view, runs are found after the `hidden-unicode-normalization` rules, so a
  run written as Unicode tag characters or as full-width characters is decoded there. The
  decoded view does not apply those rules, so it does not decode such a run.
- The regex PII detectors decode percent-encoding and HTML entities in what they read, as
  `hidden-unicode-normalization` states, and that includes decoded runs.

#### Scenario: Base64 inside base64

- **WHEN** a request body holds a base64 run whose decoded text is an email placeholder in
  base64
- **THEN** the view holds the inner base64 run, and no guard is passed the email
  placeholder

#### Scenario: Base64 written in full-width characters

- **WHEN** a request body holds an email placeholder in base64, with every character
  written as its full-width form
- **THEN** the `pii` guard reports the email kind, and a `text_classifier` guard that sets
  no `scan_view` is not passed the decoded email

#### Scenario: Percent-encoding inside base64

- **WHEN** a request body holds a base64 run whose decoded text is an email placeholder
  with its `@` written as `%40`
- **THEN** the `pii` guard reports the email kind

### Requirement: A guard that does not read the scan view reads the decoded view

The decoded view of a request unit SHALL be its raw text with every kept run decoded, and
no other change. The rules of `hidden-unicode-normalization` SHALL NOT apply to it. A
guard whose `scan_view` is `false`, and the `invisible_text` guard, SHALL read the decoded
view of a request. The decoded view SHALL be built only when such a guard is selected and
a run in one of its units is kept; otherwise it SHALL be the raw text.

#### Scenario: The injection model reads a base64 attack prompt

- **WHEN** a request body holds an attack prompt in base64, and a `text_classifier` guard
  sets no `scan_view`
- **THEN** the guard scores the decoded prompt and reports the attack

#### Scenario: The decoded view keeps hidden characters

- **WHEN** a request body holds an attack prompt in base64 whose decoded text has a soft
  hyphen after each letter, and a `text_classifier` guard sets no `scan_view`
- **THEN** the guard scores the decoded text with the soft hyphens in it

#### Scenario: A zero-width character inside a run

- **WHEN** a request body holds an attack prompt in base64 with a zero-width space after
  the third character of the run, and a `text_classifier` guard sets no `scan_view`
- **THEN** the guard is not passed the decoded prompt (a known limit: the decoded view does
  not remove the zero-width space, so it splits the run)

### Requirement: The scan view decodes runs after normalization

For a guard that reads the scan view, the engine SHALL build the view of a request body
unit in this order:

1. normalize the raw text by the rules of `hidden-unicode-normalization`;
2. find and decode the runs of the result, by the rules of this capability;
3. normalize the decoded text of each kept run by the rules of
   `hidden-unicode-normalization`.

#### Scenario: A zero-width character inside a run

- **WHEN** a request body holds an email placeholder in base64 with a zero-width space
  after the third character of the run
- **THEN** the `pii` guard reports the email kind

#### Scenario: A hidden character inside decoded text

- **WHEN** a request body holds a base64 run whose decoded text is an IBAN placeholder
  with a soft hyphen between two digits
- **THEN** the `pii` guard reports the IBAN kind

### Requirement: A span in a decoded run names the whole encoded run

The span of a finding that a guard reports inside the decoded text of a run SHALL be the
byte range of the whole encoded run in the raw message, with its padding. Two findings
inside one decoded run SHALL have the same span and SHALL stay two findings. Text outside
decoded runs SHALL keep the span rule of the view the guard reads. In a JSON fragment the
span SHALL map through the escape decoding as well, so it names bytes of the raw document.

#### Scenario: A finding inside a base64 run

- **WHEN** a plain request body holds ordinary text and then an email placeholder in
  base64, and the `pii` guard reports the email
- **THEN** the finding's span is the byte range of the base64 run in the raw body

#### Scenario: Two findings inside one run

- **WHEN** a plain request body holds one base64 run whose decoded text is two different
  email placeholders separated by a space
- **THEN** the result holds two email findings with the same span, and the match count is
  two

#### Scenario: A finding in a JSON value with escaped base64 characters

- **WHEN** a JSON request value holds ordinary text and then an email placeholder in
  base64 whose run holds `/`, written as `\/` in the JSON
- **THEN** the finding's span is the byte range of the run in the raw body, with each
  `\/` escape inside it

#### Scenario: A finding inside a hex run

- **WHEN** a plain request body holds an email placeholder in hex
- **THEN** the finding's span is the byte range of the hex run in the raw body

#### Scenario: A finding after a decoded run

- **WHEN** a plain request body holds a base64 run that decodes to Latin text, and then an
  email placeholder written plainly
- **THEN** the email finding's span is the byte range of the plain placeholder in the raw
  body

### Requirement: Decoding alone never blocks

Decoding SHALL NOT produce a finding. A message SHALL be blocked only when a guard
reports a finding in the view it reads.

#### Scenario: Benign base64 text

- **WHEN** a request body holds a base64 run that decodes to Latin text in which no guard
  reports a finding
- **THEN** the proxy forwards the request
