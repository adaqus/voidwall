## MODIFIED Requirements

### Requirement: JSON flattening produces key-path fragments

The scanner SHALL flatten nested JSON recursively. Each string value SHALL become one
fragment. The context SHALL be the dot-separated key path, built from the decoded keys.
An array element SHALL carry its index in square brackets. A number, a boolean, and a
null SHALL produce no fragment. A fragment offset SHALL point at the value content bytes,
excluding the surrounding quotes.

A fragment's value SHALL be the decoded string: every escape sequence SHALL be resolved
once, as a JSON parser resolves it, and a `\uXXXX` surrogate pair SHALL become one
character. The escaped text SHALL NOT be scanned.

#### Scenario: Nested object

- **WHEN** the body is `{"user": {"phone_number": "555-1234"}}`
- **THEN** one fragment carries the context `user.phone_number` and the value `555-1234`

#### Scenario: Array of strings

- **WHEN** the body is `{"phones": ["555-1234", "555-5678"]}`
- **THEN** the fragments carry the contexts `phones[0]` and `phones[1]`

#### Scenario: Non-string value

- **WHEN** a JSON value is a number, a boolean, or null
- **THEN** the scanner produces no fragment for it

#### Scenario: A Unicode escape

- **WHEN** the body is `{"s": "a@b"}`
- **THEN** the fragment's value is `a@b`

#### Scenario: The two-character escapes

- **WHEN** a string value holds `\"`, `\\`, `\/`, `\b`, `\f`, `\n`, `\r` and `\t`
- **THEN** the fragment's value holds a quote, a backslash, a slash, U+0008, U+000C, a
  newline, a carriage return and a tab

#### Scenario: An escaped backslash before the text of an escape

- **WHEN** the body is `{"s": "a\\u0040b"}`
- **THEN** the fragment's value is `a`, a backslash, and `u0040b`
- **AND** the value does not hold `@`

#### Scenario: A surrogate pair

- **WHEN** a string value holds a character outside the Basic Multilingual Plane written
  as a `\uXXXX` surrogate pair
- **THEN** the fragment's value holds that one character

#### Scenario: An escaped key

- **WHEN** the body is `{"email": "x"}`
- **THEN** the fragment carries the context `email`

### Requirement: A body that fails to parse follows the on_error policy

The scanner SHALL surface a parse failure as an error. Malformed JSON and an
unterminated CSV quote SHALL not be scanned silently.

A JSON body in which one object holds the same key more than once SHALL be a body that
fails to parse, wherever that object is in the body. Two keys that are equal after their
escapes are decoded SHALL be the same key. Every path that reads a JSON body SHALL then
apply its own rule for a body that does not parse.

#### Scenario: Malformed JSON body

- **WHEN** a body claims a JSON content type but does not parse
- **THEN** the scanner returns an error and the `on_error` policy decides the outcome

#### Scenario: A lone surrogate

- **WHEN** a JSON string holds `\ud800` with no low surrogate after it
- **THEN** the body fails to parse

#### Scenario: A duplicate key on a reverse proxy route

- **WHEN** a JSON request body holds `"x": "a", "x": "b"` in one object, then a string
  with an email placeholder, and `on_error` is `fail_close`
- **THEN** the proxy answers 400 and does not forward the request

#### Scenario: A duplicate key in a nested object

- **WHEN** a JSON body holds the same key twice in an object inside an array
- **THEN** the body fails to parse

#### Scenario: A duplicate key written with an escape

- **WHEN** one object holds the keys `"a"` and `"a"`
- **THEN** the body fails to parse

#### Scenario: A duplicate key on an openai-chat route

- **WHEN** a Chat Completions request holds the key `content` twice in one message and
  `on_error` is `fail_open`
- **THEN** the proxy answers 400 and does not forward the request

#### Scenario: A duplicate key on /v1/scan

- **WHEN** a client sends `/v1/scan` a JSON body with a duplicate key
- **THEN** the API answers 400

#### Scenario: A duplicate key on the LiteLLM route

- **WHEN** a LiteLLM guardrail payload holds a duplicate key
- **THEN** the route answers 400

#### Scenario: A duplicate key in a stream chunk

- **WHEN** a stream on an `openai-chat` route holds a `data:` payload with a duplicate key
  and `on_error` is `fail_close`
- **THEN** the proxy stops the stream with `error.code` `malformed_body`

## ADDED Requirements

### Requirement: A span in a JSON value names the raw bytes it was decoded from

A finding's span inside a fragment of a JSON body SHALL be the byte range of the raw
document that the span's characters were decoded from. A character that came from an
escape sequence SHALL map to the whole sequence. The findings of every guard SHALL follow
this rule.

This rule covers a body that is read whole and parsed as one document. It does not cover
a stream on an `openai-chat` route, where the scanned text is joined from many events.

#### Scenario: A value after an escape sequence

- **WHEN** a JSON string holds an escape sequence and then an email placeholder that a
  guard reports
- **THEN** the finding's span is the byte range of the placeholder in the raw body

#### Scenario: A value that holds an escape sequence

- **WHEN** a JSON string holds an email placeholder whose `@` is written as `@`
- **THEN** the finding's span starts at the first byte of the placeholder and ends after
  its last byte in the raw body, and the six bytes of `@` are inside it

#### Scenario: A value that starts and ends with an escape sequence

- **WHEN** a JSON string holds an email placeholder with every character written as a
  `\uXXXX` escape
- **THEN** the finding's span starts at the backslash of the first escape and ends after
  the last hex digit of the last escape

### Requirement: Every JSON path scans decoded values

Every path that reads a JSON body into fragments SHALL scan the decoded values, in both
directions:

- a JSON body on a reverse proxy route, request and response;
- on an `openai-chat` route, the request, the buffered response, and a stream in
  hold-back mode and in buffer mode, both the joined delta strings and the strings
  scanned per event;
- `/v1/scan` with a JSON body;
- the request side and the response side of the LiteLLM guardrail route.

In the scenarios below, "escaped" means that every character of the value is written as a
`\uXXXX` escape, unless the scenario names the escape.

#### Scenario: One escaped character in a JSON request

- **WHEN** a JSON request body on a reverse proxy route holds an email placeholder whose
  `@` is written as `@`
- **THEN** the proxy blocks the request and the kinds name the email kind

#### Scenario: An escaped value in a JSON response

- **WHEN** a JSON response body on a route with response scan on holds an escaped email
  placeholder
- **THEN** the proxy blocks the response and the kinds name the email kind

#### Scenario: A value directly after an escaped newline or tab

- **WHEN** a JSON request body holds a `US_SSN` placeholder directly after `\n`, or
  directly after `\t`
- **THEN** the proxy blocks the request and the kinds name `US_SSN`

#### Scenario: An escaped value in an openai-chat request

- **WHEN** a Chat Completions request holds a message whose content is an escaped email
  placeholder
- **THEN** the route answers 400 with `code` `content_filter` and the kinds name the email
  kind

#### Scenario: An escaped value in an openai-chat buffered response

- **WHEN** an upstream response on an `openai-chat` route holds an escaped email
  placeholder in `choices[0].message.content`
- **THEN** the proxy blocks the response and the upstream body does not reach the client

#### Scenario: An escaped value in a stream delta

- **WHEN** a stream on an `openai-chat` route in hold-back mode carries an escaped email
  placeholder in `delta.content`
- **THEN** the proxy stops the stream

#### Scenario: A value directly after an escaped newline in a stream delta

- **WHEN** a stream on an `openai-chat` route in hold-back mode carries a `US_SSN`
  placeholder directly after `\n` in `delta.content`
- **THEN** the proxy stops the stream

#### Scenario: An escaped value in a string scanned per event

- **WHEN** the upstream sends `data: {"error": {"message": ...}}` whose message holds an
  escaped email placeholder
- **THEN** the proxy stops the stream

#### Scenario: An escaped value in buffer mode

- **WHEN** a route sets `stream = "buffer"` and the stream carries an escaped email
  placeholder in `delta.content`
- **THEN** the proxy answers 400 with `error.code` `content_filter`

#### Scenario: An escaped value on /v1/scan

- **WHEN** a client sends `/v1/scan` a JSON body that holds an escaped email placeholder
- **THEN** the response reports `detected` true and `kinds` holds the email kind

#### Scenario: An escaped value on the LiteLLM request side

- **WHEN** a LiteLLM guardrail call with `input_type` `request` holds a message text that
  is an escaped email placeholder
- **THEN** the route answers 200 with `action` `BLOCKED`, and `blocked_reason` names the
  email kind

#### Scenario: An escaped value on the LiteLLM response side

- **WHEN** a LiteLLM guardrail call with `input_type` `response` holds an escaped email
  placeholder in `texts`
- **THEN** the route reports the email kind
