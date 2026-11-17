## ADDED Requirements

### Requirement: A guard chooses the scan view or the raw text

The `[builtin_guards.pii]` section and every `[guards.<name>]` section MAY set
`scan_view`, a boolean. It SHALL decide whether the guard reads a request unit through
the scan view that the `hidden-unicode-normalization` capability builds (`true`) or as
raw text (`false`). The defaults SHALL be:

- `true` for the `pii` guard;
- `true` for a model guard with `adapter = "token_classifier"`;
- `false` for a model guard with `adapter = "text_classifier"`.

`scan_view` SHALL change only what the guard reads in the request direction. It SHALL NOT
change the guard's directions, its surface, or how its findings block. A value that is not
a boolean SHALL fail the schema. The `hidden_context` and `invisible_text` sections SHALL
NOT accept `scan_view`.

#### Scenario: Defaults of the shipped guards

- **WHEN** the config declares the `pii` guard, a `text_classifier` guard and a
  `token_classifier` guard, and none sets `scan_view`
- **THEN** the `pii` guard and the `token_classifier` guard read the scan view of a
  request, and the `text_classifier` guard reads its raw text

#### Scenario: A text classifier set to read the scan view

- **WHEN** a `text_classifier` guard sets `scan_view = true`
- **THEN** the file loads and the guard reads the scan view of a request

#### Scenario: The pii guard set to read the raw text

- **WHEN** `[builtin_guards.pii]` sets `scan_view = false`
- **THEN** the file loads and the guard reads the raw text of a request

#### Scenario: A value that is not a boolean

- **WHEN** a model guard sets `scan_view = "yes"`
- **THEN** the schema rejects the file

#### Scenario: The pii guard reads the raw text of a response

- **WHEN** `[builtin_guards.pii]` sets `scan_view = true`, and a response body holds an
  IBAN placeholder with a soft hyphen between two digits
- **THEN** the guard reads the raw text of the response and reports no IBAN

#### Scenario: The hidden context guard sets scan_view

- **WHEN** `[builtin_guards.hidden_context]` sets `scan_view = true`
- **THEN** the schema rejects the file

## MODIFIED Requirements

### Requirement: A built-in guard is declared in its own section

A guard that ships with Voidwall SHALL be declared under `[builtin_guards.<name>]`,
where `<name>` is drawn from a fixed set the build defines. `pii`, `hidden_context` and
`invisible_text` SHALL be the only names in that set. A built-in guard SHALL NOT carry a
`type` field: its section key identifies it.

A built-in guard SHALL be a singleton. The section shape SHALL admit one instance per
name, so two instances of one built-in guard SHALL NOT be expressible.

#### Scenario: The built-in PII guard is declared

- **WHEN** the config holds a `[builtin_guards.pii]` table
- **THEN** the proxy builds the regex PII guard from it

#### Scenario: The built-in hidden context guard is declared

- **WHEN** the config holds a `[builtin_guards.hidden_context]` table with one marker
- **THEN** the proxy builds the `hidden_context` guard from it

#### Scenario: The built-in invisible text guard is declared

- **WHEN** the config holds an empty `[builtin_guards.invisible_text]` table
- **THEN** the proxy builds the `invisible_text` guard from it

#### Scenario: An unknown built-in name

- **WHEN** the config holds a `[builtin_guards.jailbreak]` table
- **THEN** validation fails naming the unknown built-in guard

#### Scenario: A built-in guard carries a type field

- **WHEN** `[builtin_guards.pii]` sets `type`
- **THEN** the schema rejects the file

### Requirement: A guard declares its scan surface

Each guard except `hidden_context` and `invisible_text` SHALL carry a `surface` table
holding `url_path`, `query_params`, `body`, and `headers`. The surface SHALL be the
configuration form of the guard's declared interest: the engine SHALL pass a guard only
the units its surface admits.

The surface SHALL be per guard, not global. A unit kind no enabled guard admits SHALL
NOT be built. A built-in guard's surface SHALL default `url_path`, `query_params`, `body`,
and `headers` to true.

`headers` SHALL be a boolean and SHALL NOT be a list of header names. Which header values a
message is decoded into is a property of the traffic rather than of a detector, so the set
SHALL be declared per route — see "A route names the headers it exposes to detection". The
guard's boolean SHALL decide only whether that guard sees the header units the route built.

A surface that disables every target SHALL fail validation, because it describes a guard
that can never be called.

The `hidden_context` guard's interest SHALL be fixed to the response body. Its section
SHALL NOT accept a `surface` key.

The `invisible_text` guard's interest SHALL be fixed to every unit kind of a request: the
URL path, the query string, the body, and every header value the route named. Its section
SHALL NOT accept a `surface` key. A route that selects it therefore builds every one of
these units for a request.

#### Scenario: Default surface

- **WHEN** a built-in guard section omits `surface`
- **THEN** the guard inspects the URL path, the query string, the body, and every header
  value the route named

#### Scenario: A target is disabled for one guard

- **WHEN** a guard sets `surface.body = false`
- **THEN** that guard is not called with the body unit

#### Scenario: One guard declines header units and another admits them

- **WHEN** a route names a header, one selected guard sets `surface.headers = false`, and
  another selected guard admits them
- **THEN** that header value is decoded into a unit, the admitting guard is called with
  it, and the declining guard is not

#### Scenario: Every selected guard declines header units

- **WHEN** a route names a header and every guard it selected sets
  `surface.headers = false`
- **THEN** that header value is never decoded into a unit, because a unit kind no
  selected guard admits is not built

#### Scenario: The invisible text guard admits header units

- **WHEN** a route names a header, selects `invisible_text`, and every other guard it
  selected sets `surface.headers = false`
- **THEN** that header value is decoded into a unit on a request, and only the
  `invisible_text` guard is called with it

#### Scenario: The surface names a header

- **WHEN** a guard sets `surface.headers` to a list of header names
- **THEN** the schema rejects the file

#### Scenario: Every target is disabled

- **WHEN** a guard disables `url_path`, `query_params`, `body`, and `headers`
- **THEN** validation fails naming the guard

#### Scenario: The hidden context guard sets a surface

- **WHEN** `[builtin_guards.hidden_context]` sets `surface`
- **THEN** the schema rejects the file

#### Scenario: The invisible text guard sets a surface

- **WHEN** `[builtin_guards.invisible_text]` sets `surface`
- **THEN** the schema rejects the file

### Requirement: A guard inspects the directions its kind fixes

Each guard SHALL be passed units of the directions it inspects and no other. The `pii`
guard and every model guard SHALL inspect both requests and responses. The
`hidden_context` guard SHALL inspect responses only. The `invisible_text` guard SHALL
inspect requests only. No setting SHALL change a guard's directions.

#### Scenario: A request on a route selecting both built-in guards

- **WHEN** a route selects `pii` and `hidden_context` and a request holds an email
  placeholder and a marker
- **THEN** the `pii` guard is called with the request units, the `hidden_context` guard
  is not called, and the request is blocked with `kinds` `["EMAIL"]`

#### Scenario: A response on the same route

- **WHEN** the upstream response on that route holds a marker and no PII
- **THEN** both guards are called with the response body, and the response is blocked
  with `kinds` `["HIDDEN_CONTEXT"]`

#### Scenario: A response on a route selecting the invisible text guard

- **WHEN** a route selects `invisible_text` and the upstream response holds a tag run
- **THEN** the `invisible_text` guard is not called and the response is forwarded

### Requirement: A model guard scores the text of a unit

A model guard SHALL score one text per unit. For a plain-text unit, the text SHALL be the
unit's bytes decoded as UTF-8, with every invalid byte sequence replaced by U+FFFD. For a
unit parsed into fragments (a JSON body), the text SHALL be the fragments' decoded values
in document order, joined with a newline; keys SHALL NOT be part of it.

In the request direction, when the guard reads the scan view (`scan_view`, see "A guard
chooses the scan view or the raw text"), the bytes of a plain-text unit and the values of
a fragment SHALL be those of the scan view that the `hidden-unicode-normalization`
capability builds. Otherwise they SHALL be the raw text.

The span of a `token_classifier` finding SHALL name the unit's bytes:
- in a plain-text unit, the byte range the span's characters were decoded from; a
  U+FFFD maps to the invalid bytes it replaced;
- in a unit parsed into fragments, the document-absolute byte range that the span's
  characters were decoded from inside one fragment value; a character from an escape
  sequence maps to the whole sequence.

When the guard reads the scan view, the span SHALL name bytes of the raw unit, by the
span rule of `hidden-unicode-normalization`.

The newline that joins two fragments SHALL be a boundary no span crosses: words on its two
sides SHALL NOT merge.

#### Scenario: A plain-text unit holds an invalid byte

- **WHEN** a request body holds an attack prompt and one byte that is not valid UTF-8
- **THEN** the guard scores the decoded text and reports the attack

#### Scenario: A JSON body

- **WHEN** a JSON request body holds an attack prompt as one string value among others
- **THEN** the guard scores the values joined with newlines and reports one finding for
  the body

#### Scenario: An escaped attack prompt in a JSON body

- **WHEN** a JSON request body holds an attack prompt with every character written as a
  `\uXXXX` escape
- **THEN** the guard scores the decoded prompt and reports the attack

#### Scenario: A text classifier reads the raw text by default

- **WHEN** a request body holds an attack prompt with a soft hyphen after each letter,
  and a `text_classifier` guard sets no `scan_view`
- **THEN** the guard scores the raw text, with the soft hyphens in it

#### Scenario: A text classifier set to read the scan view

- **WHEN** a request body holds an attack prompt with a soft hyphen after each letter,
  and a `text_classifier` guard sets `scan_view = true`
- **THEN** the guard scores the scan view, which holds the prompt without soft hyphens,
  and reports the attack

#### Scenario: A token classifier reads the scan view by default

- **WHEN** a request body holds a name with a soft hyphen between two of its letters,
  and a `token_classifier` guard sets no `scan_view`
- **THEN** the guard scores the scan view and reports the name

#### Scenario: The response direction

- **WHEN** a response body holds a name with a soft hyphen between two of its letters,
  and a `token_classifier` guard sets no `scan_view`
- **THEN** the guard scores the raw text, with the soft hyphen in it

#### Scenario: A span after an invalid byte

- **WHEN** a plain-text body holds one invalid byte before a value a `token_classifier`
  guard reports
- **THEN** the finding's span is the byte range of that value in the body

#### Scenario: A span in a JSON value

- **WHEN** a JSON body holds a value that a `token_classifier` guard reports, inside its
  second string value
- **THEN** the finding's span is the value's document-absolute byte range in the body

#### Scenario: A span in a JSON value with escaped non-ASCII

- **WHEN** a JSON body holds a name that a `token_classifier` guard reports, with its
  non-ASCII letters written as `\uXXXX` escapes
- **THEN** the guard reports the name, and the finding's span is the byte range of the
  escaped name in the raw body

#### Scenario: A span after removed characters in a request

- **WHEN** a plain-text request body holds soft hyphens, then ordinary text, and then a
  name that a `token_classifier` guard reports through the scan view
- **THEN** the finding's span is the byte range of the name in the raw body

#### Scenario: Two values of one type in neighbouring fragments

- **WHEN** one JSON string ends with a name and the next JSON string starts with a name
- **THEN** the guard reports two spans, one inside each value
