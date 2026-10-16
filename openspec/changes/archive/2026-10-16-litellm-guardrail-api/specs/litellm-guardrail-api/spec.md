## Purpose

Lets a LiteLLM gateway use Voidwall as an outside guardrail through LiteLLM's Generic
Guardrail API, on the request side and on the response side of every call LiteLLM proxies.

## ADDED Requirements

### Requirement: The REST API serves the LiteLLM Generic Guardrail API route

When `http_api.enabled` and `http_api.litellm.enabled` are both true, the HTTP API
listener SHALL serve `POST /beta/litellm_basic_guardrail_api`, whatever
`http_api.scan.enabled` says. When `http_api.litellm.enabled` is false, the route SHALL
NOT exist.

The route SHALL run every enabled guard, as `/v1/scan` does. It SHALL NOT authenticate a
caller.

#### Scenario: The route is on

- **WHEN** `http_api.enabled` is true, `http_api.litellm.enabled` is not set, and a client
  posts a LiteLLM payload to `/beta/litellm_basic_guardrail_api`
- **THEN** the listener answers it

#### Scenario: The route is off

- **WHEN** `http_api.litellm.enabled` is false and a client posts to
  `/beta/litellm_basic_guardrail_api`
- **THEN** the listener returns 404
- **AND** `POST /v1/scan` is still served

#### Scenario: The route without /v1/scan

- **WHEN** `http_api.scan.enabled` is false and a client posts a LiteLLM payload to
  `/beta/litellm_basic_guardrail_api`
- **THEN** the listener answers it

### Requirement: The route accepts a JSON body within max_body_size

The route SHALL accept a body with a JSON media type only, and SHALL answer 415 with the
body `{"error":"unsupported content type"}` to any other. The top-level `content_types`
allowlist SHALL NOT apply to the route. The top-level `max_body_size` SHALL apply to the
route as it applies to `/v1/scan`.

#### Scenario: JSON is admitted although content_types omits it

- **WHEN** `content_types` does not list `application/json` and a client posts a LiteLLM
  payload with `Content-Type: application/json`
- **THEN** the route scans it

#### Scenario: Another content type

- **WHEN** a client posts to the route with `Content-Type: text/plain`
- **THEN** the route answers 415

#### Scenario: Body is too large

- **WHEN** a posted body exceeds `max_body_size`
- **THEN** the route answers as `/v1/scan` answers an oversize body

### Requirement: A malformed LiteLLM payload is a client error

The route SHALL answer 400 with the body
`{"error":"malformed body for declared content type"}`, whatever `on_error` says, when
the body does not parse as JSON, is not a JSON object, or carries no `input_type` of
`request` or `response`. A top-level field the route does not know SHALL be ignored.

#### Scenario: Body is not JSON

- **WHEN** a client posts a body that does not parse as JSON
- **THEN** the route answers 400 under `fail_open` and under `fail_close` alike

#### Scenario: input_type is missing

- **WHEN** a client posts a JSON object with no `input_type`
- **THEN** the route answers 400

#### Scenario: An unknown top-level field

- **WHEN** a payload carries a top-level field `future_field` that holds a PII
  placeholder value
- **THEN** the route does not scan `future_field`

### Requirement: The request side is read from structured messages, tools, and tool calls

When `input_type` is `request`, the route SHALL scan these fields:

- In each message of `structured_messages`: `content` when it is a string; in a
  `content` array, `text` of a `text` part, `refusal` of a `refusal` part, and
  `file.filename` of a `file` part; `name`; `refusal`; and, in each of `tool_calls`,
  `function.name`, `function.arguments`, `custom.name`, and `custom.input`; and
  `function_call.name` and `function_call.arguments`.
- In each entry of `tools`: `function.name`, `function.description`, every string value in
  `function.parameters`, `custom.name`, `custom.description`, and
  `custom.format.grammar.definition`.
- In each entry of `tool_calls`: the same fields as in a message's `tool_calls`.

It SHALL NOT scan `role`, `tool_call_id`, a tool call's `id` or `type`, `audio.id`,
`image_url.detail`, `file.file_id`, `function.strict`, or a tool that carries only a
`type`.

It SHALL scan `texts` only when `structured_messages` is missing.

#### Scenario: A system message

- **WHEN** a request payload holds a `system` message whose content carries an email
  placeholder
- **THEN** the route reports the email kind

#### Scenario: A tool message

- **WHEN** a request payload holds a `tool` message whose content carries an email
  placeholder
- **THEN** the route reports the email kind

#### Scenario: Tool-call arguments in a replayed assistant message

- **WHEN** a request payload holds an assistant message whose
  `tool_calls[].function.arguments` carries an email placeholder
- **THEN** the route reports the email kind

#### Scenario: A tool description

- **WHEN** a request payload holds a `tools[].function.description` that carries an
  email placeholder
- **THEN** the route reports the email kind

#### Scenario: A built-in tool with only a type

- **WHEN** a request payload holds `tools` with `{"type": "code_interpreter"}`
- **THEN** the route accepts the payload and scans nothing from that tool

#### Scenario: texts is ignored when structured messages exist

- **WHEN** a request payload holds `structured_messages` with no PII and `texts` with an
  email placeholder
- **THEN** the route answers `NONE`

#### Scenario: texts is the fallback

- **WHEN** a request payload has no `structured_messages` and holds `texts` with an email
  placeholder
- **THEN** the route reports the email kind

### Requirement: The response side is read from texts and tool calls

When `input_type` is `response`, the route SHALL scan each string in `texts`, and in
each entry of `tool_calls` the fields the request side scans in a tool call.

#### Scenario: Model output

- **WHEN** a response payload holds `texts` with an email placeholder
- **THEN** the route reports the email kind

#### Scenario: Model tool call

- **WHEN** a response payload holds a `tool_calls[].function.arguments` with an email
  placeholder
- **THEN** the route reports the email kind

### Requirement: Caller identity and headers are not scanned

The route SHALL NOT scan `request_data` or `request_headers`.

#### Scenario: The caller's email in request_data

- **WHEN** a payload holds `request_data.user_api_key_user_email` with an email
  placeholder and no other PII
- **THEN** the route answers `NONE`

### Requirement: An unknown field or role is scanned generically

Inside a message, a tool, or a tool call, a field the route does not know SHALL have
every string value under it scanned. A message whose `role` the route does not know
SHALL have every string value in it scanned.

#### Scenario: An unknown field on an assistant message

- **WHEN** a request payload holds an assistant message with a `reasoning_content` field
  that carries an email placeholder
- **THEN** the route reports the email kind

#### Scenario: An unknown role

- **WHEN** a request payload holds a message with `role` `narrator` whose content carries
  an email placeholder
- **THEN** the route reports the email kind

### Requirement: An unknown content part type follows on_error

A content part in a message's `content` array whose `type` is not `text`, `image_url`,
`input_audio`, `file`, or `refusal` SHALL be unscannable. Under `fail_close` the route
SHALL answer 422 with the body exactly `{"error":"unscannable content"}` and SHALL run no
guard. Under `fail_open` the route SHALL skip the part and scan the rest. Either way
`voidwall_errors_total` SHALL increment with `reason="unscannable_content"` and the
`outcome` the message took.

The 422 body SHALL NOT name the unknown type.

#### Scenario: Unknown part under fail_close

- **WHEN** a request payload holds a content part with `type` `hologram` and `on_error`
  is `fail_close`
- **THEN** the route answers 422 with the body `{"error":"unscannable content"}`
- **AND** `voidwall_errors_total` increments with `outcome="blocked"` and
  `reason="unscannable_content"`

#### Scenario: Unknown part under fail_open

- **WHEN** a request payload holds a content part with `type` `hologram`, a `text` part
  with an email placeholder, and `on_error` is `fail_open`
- **THEN** the route reports the email kind
- **AND** `voidwall_errors_total` increments with `outcome="passed"` and
  `reason="unscannable_content"`

### Requirement: Encoded data is skipped and counted

The route SHALL NOT scan base64 data: an `image_url.url` that starts with `data:`,
`input_audio.data`, `file.file_data`, and each string in `images` that starts with
`data:`. It SHALL increment `voidwall_unscanned_total` once for each skipped value, with
`reason="encoded_data"`.

When `input_type` is `request` and `structured_messages` exists, the route SHALL ignore
`images`, because LiteLLM copies the image URLs of the messages into it.

#### Scenario: An inline image

- **WHEN** a request payload holds one user message with an `image_url` data URL and a
  `text` part with no PII
- **THEN** the route answers `NONE`
- **AND** `voidwall_unscanned_total` increments by one with `reason="encoded_data"`

#### Scenario: An image URL

- **WHEN** a request payload holds an `image_url` whose `url` starts with `https://`
- **THEN** `voidwall_unscanned_total` does not increment

#### Scenario: images without structured messages

- **WHEN** a payload has no `structured_messages` and holds `images` with one `data:`
  URL and one `https://` URL
- **THEN** `voidwall_unscanned_total` increments by one with `reason="encoded_data"`

### Requirement: The route answers NONE or BLOCKED

The route SHALL answer 200 with a JSON body. When no guard reports a finding, the body
SHALL be `{"action":"NONE"}`. When a guard reports a finding, the body SHALL be
`{"action":"BLOCKED","blocked_reason":"<reason>"}`, where `<reason>` is
`Voidwall blocked the message. Kinds: ` followed by the sorted kind names joined by
`, `, each once. The kinds SHALL be the same set a 403 of the reverse proxy would list.

The route SHALL NOT answer `GUARDRAIL_INTERVENED`, and SHALL NOT return `texts`,
`images`, or `structured_messages`. No answer SHALL carry a detected value.

#### Scenario: Clean payload

- **WHEN** a payload holds no PII
- **THEN** the route answers 200 with `{"action":"NONE"}`

#### Scenario: Two kinds

- **WHEN** a payload holds an IBAN placeholder and an email placeholder
- **THEN** the route answers 200 with `action` `BLOCKED`
- **AND** `blocked_reason` is `Voidwall blocked the message. Kinds: ` followed by the two
  kind names in sorted order
- **AND** the body holds neither placeholder value

### Requirement: Errors follow the HTTP API error rules

A scanner failure, a model guard inference failure, and a window limit SHALL answer as
they answer on `/v1/scan`. Under `fail_close` that is a 500 or 413 with the fixed body,
even when another guard reported a finding. Under `fail_open` the route SHALL answer 200
from the findings of the guards that succeeded: `BLOCKED` when they hold a finding, and
`NONE` when they hold none.

#### Scenario: Scanner failure under fail_close

- **WHEN** a guard fails and `on_error` is `fail_close`
- **THEN** the route answers 500 with the body `{"error":"internal error"}`

#### Scenario: Scanner failure under fail_open with no finding

- **WHEN** a guard fails, no other guard reports a finding, and `on_error` is
  `fail_open`
- **THEN** the route answers 200 with `{"action":"NONE"}`

#### Scenario: Scanner failure under fail_open with a finding

- **WHEN** a guard fails, another guard reports a finding, and `on_error` is `fail_open`
- **THEN** the route answers 200 with `action` `BLOCKED`

### Requirement: The route records metrics as the HTTP API does

The route SHALL record `voidwall_requests_total`, `voidwall_request_duration_seconds`,
`voidwall_pii_detections_total`, `voidwall_detections_total`, and `voidwall_errors_total`
by the rules `/v1/scan` follows, with `mode="http_api"` and `route="global"`. The
`direction` label SHALL be `request` when `input_type` is `request`, and `response` when
it is `response`.

The route SHALL NOT increment `voidwall_blocked_total` or `voidwall_pii_blocked_total`,
also when it answers `BLOCKED`.

#### Scenario: A detection on the response side

- **WHEN** a response payload holds an email placeholder
- **THEN** `voidwall_detections_total` increments with `guard="pii"`, `mode="http_api"`,
  `route="global"`, and `direction="response"`

#### Scenario: BLOCKED is not a block count

- **WHEN** the route answers `BLOCKED`
- **THEN** `voidwall_blocked_total` and `voidwall_pii_blocked_total` do not increment
