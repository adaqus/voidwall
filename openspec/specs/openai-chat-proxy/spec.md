## Purpose

Lets a reverse proxy route decode OpenAI Chat Completions traffic field by field, and
answer a block or an error in the error shape that OpenAI clients understand.

## Requirements

### Requirement: A route opts in with format openai-chat

A reverse proxy route with `format = "openai-chat"` SHALL decode its request body and its
upstream response body as Chat Completions by the requirements of this capability. A
route without `format` SHALL keep the generic body scan.

The format SHALL change how a body is decoded and how the proxy answers. It SHALL NOT
change which guards run, which headers are scanned, or whether the URL path and query
are scanned. A body SHALL be decoded only when a guard selected for the route admits the
body and the body is not empty.

#### Scenario: A route with the format

- **WHEN** a route sets `format = "openai-chat"` and a client posts a Chat Completions
  request whose user message carries an email placeholder
- **THEN** the proxy blocks the request as this capability states

#### Scenario: A route without the format

- **WHEN** a route sets no `format` and a request body carries an email placeholder
- **THEN** the proxy answers the fixed 403 of the reverse proxy

#### Scenario: An empty request body

- **WHEN** a client sends a `GET` with no body to an `openai-chat` route
- **THEN** the proxy decodes no body and forwards the request when nothing else is
  detected

### Requirement: The request body must be a Chat Completions request

On an `openai-chat` route the top-level `content_types` allowlist SHALL NOT apply.
`max_body_size` SHALL apply as on any route.

The proxy SHALL answer 400 when a non-empty request body has a content type that is not
JSON, does not parse as JSON, is not a JSON object, or has no `messages` array. It SHALL
answer so under `fail_open` and under `fail_close` alike, SHALL NOT forward the request,
and SHALL increment `voidwall_errors_total` with `outcome="blocked"` and
`reason="body_parse_failed"`.

#### Scenario: JSON is admitted although content_types omits it

- **WHEN** `content_types` does not list `application/json` and a client posts a Chat
  Completions request with `Content-Type: application/json`
- **THEN** the proxy scans it

#### Scenario: A body that is not JSON

- **WHEN** a client posts `text/plain` to an `openai-chat` route and `on_error` is
  `fail_open`
- **THEN** the proxy answers 400 and does not forward the request

#### Scenario: messages is missing

- **WHEN** a client posts the JSON object `{"model": "m", "input": "hello"}`
- **THEN** the proxy answers 400

### Requirement: The request is read from messages, tools, and the free-text fields

The proxy SHALL scan these request fields:

- Each entry of `messages`, by the message rules of the LiteLLM route for
  `structured_messages`: the content, the `text` and `refusal` parts, `file.filename`,
  `name`, `refusal`, the tool calls, and `function_call`.
- Each entry of `tools`, by the tool rules of the LiteLLM route.
- Each entry of the deprecated `functions`: `name`, `description`, and every string
  value in `parameters`.
- Every string value in `response_format.json_schema`.
- `prediction.content`, as a string or as `text` parts.
- Every string value in `metadata`.
- `safety_identifier`, `user`, and `prompt_cache_key`.
- Every string value in `web_search_options.user_location`.

It SHALL NOT scan `model`, `stop`, `tool_choice`, `function_call` at the top level,
`modalities`, `audio`, `stream`, `stream_options`, `response_format.type`, or a sampling
or token setting such as `temperature`, `top_p`, `n`, `seed`, `max_tokens`,
`max_completion_tokens`, `logit_bias`, `logprobs`, `top_logprobs`, `frequency_penalty`,
`presence_penalty`, `parallel_tool_calls`, `reasoning_effort`, `verbosity`,
`service_tier`, `store`, `moderation`, `prompt_cache_options`, or
`prompt_cache_retention`. It SHALL NOT scan a message's `role` or `tool_call_id`, a tool
call's `id` or `type`, `audio.id`, `image_url.detail`, `file.file_id`, `function.strict`,
or a tool that carries only a `type`.

#### Scenario: A system message

- **WHEN** a request holds a `system` message whose content carries an email placeholder
- **THEN** the proxy blocks the request

#### Scenario: A replayed tool call

- **WHEN** a request holds an assistant message whose
  `tool_calls[].function.arguments` carries an email placeholder
- **THEN** the proxy blocks the request

#### Scenario: A tool parameter schema

- **WHEN** a request holds a `tools[].function.parameters` property description that
  carries an email placeholder
- **THEN** the proxy blocks the request

#### Scenario: Metadata

- **WHEN** a request holds `metadata` with a value that carries an email placeholder
- **THEN** the proxy blocks the request

#### Scenario: safety_identifier

- **WHEN** a request holds a `safety_identifier` that is an email placeholder
- **THEN** the proxy blocks the request

#### Scenario: A response format schema

- **WHEN** a request holds a `response_format.json_schema.schema` whose `description`
  carries an email placeholder
- **THEN** the proxy blocks the request

#### Scenario: The model name is not scanned

- **WHEN** a request holds a `model` value that is an email placeholder and no other PII
- **THEN** the proxy forwards the request

### Requirement: An unknown key or role is scanned generically

A top-level request key the proxy does not name in "The request is read from messages,
tools, and the free-text fields" SHALL have every string value under it scanned. Inside a
message, a tool, or a tool call, an unknown field SHALL have every string value under it
scanned, and a message whose `role` the proxy does not know SHALL have every string value
in it scanned.

#### Scenario: A vendor extension at the top level

- **WHEN** a request holds a top-level `chat_template_kwargs` object with a value that
  carries an email placeholder
- **THEN** the proxy blocks the request

#### Scenario: A reasoning trace on an assistant message

- **WHEN** a request holds an assistant message with a `reasoning_content` field that
  carries an email placeholder
- **THEN** the proxy blocks the request

#### Scenario: An unknown role

- **WHEN** a request holds a message with `role` `narrator` whose content carries an
  email placeholder
- **THEN** the proxy blocks the request

### Requirement: The response is read from choices

When response scan is on and the upstream response carries a JSON content type, the
proxy SHALL scan these response fields:

- In each entry of `choices`, `message` by the message rules, and in it every string
  value of `annotations` and `audio.transcript`.
- Every string value under a top-level key the proxy does not know, such as `error`.

It SHALL NOT scan `choices[].logprobs`, `choices[].index`, `choices[].finish_reason`,
`message.audio.id`, `message.audio.expires_at`, `id`, `object`, `created`, `model`,
`system_fingerprint`, `service_tier`, or `usage`.

A JSON response body that is not an object SHALL have every string value in it scanned.
A JSON response body that does not parse SHALL follow the parse-failure rule of the
generic scan.

#### Scenario: Model output

- **WHEN** an upstream response holds `choices[0].message.content` with an email
  placeholder
- **THEN** the proxy blocks the response and the upstream body does not reach the client

#### Scenario: Model tool call

- **WHEN** an upstream response holds `choices[0].message.tool_calls[0].function.arguments`
  with an email placeholder
- **THEN** the proxy blocks the response

#### Scenario: An upstream error that echoes input

- **WHEN** the upstream answers 400 with `{"error": {"message": ...}}` whose message
  carries an email placeholder
- **THEN** the proxy blocks the response

#### Scenario: An upstream error as a flat string

- **WHEN** the upstream answers 400 with `{"error": "<text>"}` whose text carries an
  email placeholder
- **THEN** the proxy blocks the response

#### Scenario: A reasoning trace in the response

- **WHEN** an upstream response holds `choices[0].message.reasoning_content` with an
  email placeholder
- **THEN** the proxy blocks the response

#### Scenario: Logprobs are not scanned

- **WHEN** an upstream response holds an email placeholder only in
  `choices[0].logprobs.content[].token`
- **THEN** the proxy forwards the response

### Requirement: Encoded data is skipped and counted

The proxy SHALL NOT scan base64 data in a request or a response: an `image_url.url` that
starts with `data:`, `input_audio.data`, `file.file_data`, and `message.audio.data` in a
response. It SHALL increment `voidwall_unscanned_total` once for each skipped value, with
`mode="reverse_proxy"`, the route's `path_prefix` as `route`, the message's `direction`,
and `reason="encoded_data"`. It SHALL count only a message that goes on to be scanned.

An `image_url.url` that does not start with `data:` SHALL NOT be scanned and SHALL NOT
be counted.

#### Scenario: An inline image

- **WHEN** a request holds one user message with an `image_url` data URL and a `text`
  part with no PII
- **THEN** the proxy forwards the request
- **AND** `voidwall_unscanned_total` increments by one with `direction="request"` and
  `reason="encoded_data"`

#### Scenario: Audio output

- **WHEN** an upstream response holds `choices[0].message.audio.data` and no PII
- **THEN** the proxy forwards the response
- **AND** `voidwall_unscanned_total` increments by one with `direction="response"`

### Requirement: An unknown content part type follows on_error

A content part whose `type` is not `text`, `image_url`, `input_audio`, `file`, or
`refusal` SHALL be unscannable. Under `fail_close` the proxy SHALL answer 422, SHALL run
no guard, and SHALL NOT forward the message. Under `fail_open` it SHALL skip the part and
scan the rest. Either way `voidwall_errors_total` SHALL increment with
`reason="unscannable_content"` and the `outcome` the message took.

#### Scenario: Unknown part under fail_close

- **WHEN** a request holds a content part with `type` `hologram` and `on_error` is
  `fail_close`
- **THEN** the proxy answers 422 and does not reach the upstream
- **AND** `voidwall_errors_total` increments with `outcome="blocked"` and
  `reason="unscannable_content"`

#### Scenario: Unknown part under fail_open

- **WHEN** a request holds a content part with `type` `hologram`, a `text` part with an
  email placeholder, and `on_error` is `fail_open`
- **THEN** the proxy blocks the request for the email kind
- **AND** `voidwall_errors_total` increments with `outcome="passed"` and
  `reason="unscannable_content"`

### Requirement: A response that is not JSON is unscannable

When response scan is on, a non-empty upstream response body whose content type is not
JSON and not `text/event-stream`, or that has no content type, SHALL be unscannable. Under
`fail_close` the proxy SHALL answer 422 and no part of the upstream body SHALL reach the
client. Under `fail_open` the proxy SHALL forward the response unscanned, as it does
with response scan off. Either way `voidwall_errors_total` SHALL increment with
`reason="unscannable_content"` and the
`outcome` the message took.

#### Scenario: An HTML error page under fail_close

- **WHEN** the upstream answers 502 with `Content-Type: text/html` and `on_error` is
  `fail_close`
- **THEN** the proxy answers 422
- **AND** `voidwall_errors_total` increments with `outcome="blocked"` and
  `reason="unscannable_content"`

#### Scenario: An HTML error page under fail_open

- **WHEN** the upstream answers with `Content-Type: text/html` and `on_error` is
  `fail_open`
- **THEN** the client receives the upstream response

### Requirement: A detection answers 400 in the OpenAI error shape

When a guard reports a finding on an `openai-chat` route, in the request or in the
response, the proxy SHALL stop the message and SHALL answer 400 with
`Content-Type: application/json`. The body SHALL be a JSON object with one key, `error`,
whose value SHALL be an object with exactly these keys:

- `message`: `content blocked. Kinds: ` followed by the kind names joined by `, `.
- `type`: `invalid_request_error`.
- `param`: `null`.
- `code`: `content_filter`.
- `kinds`: the kind names as an array.

The kinds SHALL be the set the fixed 403 of the reverse proxy would list: sorted, each
once, from every guard. The body SHALL carry no matched text. The status, the body, and
the response headers SHALL NOT be configurable. The proxy SHALL record the detection and
blocked metrics as it does for the fixed 403.

#### Scenario: Two kinds in a request

- **WHEN** a request holds an IBAN placeholder and an email placeholder
- **THEN** the proxy answers 400 and does not reach the upstream
- **AND** `error.code` is `content_filter`, `error.type` is `invalid_request_error`,
  `error.param` is `null`, and `error.kinds` names the two kinds sorted
- **AND** `error.message` is `content blocked. Kinds: ` followed by the same two names
  joined by `, `
- **AND** the body holds neither placeholder value

#### Scenario: A detection in the response

- **WHEN** an upstream response holds an email placeholder in
  `choices[0].message.content`
- **THEN** the proxy answers 400 with `error.code` `content_filter`
- **AND** `voidwall_blocked_total` increments by one with `direction="response"`

### Requirement: Every other answer uses the OpenAI error shape

On an `openai-chat` route, every answer the proxy makes instead of the upstream's SHALL
keep the status the reverse proxy states for it, and SHALL carry a JSON body with one key,
`error`, whose value SHALL be an object with exactly the keys `message`, `type`, `param`,
and `code`. `param` SHALL be `null`. The other keys SHALL be:

| Status | Cause | `message` | `type` | `code` |
|---|---|---|---|---|
| 400 | Malformed body | `body parse failed` | `invalid_request_error` | `malformed_body` |
| 413 | Oversize body | `request body too large` | `invalid_request_error` | `body_too_large` |
| 413 | Window limit | `tokenized content too long to scan` | `invalid_request_error` | `content_too_long` |
| 422 | Unscannable content | `unscannable content` | `invalid_request_error` | `unscannable_content` |
| 500 | Scanner or inference failure | `internal error` | `server_error` | `internal_error` |
| 502 | Upstream failure, oversize response, or oversize stream | `upstream error` | `server_error` | `upstream_error` |
| 504 | Upstream timeout or idle stream | `upstream timeout` | `server_error` | `upstream_timeout` |

No body SHALL carry a detail of the failure, a matched value, or a fragment of the
scanned message. After the first byte of a stream, the same body SHALL go in the error
event that the `openai-chat-streaming` capability states.

A response the upstream sends and the proxy forwards SHALL reach the client unchanged.

#### Scenario: A scanner failure under fail_close

- **WHEN** a guard fails, no guard reports a finding, and `on_error` is `fail_close`
- **THEN** the proxy answers 500 with
  `{"error":{"message":"internal error","type":"server_error","param":null,"code":"internal_error"}}`
  in any key order

#### Scenario: The upstream cannot be reached

- **WHEN** the proxy forwards a clean request and the upstream connection fails
- **THEN** the proxy answers 502 with `error.code` `upstream_error`

#### Scenario: The upstream times out

- **WHEN** the upstream sends no response headers within `upstream_timeout_secs`
- **THEN** the proxy answers 504 with `error.code` `upstream_timeout`

#### Scenario: An oversize request under fail_close

- **WHEN** a request body is larger than `max_body_size` and `on_error` is `fail_close`
- **THEN** the proxy answers 413 with `error.code` `body_too_large`

#### Scenario: An upstream error is forwarded

- **WHEN** the upstream answers 429 with a JSON error body that holds no PII
- **THEN** the client receives the upstream status and body unchanged
