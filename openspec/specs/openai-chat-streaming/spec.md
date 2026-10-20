# openai-chat-streaming Specification

## Purpose
Lets a reverse proxy route with `format = "openai-chat"` scan a Chat Completions stream
(`text/event-stream`) and stop it on a detection, in hold-back or buffer mode, without
rewriting any event it forwards.

## Requirements

### Requirement: A stream on an openai-chat route is scanned

When response scan is on, an upstream response with the content type `text/event-stream`
on a route with `format = "openai-chat"` SHALL be scanned as a stream, whatever the
request said about `stream`. The route's `stream` field SHALL select the mode:
`holdback` when it is absent or `"holdback"`, buffer mode when it is `"buffer"`.

A request with `"stream": true` SHALL be scanned and forwarded as any other request on
the route. The headers the route names SHALL be scanned on the response before any byte
of the body reaches the client. When response scan is off, a stream SHALL pass as on any
route.

Every byte the upstream sends up to the end of the stream SHALL reach the client
unchanged and in the order it was sent, unless the proxy stops the stream.

#### Scenario: A clean stream in hold-back mode

- **WHEN** a client posts a clean request with `"stream": true` to an `openai-chat` route
  without `stream`, and the upstream answers the recorded stream
- **THEN** the client receives the upstream status and every upstream byte unchanged,
  ending with `data: [DONE]`

#### Scenario: A stream without stream true in the request

- **WHEN** a request without `stream` reaches an `openai-chat` route and the upstream
  answers `text/event-stream` that holds an email placeholder in `delta.content`
- **THEN** the proxy stops the stream

#### Scenario: A detection in a response header

- **WHEN** the route names a response header and the upstream stream carries an email
  placeholder in that header
- **THEN** the proxy answers 400 with `error.code` `content_filter` and no body byte
  reaches the client

#### Scenario: Response scan off

- **WHEN** response scan is off and the upstream answers `text/event-stream`
- **THEN** the client receives the upstream stream unscanned

### Requirement: Stream text is read by the response field rules

The proxy SHALL join the text of the stream's chunks before it scans them. Each string
under `choices[].delta` SHALL be joined, in arrival order, with the strings of the same
key in the same choice `index`, and for `delta.tool_calls[]` in the same tool call
`index`. A joined string SHALL be scanned by the rule the response field rules give to
the same key under `choices[].message`, so a key those rules do not know, such as
`reasoning_content` or `reasoning`, SHALL be scanned. Every other chunk key SHALL follow
the response field rules for the same top-level key, and SHALL be scanned per event.

The proxy SHALL NOT scan `choices[].logprobs`, `choices[].index`,
`choices[].finish_reason`, `id`, `object`, `created`, `model`, `system_fingerprint`,
`service_tier`, or `usage` in a chunk.

#### Scenario: A value split across chunks

- **WHEN** an email placeholder arrives in three `delta.content` chunks of choice 0
- **THEN** the proxy stops the stream

#### Scenario: Tool call arguments

- **WHEN** an email placeholder arrives split across the `delta.tool_calls[0].function.arguments`
  chunks of choice 0
- **THEN** the proxy stops the stream

#### Scenario: A reasoning trace

- **WHEN** an email placeholder arrives in `delta.reasoning_content` chunks
- **THEN** the proxy stops the stream

#### Scenario: Two choices interleaved

- **WHEN** choice 0 and choice 1 interleave their chunks and only choice 1 holds an email
  placeholder
- **THEN** the proxy stops the stream and the kinds name the email kind once

#### Scenario: An upstream error event

- **WHEN** the upstream sends `data: {"error": {"message": ...}}` whose message holds an
  email placeholder
- **THEN** the proxy stops the stream

#### Scenario: Logprobs are not scanned

- **WHEN** a stream holds an email placeholder only in `choices[0].logprobs`
- **THEN** the client receives the whole stream

### Requirement: A payload that does not parse follows the parse-failure rule

A `data:` payload other than `[DONE]` that is not JSON SHALL follow the parse-failure
rule of the generic scan. Under `fail_close` the proxy SHALL stop the stream with the
`malformed_body` answer. Under `fail_open` the proxy SHALL scan the payload as plain text
and go on.

#### Scenario: A bad payload under fail_close

- **WHEN** a stream holds a `data:` line that is not JSON and `on_error` is `fail_close`
- **THEN** the proxy stops the stream with `error.code` `malformed_body`

#### Scenario: A bad payload under fail_open

- **WHEN** a stream holds a `data:` line that is not JSON with no PII and `on_error` is
  `fail_open`
- **THEN** the client receives the whole stream

### Requirement: Hold-back mode forwards an event only after a scan clears it

In hold-back mode the proxy SHALL scan each joined text again when at least
`stream_scan_bytes` of new text have arrived since its last scan, and when the stream
ends. Each scan SHALL cover the text not yet released plus up to `stream_context_bytes`
of released text before it.

After a scan, the proxy SHALL release text up to `stream_holdback_bytes` before the end
of the received text, and SHALL NOT release a byte at or after the start of a finding
that waits for more text. An event SHALL reach the client only when every event before
it has reached the client and every text byte it carries is released. An event SHALL be
forwarded whole.

#### Scenario: A short reply

- **WHEN** a clean stream carries less text than `stream_holdback_bytes`
- **THEN** no body byte reaches the client before the choice sends `finish_reason` or
  the upstream ends the stream, and then the client receives every byte

#### Scenario: A value inside the hold-back

- **WHEN** the client has received some events and an email placeholder arrives after
  them
- **THEN** no byte of the placeholder reaches the client

#### Scenario: A keyword before the value

- **WHEN** a keyword-gated value arrives less than `stream_context_bytes` after its
  keyword, and the keyword is already released
- **THEN** the proxy stops the stream

### Requirement: A finding at the end of the received text waits

While the stream has not ended and the text is open, a finding with a span that ends
within the tail of the received text SHALL NOT stop the stream in that scan. The tail SHALL be the last
2 bytes of the received text. The proxy SHALL scan the text again, and the
finding SHALL stop the stream when a later scan reports it outside the tail, or when the
stream ends.

#### Scenario: A value that is not complete yet

- **WHEN** a joined text ends with the first digits of a longer number, those digits
  alone match a kind, and the next chunk completes a number that matches no kind
- **THEN** the client receives the whole stream

#### Scenario: A value at the end of the stream

- **WHEN** a stream ends with an email placeholder as its last text
- **THEN** the proxy stops the stream

### Requirement: A finding without a span waits for the next scan

While the stream has not ended and the text is open, a finding without a span SHALL NOT
stop the stream in the scan that first reports it, and the proxy SHALL release no text of that joined
string until the next scan of it. The finding SHALL stop the stream when the next scan
of the same joined string reports a finding without a span of the same kind from the
same guard, or when the stream ends while it waits in an open text.

#### Scenario: The finding comes back

- **WHEN** a model guard reports a finding without a span in two scans of one joined
  string in a row
- **THEN** the proxy stops the stream

#### Scenario: The finding does not come back

- **WHEN** a model guard reports a finding without a span in one scan, and the next scan
  of that string reports none
- **THEN** the proxy releases the text and goes on

### Requirement: A text of a choice closes when the choice moves on

In hold-back mode, a joined text of a choice SHALL close when an event carries text for
another joined text of the same choice, or when an event carries `finish_reason` for
that choice. When a text closes, the proxy SHALL scan it as at the end of the stream:
with no tail wait, and a finding without a span SHALL NOT wait. The scan at the close
SHALL count as the next scan of a finding without a span that waits in the text, also when
the stream ends before that scan, and the proxy SHALL drop such a finding when that scan
does not report it again. The proxy SHALL then release the whole text or stop the
stream.

A closed text that gets more text SHALL open again and SHALL go on as the same joined
text. A value that starts before the close and ends after it can reach the client in
part before the proxy stops the stream.

#### Scenario: Content after a reasoning trace

- **WHEN** a clean stream sends `delta.reasoning_content` chunks and then
  `delta.content` chunks, each text longer than `stream_holdback_bytes`
- **THEN** the client receives every `reasoning_content` event before the upstream ends
  the stream

#### Scenario: Tool call arguments after the name

- **WHEN** a clean stream sends a tool call's `function.name` and then
  `function.arguments` chunks longer than `stream_holdback_bytes`
- **THEN** the client receives the event that carries the name before the upstream ends
  the stream

#### Scenario: A choice that finishes

- **WHEN** a clean stream sends `finish_reason` for choice 0 while choice 1 goes on
- **THEN** the client receives every event of choice 0 up to its `finish_reason` event
  before the upstream ends the stream

#### Scenario: A value at the switch

- **WHEN** `delta.reasoning_content` ends with an email placeholder and `delta.content`
  chunks follow
- **THEN** the proxy stops the stream

#### Scenario: A text that opens again

- **WHEN** a closed text gets more text that holds an email placeholder
- **THEN** the proxy stops the stream

#### Scenario: A finding without a span that does not come back at the close

- **WHEN** a model guard reports a finding without a span in a scan of an open text, and
  the scan at the close of that text reports none
- **THEN** the proxy releases the text and goes on

#### Scenario: A finding without a span that does not come back at a close with the end

- **WHEN** a model guard reports a finding without a span in a scan of an open text, one
  read then carries the text's `finish_reason` and `[DONE]`, and the scan at the close
  reports none
- **THEN** the proxy releases the text and ends the stream with `[DONE]`

### Requirement: Before the first byte a stop answers as a buffered response

While no byte of the body has reached the client, the proxy SHALL hold the response
status and headers. A stop in that time SHALL answer what the route answers for a
buffered response: 400 with `error.code` `content_filter` for a detection, and the
status and OpenAI error body the `openai-chat-proxy` capability states for each error.
After the first release, the client SHALL receive the upstream status and headers,
minus the hop-by-hop headers and `content-length`.

#### Scenario: The upstream length is not forwarded

- **WHEN** the upstream sends a clean stream with a `content-length` header
- **THEN** the client's response carries no `content-length` header

#### Scenario: A detection in the first text

- **WHEN** a stream holds an email placeholder in its first `delta.content` chunk
- **THEN** the proxy answers 400 with `error.code` `content_filter` and the kinds
- **AND** no byte of the upstream body reaches the client

### Requirement: After the first byte a stop ends the stream with one error event

Once a byte of the body has reached the client, a stop SHALL send one event
`data: <body>` followed by a blank line, and SHALL then close the stream. `<body>`
SHALL be the JSON body the route would answer for the same cause before the first byte.
The proxy SHALL NOT send `data: [DONE]` after it, and SHALL close the upstream
connection. The event SHALL carry no matched text.

#### Scenario: A detection after the first release

- **WHEN** the client has received some events and a later chunk completes an email
  placeholder
- **THEN** the client receives `data: {"error":{"message":"content blocked. Kinds: ...","type":"invalid_request_error","param":null,"code":"content_filter","kinds":[...]}}`
  in any key order, and the stream closes
- **AND** no `data: [DONE]` follows it

### Requirement: A guard error follows on_error

A guard error during a stream SHALL follow `on_error`. Under `fail_close` the proxy SHALL
stop the stream with the answer the route gives that error. Under `fail_open` the proxy
SHALL stop scanning that stream and forward the rest of it unscanned. Either way
`voidwall_errors_total` SHALL increment with the error's reason and the `outcome` the
stream took.

#### Scenario: A scanner failure under fail_close after the first byte

- **WHEN** a guard fails during a stream that has sent bytes and `on_error` is
  `fail_close`
- **THEN** the client receives an error event with `error.code` `internal_error` and the
  stream closes

#### Scenario: A scanner failure under fail_open

- **WHEN** a guard fails during a stream and `on_error` is `fail_open`
- **THEN** the client receives the rest of the stream
- **AND** `voidwall_errors_total` increments with `outcome="passed"`

### Requirement: The stream ends at DONE or at a clean end of the body

The stream SHALL end at `data: [DONE]`, or when the upstream ends the body cleanly
without it. No byte after the `[DONE]` event SHALL reach the client, in either mode, and
the proxy SHALL NOT read the upstream body after it. At the end the proxy SHALL scan the text not yet scanned, with no tail wait,
and SHALL then release every byte or stop the stream. A connection to the upstream that
fails before the body ends SHALL be an upstream failure: 502 with `error.code`
`upstream_error` before the first byte, an error event with that body after it.

#### Scenario: Bytes after DONE

- **WHEN** the upstream sends a clean stream and then an event after `data: [DONE]`
- **THEN** the client's body ends with `data: [DONE]`, in hold-back and in buffer mode

#### Scenario: No DONE line

- **WHEN** the upstream ends a clean stream without `data: [DONE]`
- **THEN** the client receives every upstream byte and the stream closes

#### Scenario: The upstream connection fails

- **WHEN** the upstream connection fails after the client received some events
- **THEN** the client receives an error event with `error.code` `upstream_error`

### Requirement: The idle timeout limits each gap in a stream

The proxy SHALL stop a stream when no byte arrives from the upstream for
`stream_idle_timeout_secs` seconds, whatever `on_error` says. An SSE comment SHALL count
as a byte. The stop SHALL answer 504 with `error.code` `upstream_timeout` before the
first byte, and an error event with that body after it. `voidwall_errors_total` SHALL
increment with `outcome="blocked"` and `reason="upstream_timeout"`. The limit SHALL
apply in both modes.

#### Scenario: The upstream goes silent

- **WHEN** the upstream sends some events and then nothing for
  `stream_idle_timeout_secs`
- **THEN** the stream is stopped with `error.code` `upstream_timeout`

#### Scenario: Keep-alive comments

- **WHEN** the upstream sends only `: keep-alive` comments for longer than
  `stream_idle_timeout_secs`, each gap shorter than it, and then a clean end
- **THEN** the client receives the whole stream

#### Scenario: on_error does not change the idle answer

- **WHEN** a stream goes idle before the first byte and `on_error` is `fail_open`
- **THEN** the proxy answers 504

### Requirement: The stream size counts against max_body_size

The proxy SHALL count the bytes of the upstream stream body. When the count passes
`max_body_size`, the proxy SHALL stop the stream, whatever `on_error` says: 502 with
`error.code` `upstream_error` before the first byte, an error event with that body after
it. `voidwall_errors_total` SHALL increment with `outcome="blocked"` and
`reason="response_too_large"`. The limit SHALL apply in both modes.

#### Scenario: A stream larger than the limit

- **WHEN** a clean stream body is larger than `max_body_size`
- **THEN** the stream is stopped with `error.code` `upstream_error`

#### Scenario: A stream at the limit

- **WHEN** a clean stream body is exactly `max_body_size` bytes
- **THEN** the client receives the whole stream

### Requirement: Buffer mode scans the whole stream before the first byte

In buffer mode the proxy SHALL read the stream to its end, under the idle timeout and
the size limit, and SHALL scan its joined text once. A detection SHALL answer 400 with
`error.code` `content_filter`, and an error SHALL answer as for a buffered response. A
clean stream SHALL reach the client as the exact bytes the upstream sent up to the end
of the stream, with the upstream status and headers minus the hop-by-hop headers. The
`content-length` the client receives SHALL be the length of the body it receives.

#### Scenario: A clean stream in buffer mode

- **WHEN** a route sets `stream = "buffer"` and the upstream answers the recorded stream
- **THEN** no byte reaches the client before the upstream ends the stream
- **AND** the client then receives every upstream byte unchanged

#### Scenario: A detection in buffer mode

- **WHEN** a route sets `stream = "buffer"` and the stream holds an email placeholder
  near its end
- **THEN** the proxy answers 400 with `error.code` `content_filter` and no body byte
  reaches the client

### Requirement: A compressed stream is unscannable content

A stream on an `openai-chat` route with response scan on and a `Content-Encoding` other
than `identity` SHALL be unscannable content in both modes. It SHALL follow `on_error`
as a response the route cannot inspect does.

#### Scenario: A compressed stream under fail_close

- **WHEN** the upstream answers `text/event-stream` with `Content-Encoding: gzip` and
  `on_error` is `fail_close`
- **THEN** the proxy answers 422 with `error.code` `unscannable_content` and no body byte
  reaches the client

#### Scenario: A compressed stream under fail_open

- **WHEN** the upstream answers `text/event-stream` with `Content-Encoding: gzip` and
  `on_error` is `fail_open`
- **THEN** the client receives the stream unscanned
- **AND** `voidwall_errors_total` increments with `outcome="passed"` and
  `reason="unscannable_content"`

### Requirement: Startup warns about custom patterns without a bound

At startup the proxy SHALL log one warning when a route with `format = "openai-chat"` in
hold-back mode selects the `pii` guard and a custom definition has no keywords. The
warning SHALL name the custom labels and the route prefixes. It SHALL NOT stop startup.

#### Scenario: A custom pattern without keywords

- **WHEN** the config defines a custom pattern without keywords and an `openai-chat`
  route in hold-back mode selects the `pii` guard
- **THEN** the proxy starts and logs one warning that names the label and the route

#### Scenario: Buffer mode

- **WHEN** the same config sets `stream = "buffer"` on the route
- **THEN** no such warning is logged
