## Purpose

The proxy publishes Prometheus metrics that describe detections, actions, traffic,
errors, and process health. The admin listener serves them.

## Requirements

### Requirement: Metric label values are drawn from fixed sets

The `mode` label SHALL be `reverse_proxy`, `forward_proxy`, or `http_api`. The `route`
label SHALL be the path prefix in reverse proxy mode, and `global` in every other mode.
The `direction` label SHALL be `request` or `response`. The `outcome` label SHALL be
`passed` or `blocked`. The `guard` label SHALL be the name configuration gave the guard,
so the set of its values is fixed at startup. The built-in regex PII guard SHALL carry
`guard="pii"`. The `pii_kind` label SHALL be a kind the regex PII guard defines, or a label
that a guard with `class = "pii"` declares in configuration, so the set of its values is
fixed at startup too.

#### Scenario: HTTP API records a detection

- **WHEN** the HTTP API detects PII
- **THEN** the detection metric carries `mode="http_api"` and `route="global"`

#### Scenario: A detection carries no specialization label

- **WHEN** the proxy increments the detection counter
- **THEN** the sample carries no `specialization` label

#### Scenario: The PII guard records a detection

- **WHEN** the built-in regex PII guard reports a finding
- **THEN** `voidwall_detections_total` increments with `guard="pii"`

#### Scenario: A PII model guard's kind

- **WHEN** a guard with `class = "pii"` reports a finding of its label `POSTAL_ADDRESS`
- **THEN** the detection counter carries `pii_kind="POSTAL_ADDRESS"`

### Requirement: A metric label never carries a PII value

Every label SHALL carry a kind name, a guard name, a mode, a route, a direction, a
method, a status, or a reason. No label SHALL ever carry matched text.

#### Scenario: A detection is recorded

- **WHEN** the proxy increments the detection counter for a match
- **THEN** the `pii_kind` label holds the kind name and no matched value

#### Scenario: A guard detection is recorded

- **WHEN** the proxy increments `voidwall_detections_total`
- **THEN** the `guard` label holds the guard's configured name and no matched value

### Requirement: Detections increment once per resolved kind, whatever happens to the message

The proxy SHALL increment `voidwall_pii_detections_total` once per kind in the findings of
the PII guards: the `pii` guard's resolved set, and the findings of every guard with
`class = "pii"`. It SHALL increment once for a kind however many findings, and however
many PII guards, reported that kind. It SHALL NOT increment for a kind that only a guard
outside the PII guards reported. It SHALL do so whether the message is blocked or reported
on, and when a guard error makes the API answer 500.

#### Scenario: A blocked message increments the detection counter

- **WHEN** a PII detection blocks a request
- **THEN** the detection counter increments for each detected kind, and the blocked
  counter increments once

#### Scenario: A reported detection increments the counter

- **WHEN** `/v1/scan` detects PII and blocks nothing
- **THEN** the detection counter still increments for each detected kind

#### Scenario: One kind is found many times

- **WHEN** a scan returns four findings of the same kind
- **THEN** the counter for that kind increments by one

#### Scenario: Two guards report the same kind

- **WHEN** the `pii` guard and a model guard each report a finding of the same kind in one
  message
- **THEN** the counter for that kind increments by one

#### Scenario: A model guard's kind is not a PII kind

- **WHEN** a model guard without a class reports a `PROMPT_INJECTION` finding
- **THEN** `voidwall_pii_detections_total` does not increment for `PROMPT_INJECTION`

#### Scenario: A PII model guard detects

- **WHEN** only a guard with `class = "pii"` reports findings, of kinds `PERSON_NAME` and
  `POSTAL_ADDRESS`, in one message
- **THEN** the detection counter increments once for each of the two kinds

#### Scenario: A guard error makes the API answer 500

- **WHEN** one guard fails on `/v1/scan`, the `pii` guard reports a finding, and
  `on_error` is `fail_close`
- **THEN** the detection counter increments for each kind the `pii` guard found

### Requirement: Errors record the fail-open or fail-close outcome

Every scanner failure and limit violation SHALL increment `voidwall_errors_total`. The
`outcome` label SHALL name the path the message took: `passed` when it went through,
`blocked` when it was stopped. The `reason` label SHALL name the cause.

When a detection from another guard blocks the message, a scanner failure that the engine
received before the block SHALL increment the counter with `outcome="blocked"`, whatever
`on_error` says. A guard still running when the block arrives is abandoned, so an error it
would have returned is not counted.

#### Scenario: Body exceeds the size limit under fail_open

- **WHEN** a body is oversize and `on_error` is `fail_open`
- **THEN** the error counter increments with `outcome="passed"` and a reason naming the
  size limit

#### Scenario: A detection overrules a scanner failure under fail_open

- **WHEN** one guard fails, another guard then reports a finding that blocks the message,
  and `on_error` is `fail_open`
- **THEN** the error counter increments with `outcome="blocked"` and
  `reason="scanner_failure"`

### Requirement: Process metrics refresh on every scrape

The proxy SHALL publish `process_resident_memory_bytes`,
`process_virtual_memory_bytes`, `process_cpu_seconds_total`, `process_threads`, and
`process_open_fds`. It SHALL refresh them from the operating system on each scrape of
the metrics endpoint.

#### Scenario: Two scrapes in a row

- **WHEN** a client scrapes the metrics endpoint twice
- **THEN** each response carries process values read at that moment

### Requirement: Guard detections increment once per guard per message

The proxy SHALL increment `voidwall_detections_total` once for each guard that reported
at least one finding in a message, with that guard's name as the `guard` label. It SHALL
increment once for a guard however many findings, and however many units, that guard
reported in the message. It SHALL do so whether the message is blocked or reported on,
and when a guard error makes the API answer 500.

The counter SHALL count the guards whose findings the detection engine returned. When a
detection blocks the message, a guard still running is abandoned, and the counter SHALL
NOT increment for it.

#### Scenario: One guard finds many matches

- **WHEN** one guard reports four findings in one message
- **THEN** `voidwall_detections_total` for that guard increments by one

#### Scenario: One guard finds matches in two units

- **WHEN** one guard reports a finding in the body and a finding in a header of one
  request
- **THEN** `voidwall_detections_total` for that guard increments by one

#### Scenario: Two guards report findings

- **WHEN** two guards each report a finding in one message
- **THEN** `voidwall_detections_total` increments by one for each guard

#### Scenario: A reported detection increments the guard counter

- **WHEN** `/v1/scan` detects PII
- **THEN** `voidwall_detections_total` increments with `guard="pii"`, `mode="http_api"`,
  `route="global"`, and `direction="request"`

#### Scenario: A guard error makes the API answer 500

- **WHEN** one guard fails on `/v1/scan`, another guard reports a finding, and `on_error`
  is `fail_close`
- **THEN** `voidwall_detections_total` increments for the guard that reported the
  finding, and not for the guard that failed

#### Scenario: A block abandons a guard

- **WHEN** one guard's finding blocks a message on the reverse proxy while another
  selected guard is still running
- **THEN** `voidwall_detections_total` increments for the guard that blocked, and not for
  the guard that was abandoned

#### Scenario: A clean message

- **WHEN** no guard reports a finding in a message
- **THEN** `voidwall_detections_total` does not increment

### Requirement: The blocked counter increments once per message the reverse proxy stops

The reverse proxy SHALL increment `voidwall_blocked_total` once for each message it
stops. A message is stopped when the proxy answers a detection with the route's block
(403, or 400 on a route with `format = "openai-chat"`), or when an error answers instead
of forwarding: under `on_error = "fail_close"`, 413 for an oversize body or a window
limit, 400 for a body that does not parse as its declared content type, 422 for
unscannable content, or 500 for a scanner failure; and, on an `openai-chat` route, 400
for a request that is not a Chat Completions request, under either `on_error`. A stream
that the proxy stops for one of these causes after its first byte SHALL count as a
stopped message. The counter SHALL carry the message's `mode`, `route`, and
`direction`.

The counter SHALL increment once for a message however many guards reported findings
in it, and when a guard error and a detection come together.

A message that passes under `on_error = "fail_open"`, a 502 for an upstream failure, a
stream stopped by the idle timeout, the size limit, or an upstream failure, and every
answer of `/v1/scan` SHALL NOT increment the counter.

`voidwall_pii_blocked_total` SHALL count only a block for a detection in which the `pii`
guard, or a guard with `class = "pii"`, reported a finding. It SHALL increment once for
such a message, however many PII guards reported findings in it.

#### Scenario: A detection blocks a request

- **WHEN** a PII detection blocks a request on the reverse proxy
- **THEN** `voidwall_blocked_total` and `voidwall_pii_blocked_total` each increment by
  one with `direction="request"`

#### Scenario: A detection blocks a request on an openai-chat route

- **WHEN** a PII detection on a route with `format = "openai-chat"` answers 400
- **THEN** `voidwall_blocked_total` and `voidwall_pii_blocked_total` each increment by
  one

#### Scenario: Only a model guard detects

- **WHEN** only a model guard without a class reports a finding and the reverse proxy
  answers 403
- **THEN** `voidwall_blocked_total` increments by one and `voidwall_pii_blocked_total`
  does not increment

#### Scenario: Only a PII model guard detects

- **WHEN** only a guard with `class = "pii"` reports a finding and the reverse proxy answers
  403
- **THEN** `voidwall_blocked_total` and `voidwall_pii_blocked_total` each increment by one

#### Scenario: Two PII guards detect in one message

- **WHEN** the `pii` guard and a guard with `class = "pii"` both report findings in one
  request that the reverse proxy blocks
- **THEN** `voidwall_pii_blocked_total` increments by one

#### Scenario: Two guards report findings in one blocked message

- **WHEN** two guards each report a finding in one request that the reverse proxy blocks
- **THEN** `voidwall_blocked_total` increments by one

#### Scenario: An oversize body under fail_close

- **WHEN** a request body is oversize and `on_error` is `fail_close`
- **THEN** the proxy answers 413, `voidwall_blocked_total` increments by one with
  `direction="request"`, and `voidwall_pii_blocked_total` does not increment

#### Scenario: A window limit under fail_close

- **WHEN** a model guard hits its window limit, no guard reports a finding, and
  `on_error` is `fail_close`
- **THEN** the proxy answers 413 and `voidwall_blocked_total` increments by one

#### Scenario: An unparseable body under fail_close

- **WHEN** a response body does not parse as its declared content type and `on_error` is
  `fail_close`
- **THEN** the proxy answers 400, and `voidwall_blocked_total` increments by one with
  `direction="response"`

#### Scenario: A stream under fail_close

- **WHEN** a request with `"stream": true` reaches a route with
  `format = "openai-chat"`, response scan is on, `on_error` is `fail_close`, and a PII
  detection stops the stream after it has sent bytes to the client
- **THEN** `voidwall_blocked_total` and `voidwall_pii_blocked_total` each increment by
  one with `direction="response"`

#### Scenario: An idle stream

- **WHEN** the idle timeout stops a stream
- **THEN** `voidwall_blocked_total` does not increment

#### Scenario: A scanner failure under fail_close

- **WHEN** a guard fails, no guard reports a finding, and `on_error` is `fail_close`
- **THEN** the proxy answers 500, `voidwall_blocked_total` increments by one, and
  `voidwall_pii_blocked_total` does not increment

#### Scenario: A scanner failure and a detection together

- **WHEN** one guard fails and another guard's finding blocks the message
- **THEN** `voidwall_blocked_total` increments by one

#### Scenario: A scanner failure under fail_open

- **WHEN** a guard fails, no guard reports a finding, and `on_error` is `fail_open`
- **THEN** the message is forwarded and `voidwall_blocked_total` does not increment

#### Scenario: The REST API never counts a block

- **WHEN** `/v1/scan` detects PII, or answers 400 or 500
- **THEN** `voidwall_blocked_total` does not increment

### Requirement: Model guard errors carry their own reasons

A model guard's runtime failure SHALL increment `voidwall_errors_total` with
`reason="inference_failure"`. A runtime failure is a full worker queue, a worker thread
that died, a tokenizer error, an ONNX Runtime error, or an output that is not finite or
has the wrong shape. A unit past a model guard's window limit SHALL increment it with
`reason="window_limit"`. The regex PII guard's failure SHALL keep
`reason="scanner_failure"`. The `outcome` label SHALL follow the rules of "Errors record
the fail-open or fail-close outcome".

#### Scenario: Inference fails under fail_close

- **WHEN** a model guard's inference fails, no guard reports a finding, and `on_error` is
  `fail_close`
- **THEN** `voidwall_errors_total` increments with `outcome="blocked"` and
  `reason="inference_failure"`

#### Scenario: Window limit under fail_open

- **WHEN** a model guard hits its window limit, no guard reports a finding, and
  `on_error` is `fail_open`
- **THEN** `voidwall_errors_total` increments with `outcome="passed"` and
  `reason="window_limit"`

#### Scenario: The PII guard fails

- **WHEN** the regex PII guard fails
- **THEN** `voidwall_errors_total` increments with `reason="scanner_failure"`, not
  `inference_failure`

### Requirement: Values skipped without a scan are counted by reason

`voidwall_unscanned_total` SHALL increment once for each value a decoder skips on
purpose without a scan. Its `reason` label SHALL be drawn from a fixed set. The only
value SHALL be `encoded_data`, for a base64 value. The `mode`, `route`, and `direction`
labels SHALL follow the rules of "Metric label values are drawn from fixed sets".

#### Scenario: Two inline images

- **WHEN** the LiteLLM route skips two base64 images in one request payload
- **THEN** `voidwall_unscanned_total` increments by two with `mode="http_api"`,
  `route="global"`, `direction="request"`, and `reason="encoded_data"`

#### Scenario: Nothing is skipped

- **WHEN** a payload holds no base64 value
- **THEN** `voidwall_unscanned_total` does not increment

### Requirement: The proxy publishes nine application metrics

The proxy SHALL register these metric families:

- `voidwall_pii_detections_total`, a counter labelled `pii_kind`, `mode`, `route`, and
  `direction`.
- `voidwall_pii_blocked_total`, a counter labelled `mode`, `route`, and `direction`.
- `voidwall_detections_total`, a counter labelled `guard`, `mode`, `route`, and
  `direction`.
- `voidwall_blocked_total`, a counter labelled `mode`, `route`, and `direction`.
- `voidwall_requests_total`, a counter labelled `mode`, `route`, `method`, and
  `status`.
- `voidwall_request_duration_seconds`, a histogram labelled `mode` and `route`.
- `voidwall_errors_total`, a counter labelled `outcome` and `reason`.
- `voidwall_unscanned_total`, a counter labelled `mode`, `route`, `direction`, and
  `reason`.
- `voidwall_streams_cut_total`, a counter labelled `mode`, `route`, and `reason`.

A family that counts one class of findings SHALL carry that class in its name, and SHALL
count every guard of that class: the `pii` guard and every guard with `class = "pii"`. A
family that describes the engine as a whole SHALL NOT name a class.

#### Scenario: Prometheus scrapes a running proxy

- **WHEN** a client scrapes the admin metrics endpoint
- **THEN** the response carries these nine families with these label sets

#### Scenario: A retired family is absent

- **WHEN** a client scrapes the admin metrics endpoint
- **THEN** no family named `voidwall_specialization_errors_total` or
  `voidwall_pii_redacted_total` appears

#### Scenario: The guard families carry no kind label

- **WHEN** the proxy increments `voidwall_detections_total` or `voidwall_blocked_total`
- **THEN** the sample carries no `pii_kind` label and no other kind label

### Requirement: Unscannable content carries its own reason

When a decoder meets content it cannot inspect, `voidwall_errors_total` SHALL increment
with `reason="unscannable_content"`. The `outcome` label SHALL follow the rules of
"Errors record the fail-open or fail-close outcome". No sample SHALL carry
`reason="unscannable_stream"`.

#### Scenario: An unknown content part

- **WHEN** a decoder meets a content part of an unknown type and `on_error` is
  `fail_close`
- **THEN** `voidwall_errors_total` increments with `outcome="blocked"` and
  `reason="unscannable_content"`

#### Scenario: A stream passes under fail_open

- **WHEN** a client sends `"stream": true` to an `openai-chat` route with response scan
  on, `on_error` is `fail_open`, and the upstream answers a clean `text/event-stream`
- **THEN** no `voidwall_errors_total` sample carries `reason="unscannable_stream"`

### Requirement: Upstream errors carry their own reasons

An upstream timeout SHALL increment `voidwall_errors_total` with `outcome="blocked"` and
`reason="upstream_timeout"`. An upstream response body larger than `max_body_size` under
response scan SHALL increment it with `outcome="blocked"` and
`reason="response_too_large"`. An upstream failure SHALL increment it with
`outcome="blocked"` and `reason="upstream_error"`: a connection to the upstream that
fails before the response headers, a read of a buffered response body that fails, and a
stream on an `openai-chat` route under response scan, in hold-back or buffer mode, whose
upstream connection fails before the body ends.

#### Scenario: The upstream times out

- **WHEN** the reverse proxy answers 504 because the upstream exchange timed out
- **THEN** `voidwall_errors_total` increments with `outcome="blocked"` and
  `reason="upstream_timeout"`

#### Scenario: The upstream response is too large

- **WHEN** the reverse proxy answers 502 because the upstream response body is larger
  than `max_body_size`
- **THEN** `voidwall_errors_total` increments with `outcome="blocked"` and
  `reason="response_too_large"`

#### Scenario: The upstream cannot be reached

- **WHEN** the reverse proxy answers 502 because the connection to the upstream fails
- **THEN** `voidwall_errors_total` increments with `outcome="blocked"` and
  `reason="upstream_error"`

#### Scenario: The upstream response body fails

- **WHEN** response scan is on and the upstream connection fails while the proxy reads a
  buffered response body
- **THEN** the proxy answers 502 and `voidwall_errors_total` increments with
  `outcome="blocked"` and `reason="upstream_error"`

#### Scenario: The upstream stream fails

- **WHEN** the upstream connection fails before a stream on an `openai-chat` route ends
- **THEN** `voidwall_errors_total` increments with `outcome="blocked"` and
  `reason="upstream_error"`

### Requirement: A stream cut after its first byte is counted by reason

The reverse proxy SHALL increment `voidwall_streams_cut_total` once for each stream it
stops after a byte of the body has reached the client. A stop before the first byte
SHALL NOT increment it. The `mode` and `route` labels SHALL follow the rules of "Metric
label values are drawn from fixed sets". The `reason` label SHALL be one of:

- `detection`: a guard reported a finding.
- `scan_error`: a guard error under `fail_close`.
- `idle_timeout`: the idle timeout expired.
- `too_large`: the stream passed `max_body_size`.
- `upstream_error`: the upstream connection failed before the body ended.
- `malformed_body`: a `data:` payload did not parse, under `fail_close`.
- `unscannable_content`: a content part of an unknown type, under `fail_close`.

#### Scenario: A detection after the first byte

- **WHEN** a detection stops a stream that has sent bytes to the client
- **THEN** `voidwall_streams_cut_total` increments by one with `mode="reverse_proxy"`,
  the route's prefix, and `reason="detection"`

#### Scenario: A detection before the first byte

- **WHEN** a detection stops a stream before any byte reaches the client
- **THEN** the proxy answers 400 and `voidwall_streams_cut_total` does not increment

#### Scenario: An idle stream after the first byte

- **WHEN** the idle timeout stops a stream that has sent bytes to the client
- **THEN** `voidwall_streams_cut_total` increments by one with `reason="idle_timeout"`

#### Scenario: An unknown content part after the first byte

- **WHEN** a content part of an unknown type stops a stream that has sent bytes to the
  client, and `on_error` is `fail_close`
- **THEN** `voidwall_streams_cut_total` increments by one with
  `reason="unscannable_content"`

#### Scenario: A clean stream

- **WHEN** a clean stream ends
- **THEN** `voidwall_streams_cut_total` does not increment
