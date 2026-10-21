## MODIFIED Requirements

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
