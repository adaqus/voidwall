## ADDED Requirements

### Requirement: Decoded runs are counted by encoding

`voidwall_decoded_runs_total` SHALL increment once for each encoded run of a message that
the `encoded-content-decoding` capability keeps. A run that both the scan view and the
decoded view keep SHALL count once. A run that is not kept SHALL NOT count. Its
`encoding` label SHALL be drawn from a fixed set: `base64`, `base64url` or `hex`. The
`mode`, `route`, and `direction` labels SHALL follow the rules of "Metric label values are
drawn from fixed sets". The counter SHALL increment whether or not the message is then
blocked.

#### Scenario: Two runs in one request

- **WHEN** a reverse proxy request body holds one base64 run and one hex run that are
  both kept
- **THEN** `voidwall_decoded_runs_total` increments by one with `encoding="base64"` and by
  one with `encoding="hex"`, both with `mode="reverse_proxy"` and `direction="request"`

#### Scenario: A run read by both views

- **WHEN** a request body holds one base64 run that is kept, and the route selects the
  `pii` guard and a `text_classifier` guard
- **THEN** `voidwall_decoded_runs_total` increments by one

#### Scenario: A run that is not kept

- **WHEN** a request body holds a base64 run that decodes to bytes that are not valid
  UTF-8
- **THEN** `voidwall_decoded_runs_total` does not increment

#### Scenario: /v1/scan decodes a run

- **WHEN** `/v1/scan` is called and the body holds one kept base64url run
- **THEN** `voidwall_decoded_runs_total` increments by one with `mode="http_api"`,
  `route="global"`, `direction="request"`, and `encoding="base64url"`

#### Scenario: The LiteLLM request side decodes a run

- **WHEN** the LiteLLM guardrail route receives request-side texts that hold one kept
  base64 run
- **THEN** `voidwall_decoded_runs_total` increments by one with `mode="http_api"`,
  `route="global"`, `direction="request"`, and `encoding="base64"`

#### Scenario: A response is not counted

- **WHEN** a response body holds a base64 run that would be kept in a request
- **THEN** `voidwall_decoded_runs_total` does not increment

## RENAMED Requirements

- FROM: `### Requirement: The proxy publishes nine application metrics`
- TO: `### Requirement: The proxy publishes ten application metrics`

## MODIFIED Requirements

### Requirement: The proxy publishes ten application metrics

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
- `voidwall_decoded_runs_total`, a counter labelled `mode`, `route`, `direction`, and
  `encoding`.

A family that counts one class of findings SHALL carry that class in its name, and SHALL
count every guard of that class: the `pii` guard and every guard with `class = "pii"`. A
family that describes the engine as a whole SHALL NOT name a class.

#### Scenario: Prometheus scrapes a running proxy

- **WHEN** a client scrapes the admin metrics endpoint
- **THEN** the response carries these ten families with these label sets

#### Scenario: A retired family is absent

- **WHEN** a client scrapes the admin metrics endpoint
- **THEN** no family named `voidwall_specialization_errors_total` or
  `voidwall_pii_redacted_total` appears

#### Scenario: The guard families carry no kind label

- **WHEN** the proxy increments `voidwall_detections_total` or `voidwall_blocked_total`
- **THEN** the sample carries no `pii_kind` label and no other kind label
