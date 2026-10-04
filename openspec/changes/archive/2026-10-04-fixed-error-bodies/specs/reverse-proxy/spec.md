## MODIFIED Requirements

### Requirement: A blocked error names the party at fault

When the `on_error` policy blocks a message, the reverse proxy SHALL answer a status that
names the party at fault.

- A body larger than `max_body_size` SHALL answer 413.
- A body that fails to parse SHALL answer 400. The client declared the content type and
  sent bytes that do not match it.
- A scanner failure SHALL answer 500. The scanner belongs to the proxy.

The proxy SHALL reserve 502 for a failure of the upstream itself. Each of these response
bodies SHALL be a JSON object holding an `error` field, and SHALL carry no matched text
and no fragment of the message that was scanned.

The 500 body SHALL be exactly `{"error":"internal error"}`. Every 502 body SHALL be
exactly `{"error":"upstream error"}`. Neither body SHALL carry a detail of the failure.

#### Scenario: Oversize body under fail_close

- **WHEN** a request body is larger than `max_body_size` and `on_error` is `fail_close`
- **THEN** the proxy answers 413 and does not forward the request

#### Scenario: Malformed body under fail_close

- **WHEN** a request declares a JSON content type, its body does not parse, and `on_error`
  is `fail_close`
- **THEN** the proxy answers 400 and does not forward the request

#### Scenario: Scanner failure under fail_close

- **WHEN** the scanner returns an error and `on_error` is `fail_close`
- **THEN** the proxy answers 500 and does not forward the request
- **AND** the body is exactly `{"error":"internal error"}`

#### Scenario: The upstream cannot be reached

- **WHEN** the proxy forwards a clean request and the upstream connection fails
- **THEN** the proxy answers 502
- **AND** the body is exactly `{"error":"upstream error"}`

#### Scenario: An error body carries no scanned text

- **WHEN** the proxy answers 400, 413, or 500 for a message that held a detected value
- **THEN** the body names the error only and carries no matched text
