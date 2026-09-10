## ADDED Requirements

### Requirement: A detection blocks with a fixed 403

When a scan detects PII, the proxy SHALL stop the message and SHALL answer 403. The body
SHALL be a JSON object holding an `error` field and a `kinds` array. The array SHALL list
the detected kind names sorted, holding each kind once, and SHALL carry no matched text.
The status, the body, and the response headers SHALL NOT be configurable. The proxy SHALL
increment `voidwall_pii_blocked_total` once, and the detection counter once per kind.

#### Scenario: PII is found in a request

- **WHEN** a scan of the incoming request detects PII
- **THEN** the proxy answers 403 and does not reach the upstream

#### Scenario: PII is found in a response

- **WHEN** a scan of the upstream response detects PII
- **THEN** the proxy answers 403 and the upstream body does not reach the client

#### Scenario: Three kinds are found

- **WHEN** a scan detects three kinds
- **THEN** the `kinds` array names them sorted, each once, with no matched value

### Requirement: A clean message is forwarded unchanged

When a scan detects nothing, the proxy SHALL forward the message unchanged and SHALL
increment no detection metric. The proxy SHALL NOT rewrite a body, a URL path, a query
string, or a header value at any point.

#### Scenario: A clean request

- **WHEN** a scan of the request detects nothing
- **THEN** the request reaches the upstream as it arrived, minus the hop-by-hop headers

#### Scenario: A clean response

- **WHEN** a scan of the upstream response detects nothing
- **THEN** the client receives the upstream body unchanged

### Requirement: Request and response are inspected independently

The proxy SHALL inspect the incoming request when `request.scan` is true, and the
upstream response when `response.scan` is true. `scan = false` for a direction SHALL
disable inspection for that direction and SHALL leave the other direction untouched.

#### Scenario: Request only

- **WHEN** `request.scan` is true and `response.scan` is false
- **THEN** the proxy inspects the request and forwards the upstream response untouched

#### Scenario: Response only

- **WHEN** `request.scan` is false and `response.scan` is true
- **THEN** the proxy forwards the request untouched and inspects the upstream response

## MODIFIED Requirements

### Requirement: The URL path, the query, and listed headers are scannable

The proxy SHALL scan the URL path when `scan.url_path` is true, the query string when
`scan.query_params` is true, and each header named in `scan.headers`.

#### Scenario: PII sits in the query string

- **WHEN** `scan.query_params` is true and the query holds an email address
- **THEN** the proxy detects it and blocks the request

## REMOVED Requirements

### Requirement: Request and response are scanned independently

**Reason**: The rule was expressed with the request and response action lists, and an
empty list was how a direction was turned off. It survives as *Request and response are
inspected independently*, expressed with `request.scan` and `response.scan`.
**Migration**: Replace `actions = []` with `scan = false`. A non-empty action list becomes
`scan = true`, which is the default.

### Requirement: Redaction rewrites the forwarded request

**Reason**: Redaction is deleted. The proxy forwards a message unchanged or stops it; it
never rewrites one.
**Migration**: None. A request that would have been forwarded with a redacted body, a
rebuilt URI, or a replaced header value is now answered 403.
