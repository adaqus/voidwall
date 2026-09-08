## REMOVED Requirements

### Requirement: A specialization can be selected per request

**Reason**: The analytics specializations are retired. There is no adapter left to select, so
the query parameter, the `400` answer for an unknown name, and the `X-PII-Specialization`
response header are all removed.

**Migration**: Stop sending `?specialization=`. A request that still carries it is scanned by
the content-type router and answered `200`, whatever value it names — including a value that
was answered `400` before this change. A client that reads `X-PII-Specialization` must stop;
the header is never sent.

An optional `?specialization=<name>` query parameter SHALL select a built-in
specialization. It SHALL then own the parsing, the field selection, and the
re-encoding, and content-type routing SHALL be bypassed. An unknown name SHALL return
400. Omitting the parameter SHALL keep content-type routing.

#### Scenario: Known specialization is named

- **WHEN** a client posts with `?specialization=` naming a built-in specialization
- **THEN** that specialization parses the body instead of the content-type router

#### Scenario: Unknown specialization is named

- **WHEN** a client posts with `?specialization=` naming an unknown value
- **THEN** the API returns 400
