## REMOVED Requirements

### Requirement: A route may name a specialization

**Reason**: The analytics specializations are retired. There is no built-in adapter left for
a route to name, and the `specialization` field is removed from the route configuration.

**Migration**: Remove `specialization` from every route. A route that still carries the key
fails validation at startup. The route's query and body are scanned by the default path,
which routes on the content type.

A route MAY name a built-in specialization. It SHALL then own the query and body
decoding for that route. Config validation rejects an unknown name, so lookup at
startup always resolves.

#### Scenario: Route names a specialization

- **WHEN** a route names `ga4`
- **THEN** that specialization decodes the query and the body for the route
