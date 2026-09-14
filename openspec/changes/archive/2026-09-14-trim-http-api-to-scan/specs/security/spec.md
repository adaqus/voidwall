## ADDED Requirements

### Requirement: The API listener sends no cross-origin header

The HTTP API listener SHALL NOT send an `Access-Control-Allow-Origin` header or any
other CORS response header. A browser on another origin therefore cannot call the
listener directly. Cross-origin access is the deployment's job, at the gateway that
already supplies the authentication the listener does not.

#### Scenario: A browser on another origin calls the API

- **WHEN** a client sends `POST /v1/scan` carrying an `Origin` header
- **THEN** the response carries no `Access-Control-Allow-Origin` header

#### Scenario: A browser sends a preflight request

- **WHEN** a client sends `OPTIONS /v1/scan`
- **THEN** the listener does not answer with CORS permission headers

## MODIFIED Requirements

### Requirement: The scanner configuration is not exposed

The proxy SHALL NOT serve an endpoint that returns the scanner configuration. The HTTP
API listener SHALL serve no route that reports the configured detect list, the ignore
list, the custom patterns, or the built-in detection surface.

#### Scenario: A client queries the detection surface

- **WHEN** a client calls a route that reports the detection surface or the scanner
  configuration
- **THEN** no such route exists on the API listener
