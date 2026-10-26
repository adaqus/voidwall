## ADDED Requirements

### Requirement: A listener that fails to bind stops the start

At startup, when the admin server, the reverse proxy, or the HTTP API cannot bind its
configured address, the proxy SHALL log an error that names the listener, the address,
and the cause, and SHALL exit non-zero. It SHALL NOT keep running without that listener.

#### Scenario: A data-plane port is in use

- **WHEN** another process listens on the address in `reverse_proxy.listen` and the
  proxy starts with the reverse proxy enabled
- **THEN** the proxy logs an error naming the reverse proxy, that address, and that the
  address is in use, and exits non-zero
- **AND** `/readyz` never answers 200

#### Scenario: The admin port is in use

- **WHEN** another process listens on the address in `admin.listen` and the proxy starts
- **THEN** the proxy logs an error naming the admin server, that address, and that the
  address is in use, and exits non-zero
- **AND** no data-plane listener binds
