## Purpose

The admin server exposes the operational surface of the proxy on a port separate from
the data plane: Prometheus metrics, a liveness probe, and a readiness probe.

## Requirements

### Requirement: Admin server binds a separate port

The admin server SHALL listen on its own address, separate from every data-plane
listener. It SHALL default to `127.0.0.1:9090`.

#### Scenario: Default listen address

- **WHEN** the config omits `admin.listen`
- **THEN** the admin server binds `127.0.0.1:9090`

#### Scenario: Operator overrides the address

- **WHEN** the config sets `admin.listen`
- **THEN** the admin server binds that address instead

### Requirement: Liveness endpoint always reports healthy

The admin server SHALL serve a liveness endpoint at `admin.health_path`, default
`/healthz`. It SHALL return 200 whenever the process serves requests.

#### Scenario: Process is running

- **WHEN** a client sends `GET /healthz` to the admin listener
- **THEN** the server returns 200

### Requirement: Readiness endpoint tracks listener binding

The admin server SHALL serve a readiness endpoint at `admin.ready_path`, default
`/readyz`. It SHALL return 503 until every data-plane listener is bound, and 200
after that.

#### Scenario: Data plane is not bound yet

- **WHEN** a client sends `GET /readyz` before the data-plane listeners bind
- **THEN** the server returns 503

#### Scenario: Data plane is bound

- **WHEN** a client sends `GET /readyz` after the data-plane listeners bind
- **THEN** the server returns 200

#### Scenario: Readiness flips while the process runs

- **WHEN** the readiness flag changes after the server starts
- **THEN** the next `GET /readyz` reflects the new value without a restart

### Requirement: Metrics endpoint serves the Prometheus text format

The admin server SHALL serve the Prometheus registry at `admin.metrics_path`, default
`/metrics`. It SHALL refresh the process metrics on each scrape. It SHALL set the
content type to `text/plain; version=0.0.4; charset=utf-8`.

#### Scenario: Prometheus scrapes the endpoint

- **WHEN** a client sends `GET /metrics` to the admin listener
- **THEN** the server returns 200 with content type `text/plain`
- **AND** the body carries the registered metric families in the Prometheus text format

### Requirement: Admin paths are configurable

The admin server SHALL route each endpoint at its configured path. A configured path
SHALL replace the default, not extend it.

#### Scenario: All three paths are overridden

- **WHEN** the config sets `metrics_path`, `health_path`, and `ready_path` to custom
  values
- **THEN** each endpoint answers at its configured path

### Requirement: Admin server shuts down gracefully

The admin server SHALL stop when the shutdown token is cancelled. It SHALL drain the
requests in flight first.

#### Scenario: Shutdown signal arrives

- **WHEN** the cancellation token is triggered
- **THEN** the admin server stops accepting connections and returns without an error
