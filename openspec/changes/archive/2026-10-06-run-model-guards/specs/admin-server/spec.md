## MODIFIED Requirements

### Requirement: Readiness endpoint tracks listener binding

The admin server SHALL serve a readiness endpoint at `admin.ready_path`, default
`/readyz`. It SHALL return 503 until every guard has loaded and every data-plane listener
is bound, and 200 after that.

#### Scenario: Data plane is not bound yet

- **WHEN** a client sends `GET /readyz` before the data-plane listeners bind
- **THEN** the server returns 503

#### Scenario: Guards are still loading

- **WHEN** a client sends `GET /readyz` while a model guard loads its model
- **THEN** the server returns 503

#### Scenario: Data plane is bound

- **WHEN** a client sends `GET /readyz` after every guard loaded and the data-plane
  listeners bind
- **THEN** the server returns 200

#### Scenario: Readiness flips while the process runs

- **WHEN** the readiness flag changes after the server starts
- **THEN** the next `GET /readyz` reflects the new value without a restart

## ADDED Requirements

### Requirement: The admin server binds before the guards load

At startup, the admin server SHALL bind before the guards are built. While the guards
load, `/healthz` SHALL answer 200, `/readyz` SHALL answer 503, and the metrics endpoint
SHALL answer. The data-plane listeners SHALL bind only after every guard has loaded.

#### Scenario: Probes during a model load

- **WHEN** a client sends `GET /healthz` and `GET /readyz` while a model guard loads its
  model
- **THEN** `/healthz` answers 200 and `/readyz` answers 503

#### Scenario: The data plane waits for the guards

- **WHEN** a model guard is still loading its model
- **THEN** no data-plane listener accepts a connection
