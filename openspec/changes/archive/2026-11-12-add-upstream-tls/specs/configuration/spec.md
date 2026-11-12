## ADDED Requirements

### Requirement: A route's upstream CA bundle is validated

A reverse proxy route SHALL accept the optional key `upstream_ca_path`, a path to a PEM
file of CA certificates. Validation SHALL fail with the `semantic` category when:

- `upstream_ca_path` is an empty string;
- a route sets `upstream_ca_path` and its `upstream` carries the `http` scheme;
- two routes name the same `upstream` and their `upstream_ca_path` values differ,
  including when one route sets the key and the other does not.

Two routes name the same upstream when their `upstream` strings are equal. These checks
SHALL run in validate mode and at startup alike. They SHALL NOT open the file.

#### Scenario: A CA bundle on an https upstream

- **WHEN** a route names an `https` upstream and sets `upstream_ca_path`
- **THEN** validation passes

#### Scenario: A CA bundle on an http upstream

- **WHEN** a route names an `http` upstream and sets `upstream_ca_path`
- **THEN** validation fails with the `semantic` category naming the route's
  `path_prefix` and `upstream_ca_path`

#### Scenario: An empty CA bundle path

- **WHEN** a route sets `upstream_ca_path = ""`
- **THEN** validation fails with the `semantic` category naming the route's
  `path_prefix` and `upstream_ca_path`

#### Scenario: Two routes give one upstream different CA bundles

- **WHEN** two routes name the same `https` upstream and set different
  `upstream_ca_path` values
- **THEN** validation fails with the `semantic` category naming the upstream

#### Scenario: Only one of two routes gives the upstream a CA bundle

- **WHEN** two routes name the same `https` upstream and only one sets
  `upstream_ca_path`
- **THEN** validation fails with the `semantic` category naming the upstream

#### Scenario: Two routes give one upstream the same CA bundle

- **WHEN** two routes name the same `https` upstream and set the same `upstream_ca_path`
- **THEN** validation passes

### Requirement: An upstream CA bundle that fails to load stops the start

At startup, the proxy SHALL read every `upstream_ca_path` before any data-plane listener
binds. When a file does not exist, cannot be read, holds a PEM block that does not parse,
or holds no certificate, the proxy SHALL log an error naming the route's `path_prefix`
and the path, and SHALL exit non-zero. It SHALL NOT start without that bundle.

#### Scenario: The CA bundle file is missing

- **WHEN** a route's `upstream_ca_path` names a file that does not exist
- **THEN** the proxy logs an error naming the route and the path, and exits non-zero
- **AND** no data-plane listener binds

#### Scenario: The CA bundle holds no certificate

- **WHEN** a route's `upstream_ca_path` names a file that holds no PEM certificate
- **THEN** the proxy logs an error naming the route and the path, and exits non-zero
- **AND** no data-plane listener binds

## MODIFIED Requirements

### Requirement: Validation binds nothing and starts nothing

In validate mode the proxy SHALL NOT bind a listener, SHALL NOT spawn a scanner thread,
SHALL NOT open TLS material, SHALL NOT build an upstream client, and SHALL NOT load a
model. It SHALL build a scanner once, to exercise regex and Vectorscan compilation, and
then discard it. A route's `upstream_ca_path` is TLS material, so validate mode SHALL
NOT open it.

#### Scenario: Validate mode runs

- **WHEN** the proxy runs in validate mode
- **THEN** no socket is bound and no scanner thread is spawned
- **AND** a scanner is built and discarded, so a bad pattern is caught

#### Scenario: Validate mode with a model guard

- **WHEN** the proxy runs in validate mode on a config with a model guard whose model file
  exists but does not parse as ONNX
- **THEN** validation passes, and no model is loaded

#### Scenario: Validate mode with a CA bundle path that does not exist

- **WHEN** the proxy runs in validate mode on a config whose route names an `https`
  upstream and an `upstream_ca_path` that does not exist
- **THEN** validation passes, and the file is not opened
