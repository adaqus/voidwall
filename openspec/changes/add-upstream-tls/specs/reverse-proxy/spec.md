## ADDED Requirements

### Requirement: The proxy originates TLS to an https upstream

When a route's `upstream` carries the `https` scheme, the proxy SHALL connect to it over
TLS and SHALL verify the server certificate and the host name of the upstream URI. It
SHALL trust the system root certificates. When the route sets `upstream_ca_path`, it
SHALL also trust the certificates of that bundle: the bundle SHALL add to the system
roots and SHALL NOT replace them. No configuration SHALL turn verification off.

An `https` upstream SHALL offer HTTP/2 and HTTP/1.1 through ALPN, and SHALL use the
version that the upstream selects. An `http` upstream SHALL use plain HTTP/1.1, as
before.

A TLS failure with the upstream, a certificate that does not verify included, SHALL be
a failure of the upstream connection. It SHALL answer the 502 that the
`A blocked error names the party at fault` requirement states for that case, and SHALL
increment `voidwall_errors_total` with `outcome="blocked"` and `reason="upstream_error"`.
Neither the body nor a metric label SHALL carry a detail of the TLS failure.

#### Scenario: The upstream certificate chains to the route's CA bundle

- **WHEN** a route names an `https` upstream whose certificate is signed by a CA in the
  route's `upstream_ca_path`, and the proxy forwards a clean request
- **THEN** the upstream receives the request over TLS
- **AND** the client receives the upstream's response

#### Scenario: The upstream certificate chains to a system root, with no CA bundle

- **WHEN** a route without `upstream_ca_path` names an `https` upstream whose certificate
  is signed by a CA in the system root store, and the proxy forwards a clean request
- **THEN** the client receives the upstream's response

#### Scenario: The upstream certificate chains to a system root

- **WHEN** a route names an `https` upstream whose certificate is signed by a CA in the
  system root store, the route sets `upstream_ca_path` to a bundle of another CA, and the
  proxy forwards a clean request
- **THEN** the client receives the upstream's response

#### Scenario: The upstream certificate chains to no trusted CA

- **WHEN** a route without `upstream_ca_path` names an `https` upstream whose certificate
  is signed by a CA outside the system root store, and the proxy forwards a clean request
  on a route without `format`
- **THEN** the proxy answers 502 with the body `{"error":"upstream error"}`
- **AND** `voidwall_errors_total` increments with `outcome="blocked"` and
  `reason="upstream_error"`

#### Scenario: The upstream certificate names another host

- **WHEN** a route names an `https` upstream whose certificate is signed by a trusted CA
  but does not name the upstream's host, and the proxy forwards a clean request on a
  route without `format`
- **THEN** the proxy answers 502 with the body `{"error":"upstream error"}`

#### Scenario: The upstream selects HTTP/2

- **WHEN** an `https` upstream selects `h2` through ALPN
- **THEN** the proxy sends the request to it over HTTP/2

#### Scenario: The upstream selects HTTP/1.1

- **WHEN** an `https` upstream offers only `http/1.1` through ALPN
- **THEN** the proxy sends the request to it over HTTP/1.1

#### Scenario: A plain HTTP upstream

- **WHEN** a route names an `http` upstream
- **THEN** the proxy sends the request over plain HTTP/1.1, without TLS
