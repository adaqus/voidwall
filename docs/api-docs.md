# HTTP API — Interactive Documentation

The `docker/docker-compose.yml` stack ships with a Swagger UI service that
renders the proxy's OpenAPI spec and lets operators try the `/v1/scan` and
`/v1/redact` endpoints from a browser.

This stack is for local development and operator use. Do not run Swagger UI
alongside production deployments of the API itself.

## Starting the stack

From the repository root:

```bash
cargo build --release --bins
docker compose -f docker/docker-compose.yml up --build
```

The build step is required because `docker/Dockerfile.proxy` copies the
`target/release/pii-proxy` and `target/release/echo-server` binaries into the
image.

Services exposed on the host:

| Service     | URL                          | Notes |
|-------------|------------------------------|-------|
| Reverse proxy | `http://localhost:8082`    | Routes all paths to the bundled echo server. |
| HTTP API    | `http://localhost:8083`      | `POST /v1/scan`, `POST /v1/redact`, `GET /openapi.json`. |
| Admin       | `http://localhost:9090`      | `/metrics`, `/healthz`, `/readyz`. |
| Swagger UI  | `http://localhost:8088`      | Interactive docs for the HTTP API. |
| Prometheus  | `http://localhost:9091`      | Scrapes the proxy admin port. |
| Grafana     | `http://localhost:3000`      | Pre-provisioned dashboards. |

## Using Swagger UI

Open `http://localhost:8088` in a browser. The page loads the spec from
`http://localhost:8083/openapi.json` (set via `SWAGGER_JSON_URL`).

The "Try it out" button issues real requests against the proxy's HTTP API on
port 8083. Both the spec fetch and the test calls go through the host port
mapping, so the browser does not need to resolve the compose-internal
`proxy` hostname.

## Configuration

`docker/proxy.toml` enables both reverse proxy and HTTP API modes. The HTTP
API listens on `0.0.0.0:8083` so the docker port mapping `8083:8083` reaches
it.

The HTTP API responds with permissive CORS headers (`Access-Control-Allow-Origin: *`)
so a Swagger UI hosted on a different origin can fetch the spec and exercise
the endpoints. The API has no built-in authentication — when exposed beyond
a developer workstation, place it behind an authenticating gateway and
restrict origins at that layer.

## Production note

The Swagger UI container is a development convenience. It has no
authentication and exposes the API surface to anyone who can reach port
8088. Strip the `api-docs` service before deploying this compose stack
beyond a developer workstation, or front it with an authenticating gateway.
