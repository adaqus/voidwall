# HTTP API — Documentation

The HTTP API listener serves one route, `POST /v1/scan`. It takes the body as the
content to scan — there is no JSON envelope — and answers with the kinds detected.

The contract is `docs/openapi.json`, an OpenAPI 3.x document in this repository.
It is generated from the route handler and its request and response types, so it
cannot drift from the implementation.

## Reading and regenerating the contract

Open `docs/openapi.json` in any OpenAPI viewer, or read it directly.

A unit test compares the checked-in document with the one the handler generates and
fails when the two differ. After changing the route, the request type, or a response
type, regenerate the file:

```bash
UPDATE_OPENAPI=1 cargo test -p voidwall --lib openapi
```

Then commit the result alongside the code change.

## Starting the stack

From the repository root:

```bash
cargo build --release --bins
docker compose -f docker/docker-compose.yml up --build
```

The build step is required because `docker/Dockerfile.voidwall` copies the
`target/release/voidwall` binary into the image. The echo server image builds
from source in `tools/echo-server/`.

Services exposed on the host:

| Service     | URL                          | Notes |
|-------------|------------------------------|-------|
| Reverse proxy | `http://localhost:8082`    | Routes all paths to the bundled echo server. |
| HTTP API    | `http://localhost:8083`      | `POST /v1/scan`. |
| Admin       | `http://localhost:9090`      | `/metrics`, `/healthz`, `/readyz`. |
| Prometheus  | `http://localhost:9091`      | Scrapes the proxy admin port. |
| Grafana     | `http://localhost:3000`      | Pre-provisioned dashboards. |

## Configuration

`docker/voidwall.toml` enables both reverse proxy and HTTP API modes. The HTTP
API listens on `0.0.0.0:8083` so the docker port mapping `8083:8083` reaches
it.

The listener sends no CORS header and holds no credential check. Access control
belongs to the deployment: put an authenticating gateway in front, and set any
cross-origin permission there.
