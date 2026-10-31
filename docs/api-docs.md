# HTTP API — Documentation

The HTTP API listener serves two routes. Each has its own switch, and both are on by
default:

| Route | Switch | What it does |
|---|---|---|
| `POST /v1/scan` | `http_api.scan.enabled` | Takes the body as the content to scan — there is no JSON envelope — and answers with the kinds detected. |
| `POST /beta/litellm_basic_guardrail_api` | `http_api.litellm.enabled` | Speaks LiteLLM's Generic Guardrail API. Answers `{"action":"NONE"}`, or `{"action":"BLOCKED","blocked_reason":"..."}` naming the kinds found. |

A route whose switch is false does not exist and answers 404. `http_api.enabled` starts
the listener; enabling it with both switches false stops the start.

The contract is `docs/openapi.json`, an OpenAPI 3.x document in this repository.
It is generated from the route handlers and their request and response types, so it
cannot drift from the implementation.

## The direction of a `/v1/scan` body

`POST /v1/scan` takes an optional `direction` query parameter, `request` or `response`.
It names the direction of the posted content, and the scan runs the guards that inspect
that direction:

| Query | Scan |
|---|---|
| none, or `?direction=request` | A request scan. The `hidden_context` guard does not run. |
| `?direction=response` | A response scan. Every guard that inspects responses runs, `hidden_context` among them. |
| any other value | 400 `{"error":"invalid direction"}`. No guard runs. |

The `pii` guard and every model guard inspect both directions, so for them the parameter
changes nothing. A detection counts under the `direction` label of the scan. The LiteLLM
route takes no `direction`: its `input_type` sets it. See
[hidden-context.md](hidden-context.md).

## The LiteLLM route

- It accepts JSON only (415 otherwise). `max_body_size` applies; `content_types` does not.
- On the request side it scans `structured_messages`, `tools`, and `tool_calls`. It reads
  `texts` and `images` only when `structured_messages` is missing. On the response side
  it scans `texts` and `tool_calls`.
- It never scans `request_data` or `request_headers`.
- Base64 data (`data:` image URLs, `input_audio.data`, `file.file_data`) is not scanned.
  Each skipped value increments `voidwall_unscanned_total{reason="encoded_data"}`.
- A content part of an unknown type follows `on_error`: `fail_close` answers 422
  `{"error":"unscannable content"}`, `fail_open` skips the part.
- A body that is not a JSON object with an `input_type` of `request` or `response`
  answers 400. Guard failures answer as on `/v1/scan`.

See the README for a LiteLLM `config.yaml` example.

## Reading and regenerating the contract

Open `docs/openapi.json` in any OpenAPI viewer, or read it directly.

A unit test compares the checked-in document with the one the handler generates and
fails when the two differ. After changing a route, a request type, or a response
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
| HTTP API    | `http://localhost:8083`      | `POST /v1/scan`, `POST /beta/litellm_basic_guardrail_api`. |
| Admin       | `http://localhost:9090`      | `/metrics`, `/healthz`, `/readyz`. |
| Prometheus  | `http://localhost:9091`      | Scrapes the proxy admin port. |
| Grafana     | `http://localhost:3000`      | Pre-provisioned dashboards. |

## Configuration

`docker/voidwall.toml` enables both reverse proxy and HTTP API modes. The HTTP
API listens on `0.0.0.0:8083` so the docker port mapping `8083:8083` reaches
it. Both routes are on, because the file sets neither `http_api.scan.enabled` nor
`http_api.litellm.enabled`.

The listener sends no CORS header and holds no credential check. Access control
belongs to the deployment: put an authenticating gateway in front, and set any
cross-origin permission there.
