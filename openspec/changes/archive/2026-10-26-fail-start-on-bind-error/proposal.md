## Why

A listener that fails to bind does not stop the proxy. `server::run` spawns each
listener as a task, and a bind error only logs `admin server failed`, `reverse proxy
failed`, or `HTTP API failed`; the process keeps running with no listener on that
port. `/readyz` can still answer 200, because the readiness flag is set after a
`yield_now`, not after the binds. An orchestrator then routes traffic to a proxy that
does not listen. The port race in the startup integration tests came from this.

## What Changes

- A listener that fails to bind stops the start. This covers the admin server, the
  reverse proxy, and the HTTP API. `server::run` returns the error, and the binary exits
  non-zero.
- The error names the listener and the address it could not bind, and the I/O error.
- The admin server still binds before the guards load. The data-plane listeners still
  bind only after every guard has loaded.
- `/readyz` answers 200 only after every enabled data-plane listener is bound. This
  restores the existing requirement "Readiness endpoint tracks listener binding"; the
  `yield_now` workaround goes.
- Only a bind failure stops the process. An error a listener returns after it bound keeps
  today's behavior: it is logged, and the process keeps running.
- The binary logs any `server::run` error as `failed to start` instead of `failed to
  initialize detection engine`.

## Capabilities

### New Capabilities

None.

### Modified Capabilities

- `admin-server`: a new requirement, "A listener that fails to bind stops the start".

## Impact

- `crates/voidwall/src/server.rs`: binds every listener itself, in the existing order,
  and sets readiness after the data-plane binds.
- `crates/voidwall/src/admin.rs`, `reverse_proxy.rs`, `http_api.rs`: each gets a function
  that serves on a listener already bound. `serve(&config, ...)` stays and binds first,
  so the integration tests that call it do not change.
- `crates/voidwall/src/main.rs`: the error log line.
- `crates/voidwall/tests/startup_integration.rs` and `model_guard_integration.rs`: a start
  that loses a port now exits, so the retry waits for the exit instead of a `failed` log
  line.
- Operators: a port conflict that before left a running process without that listener now
  exits non-zero at startup.
