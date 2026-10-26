## Context

`server::run` spawns one task per listener. Each task calls `admin::serve`,
`reverse_proxy::serve`, or `http_api::serve`, which binds `config.listen` and then
serves. A bind error ends that task with an `error!` log line, and `run` never learns of
it. The readiness flag is set by a task that only calls `yield_now` first. See
proposal.md for why this matters.

Seven integration tests call the `serve` functions directly, with a config and a
cancellation token, and `admin_integration.rs` calls `server::run` and checks its result.

## Goals / Non-Goals

**Goals:**

- `server::run` knows the result of every bind before it moves on.
- The bind error carries the listener and the address.
- The readiness flag is set by `run` itself, after the last data-plane bind.

**Non-Goals:**

- An error a listener returns after it bound. It is logged, as today.
- A change to the startup order: admin first, then the guards, then the data plane.

## Decisions

### D1: `run` binds every listener, and a serve function takes a bound listener

Each module gets `serve_on(listener: TcpListener, ...)`, which only serves. `run` binds
with `TcpListener::bind`, maps the error, and returns it before it spawns the task.
`serve(&config, ...)` stays as `bind` followed by `serve_on`, so the tests that call it do
not change.

Alternative: each task binds and reports the result to `run` over a `oneshot`. This
keeps one function per module, but it adds a channel per listener and a second path for
the same error. Binding in `run` makes the order of the startup visible in one place.

### D2: A new `Error::Bind` variant with a `Listener` enum

`Error::Bind { listener: Listener, addr: String, source: std::io::Error }`. `Listener`
is an enum (`Admin`, `ReverseProxy`, `HttpApi`), so the name in the message can only be
one of the three. Display: `<listener> could not bind <addr>: <source>`, for example
`reverse proxy could not bind 127.0.0.1:8082: Address already in use (os error 98)`.
`source()` returns the I/O error.

`Error` is also the request-path error, so the response and metric matches get an arm
for `Bind`. It falls in the 500 arm with the fixed body, like `Config`; no request can
produce it.

Alternative: a separate start error type returned by `run`. It keeps startup errors out
of the response path, but it changes the signature of `run` and of every caller that
matches its error. `Error::Config` already sets the precedent for a startup-only variant.

### D3: A failed bind cancels the token and returns

On a bind error `run` cancels the token, so the admin server and any data-plane
listener already spawned stop, and returns the error at once. It does not wait for the
tasks: the process exits next. A failed admin bind returns before the guards are built.

### D4: Readiness is set in `run`, after the data-plane binds

`run` stores `true` in the flag after the last data-plane bind returned and its task was
spawned. The spawned `yield_now` task and its comment go. An accepted connection waits in
the listen backlog until the task serves it, so a probe that sees 200 can connect.

### D5: `main` logs `failed to start`

The one `error!` line for an `Err` from `server::run` reads `failed to start`, with the
error in the `error` field. Any start error, the guard build included, uses it.

### D6: The startup tests retry on an exit

`startup_integration.rs` and `model_guard_integration.rs` retry a start that lost a port.
After this change the process exits on that loss, so the retry condition becomes an exit
whose log holds `Address already in use`. Any other early exit still fails the test.

## Risks / Trade-offs

- [A deployment that today starts with a dead listener now fails to start] → This is the
  intended behavior; the proposal's Impact lists it for operators.
- [A bind on the admin port succeeds, and the guard build then fails] → Unchanged: the
  token is cancelled and the build error returns, as today.
