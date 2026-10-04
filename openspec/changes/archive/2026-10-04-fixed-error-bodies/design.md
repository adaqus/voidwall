## Context

Two code paths build a 500 today:

- The reverse proxy calls `Error::into_response` in `handle_scan_error`. For
  `Error::Scanner(msg)` and `Error::Config(msg)`, `into_response` puts `msg` in the body.
- The REST API builds its own body in `handle_scanner_failure`:
  `{"error":"scanner failure"}`.

Every 502 comes from the reverse proxy through `Error::into_response`. For
`Error::Proxy(msg)` and `Error::Io(e)`, `into_response` puts the error text in the body.
The forward proxy builds no response yet.

The 500 paths and four of the five 502 paths already log the error before they answer.
The scanner paths use a rate-limited `warn!` through `SCANNER_ERROR_LIMITER`. The 502
paths use `error!`. The one 502 path without a log is the request body read failure in
`buffer_body`.

## Goals / Non-Goals

**Goals:**

- One fixed 500 body, `{"error":"internal error"}`, for the reverse proxy and the REST API.
- One fixed 502 body, `{"error":"upstream error"}`, for the reverse proxy.
- No failure text in any 500 or 502 that `Error` produces.
- Every 502 path writes its details to the log.

**Non-Goals:**

- The 400, 413, and 415 bodies. They are already fixed.
- The status of a request body read failure. It answers 502, but the client is at
  fault. That is a separate issue.
- Any other logging change. The existing log lines stay as they are.
- Metrics. `voidwall_errors_total` keeps its current labels.

## Decisions

**The fix goes in `IntoResponse for Error`.** The `Config` and `Scanner` arms answer the
fixed 500 text. The `Proxy` and `Io` arms answer the fixed 502 text. No arm reads the
error details. Any later caller of `into_response` then gets the fixed body with no
extra work. The alternative, a change at each call site, leaves the leak in
`into_response` for the next caller.

**One constant holds each text.** `error.rs` defines the 500 text and the 502 text once.
`handle_scanner_failure` in `http_api.rs` uses the 500 constant too, so the two modes
cannot drift.

**The 500 text is `internal error`.** It does not name the scanner, so it also fits a
later model guard failure. The REST API text `scanner failure` changes to match.

**The 502 text is `upstream error`.** It names the party at fault.

**`Display` keeps the details.** `Error::to_string()` still holds the error text. The
log uses `Display`, so the details reach the log and only the response loses them.

**`buffer_body` gets an `error!` line.** It logs the read error before it builds the
502, the same way the other 502 paths do. It is not rate-limited, to match them.

## Risks / Trade-offs

- [A client matches on `"scanner failure"` in the REST API body] → The proposal marks
  the change as breaking. The status stays 500.
- [A client reads the 502 body to tell failures apart] → It now reads the log instead.
  The status stays 502.
- [The rate limit drops some scanner failure logs during a storm] → Accepted. The
  limiter reports the dropped count in the next log line.
- [Many clients that drop their connection fill the log through the new `error!` line]
  → Accepted, because it matches the other 502 paths, which are not rate-limited either.
