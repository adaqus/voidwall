## 1. Validation

- [x] 1.1 Add a rule to `AppConfig::validate` in `crates/voidwall/src/config.rs` that returns `Error::Config` naming `reverse_proxy.tls.enabled` or `forward_proxy.tls.enabled` when either is true, whatever the mode's `enabled` value. Verify: `cargo check --workspace`.
- [x] 1.2 Add unit tests in `config.rs`: reverse proxy TLS enabled fails, forward proxy TLS enabled fails, TLS enabled on a disabled forward proxy fails, `enabled = false` with `cert_path` and `key_path` passes. Each failure test checks the key name in the message. Verify: `cargo test -p voidwall config`.
- [x] 1.3 Add a test in `crates/voidwall/src/validate.rs` that a TLS-enabled config gets the `semantic` category. Verify: `cargo test -p voidwall validate`.

## 2. Docs

- [x] 2.1 Update `ARCHITECTURE.md` § 7 and `docs/backlog.md` § 1.1 to say that `tls.enabled = true` fails validation. Verify: `grep -n "nothing reads it\|parses and validates" ARCHITECTURE.md docs/backlog.md` shows no TLS line left with the old text.

## 3. Checks

- [x] 3.1 Run the workspace tests and Clippy. Verify: `cargo test --workspace` and `cargo clippy --workspace --all-targets` pass with no warning.
- [x] 3.2 Run `openspec validate reject-unbuilt-tls --strict`. Verify: it passes.
