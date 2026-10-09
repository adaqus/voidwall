## 1. Validation

- [x] 1.1 In `crates/voidwall/src/config.rs`, add a rule that returns `Error::Config` naming `forward_proxy.enabled` when it is true. Run it first in `AppConfig::validate`, before `validate_at_least_one_mode`. Verify: `cargo check --workspace`.
- [x] 1.2 Remove `forward_proxy` from `validate_at_least_one_mode` and its message, and remove the forward proxy branch of `validate_no_port_conflicts`. Verify: `grep -n "forward_proxy.enabled" crates/voidwall/src/config.rs` shows only the new rule and tests.
- [x] 1.3 Remove the forward proxy warning in `crates/voidwall/src/server.rs`. Verify: `cargo check --workspace`.

## 2. Tests

- [x] 2.1 Change every test config in `config.rs` and `engine/mod.rs` that uses `forward_proxy.enabled = true` as its mode to another mode, so that each test still checks what it checked before. Drop the TLS test case "forward proxy, mode enabled", which can no longer happen. Verify: `cargo test -p voidwall` passes.
- [x] 2.2 Add unit tests in `config.rs`: forward proxy enabled with another mode fails and names the key; only the forward proxy enabled fails and names `forward_proxy.enabled`, not the missing mode; a disabled `forward_proxy` table with `listen`, `request`, and `response` passes. Verify: `cargo test -p voidwall config::tests::forward_proxy`.
- [x] 2.3 Add a test in `crates/voidwall/src/validate.rs` that an enabled forward proxy gets the `semantic` category. Verify: `cargo test -p voidwall validate`.

## 3. Docs

- [x] 3.1 `README.md`: replace "The forward proxy uses port 8084" with a line that says the forward proxy is not built and the config rejects it. Verify: read the diff.
- [x] 3.2 `AGENTS.md`: the Architecture section lists three modes that run, and says the forward proxy is not built and the config rejects it. Verify: `grep -n "four\|8084" AGENTS.md` shows no claim that the forward proxy runs.
- [x] 3.3 `ARCHITECTURE.md` § 7 and `docs/backlog.md` § 1.2: say that `forward_proxy.enabled = true` fails validation, and that the rejection must go when the mode is built. Verify: `grep -n "logs one warning\|not yet implemented" ARCHITECTURE.md docs/backlog.md` finds nothing.

## 4. Checks

- [x] 4.1 Run the workspace tests and Clippy. Verify: `cargo test --workspace` and `cargo clippy --workspace --all-targets` pass with no warning.
- [x] 4.2 Run `openspec validate reject-unbuilt-forward-proxy --strict`. Verify: it passes.
