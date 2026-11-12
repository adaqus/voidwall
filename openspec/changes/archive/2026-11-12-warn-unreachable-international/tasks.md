## 1. Warning

- [x] 1.1 `AppConfig::warn_on_unreachable_international` and its query
  `unreachable_international_labels` in `crates/voidwall/src/config.rs`, called from
  `AppConfig::load` after the other startup warnings. Built before this change was
  written; confirm it against the spec delta. Check: re-read the function against each
  scenario.
- [x] 1.2 Unit tests for the label list: International kinds named, `ignore` respected,
  custom rules of `International` named and of a listed country not, and the five
  no-warning cases. Check: `cargo test -p voidwall --lib international` passes.

## 2. Integration tests

- [x] 2.1 `startup_integration.rs`: the binary started with `countries = ["Us"]` logs one
  warning line that names `EMAIL`, and the binary started with
  `countries = ["International", "Us"]` logs
  none. Check: new test passes.
- [x] 2.2 `validate_cli_integration.rs`: `--validate` on a config with
  `countries = ["Us"]` exits 0 and its output holds no such warning. Check: new test
  passes.

## 3. Documentation

- [x] 3.1 `docs/guards/pii-regex.md` states the warning in the `countries` paragraph.
  Check: the sentence matches the spec's conditions.

## 4. Verification

- [x] 4.1 Run `cargo test --workspace` and `cargo clippy --workspace --all-targets` (no
  warnings). Check: both pass.
