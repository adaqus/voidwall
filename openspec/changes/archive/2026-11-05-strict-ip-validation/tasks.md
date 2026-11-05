## 1. Baseline

- [x] 1.1 On the base commit, run `docker/ctl ai4p-eval` and record the IP row
  (precision, recall, counts) in design.md

## 2. Tests first

- [x] 2.1 In `validators.rs`, replace `ipv6_check_cases` with one table for the new check:
  public IPv4 and IPv6 pass; a part over 255, a leading zero, `+1.+2.+3.+4`, `1.2.3`,
  `1.2.3.4.5`, `hello`, `12345`, `::`, `dead::beef`, `Add::add`, and one address of each
  excluded range fail
- [x] 2.2 In `kind_validators.rs`, add `IpAddress` rows to `validate_as_cases`: `hello`,
  `12345`, `1.2.3.4.5`, and `10.0.0.1` fail; `109.4.61.213` passes
- [x] 2.3 In `hyperscan_detector.rs` or `scanner.rs`, add one test per scenario of
  "An address that names no public host is not reported" in the spec delta
- [x] 2.4 Run `cargo test -p voidwall-pii` and confirm the new tests fail for the right
  reason

## 3. Implementation

- [x] 3.1 Replace `ip_check` and `ipv6_check` with one check (design D1, D2, D3), point
  both `IP_ADDRESS` patterns at it, and update `ALL_VALIDATORS`
- [x] 3.2 Run `cargo test -p voidwall-pii` and `cargo test -p voidwall-pii --release`

## 4. Fixtures

- [x] 4.1 Move positive `IP_ADDRESS` fixtures in `crates/voidwall-pii` (`scanner.rs`,
  `hyperscan_detector.rs`, `benches/pii_benchmark.rs`) to public addresses (design D4)
- [x] 4.2 Do the same in `crates/voidwall/tests/` for every test that expects an
  `IP_ADDRESS` block
- [x] 4.3 Check `crates/voidwall/benches/payloads/` (for example `pii_nested.json`) and the
  status each k6 script expects for a payload with an address

## 5. Documentation

- [x] 5.1 In `docs/backlog.md` §3, remove the `IP_ADDRESS` validator item and the
  `0.11.0.0` false-positive bullet
- [x] 5.2 In `docs/model-guards.md`, remove the sentence that calls `IP_ADDRESS` a poor
  `validate_as` choice
- [x] 5.3 Search `docs/` and `ARCHITECTURE.md` for other text on what `IP_ADDRESS`
  reports, and update it

## 6. Verification

- [x] 6.1 Run `docker/ctl ai4p-eval` and record the IP row next to the baseline in design.md
- [x] 6.2 Run `cargo test --workspace` and `cargo clippy --workspace --all-targets`
- [x] 6.3 Run `openspec validate strict-ip-validation --strict`
- [x] 6.4 Review the diff against the spec delta with the `code-review` skill
