## 1. Baseline

- [x] 1.1 Record the pre-change counts of the five protected tokens — `pii_kind`,
  `PiiKind`, `[pii]` plus the `pii.` config keys, `X-PII-Detected`, and the
  `pii-scanning`/`custom-pii`/`dictionary-detection` capability paths — into a scratch
  file → verify: the file lists five counts, and `git status` is clean

## 2. Directory moves and manifests

- [x] 2.1 `git mv crates/pii crates/voidwall-pii` and `git mv crates/proxy
  crates/voidwall` → verify: `git status` shows both as renames, not as delete-plus-add
- [x] 2.2 Set `crates/voidwall-pii/Cargo.toml` `name = "voidwall-pii"` and
  `description = "PII detection library for Voidwall"` → verify: `grep -c 'name = "pii"'`
  returns 0
- [x] 2.3 Set `crates/voidwall/Cargo.toml` `name = "voidwall"`, and update its `pii`
  path dependency to `voidwall-pii` → verify: the manifest names no `pii-proxy` and no
  bare `pii` dependency
- [x] 2.4 Update the workspace `members` list in the root `Cargo.toml` → verify:
  `cargo metadata --no-deps` lists exactly `voidwall` and `voidwall-pii`
- [x] 2.5 Regenerate `Cargo.lock` → verify: `grep -c 'pii-proxy' Cargo.lock` returns 0

## 3. Rust identifier sweep

- [x] 3.1 Rewrite the three PII-tier metric names to `voidwall_pii_*` **before** any
  other `pii_proxy_` substitution, per design Decision 4 → verify:
  `grep -rc 'voidwall_pii_detections_total' crates/voidwall/src/metrics.rs` returns 1
- [x] 3.2 Rewrite the remaining `pii_proxy_` to `voidwall_` → verify:
  `grep -rn 'pii_proxy_' crates/` returns nothing
- [x] 3.3 Rewrite `PII_PROXY_CONFIG` to `VOIDWALL_CONFIG` → verify:
  `grep -rn 'PII_PROXY_CONFIG' crates/` returns nothing
- [x] 3.4 Rewrite `\bpii::` to `voidwall_pii::` across the 18 files that use it → verify:
  `grep -rn '\bpii::' crates/` returns nothing and `cargo check --workspace` passes
- [x] 3.5 Rewrite `pii-proxy` in `crates/voidwall/src/` and the four clap test argument
  vectors in `config.rs` → verify: `grep -rn 'pii-proxy' crates/` returns nothing
- [x] 3.6 Set the clap `about` to `"AI guardrails engine — PII detection today"` →
  verify: `cargo run -p voidwall -- --help` prints the new line and the binary name
  `voidwall`
- [x] 3.7 Confirm the sweep touched no protected token → verify: the five counts from
  task 1.1 are unchanged

## 4. Docker and observability

- [x] 4.1 `git mv docker/proxy.toml docker/voidwall.toml` and `git mv
  docker/Dockerfile.proxy docker/Dockerfile.voidwall` → verify: `git status` shows two
  renames
- [x] 4.2 Update `Dockerfile.voidwall`: the `COPY` source, the `/usr/local/bin` target,
  and `ENTRYPOINT` → verify: `grep -c 'pii-proxy' docker/Dockerfile.voidwall` returns 0
  and the `echo-server` line is untouched
- [x] 4.3 Edit `docker/docker-compose.yml` **by hand**, per design Decision 5: service
  `proxy` to `voidwall`, the three `depends_on` entries, both `dockerfile:` keys, the
  `--config` path, and the volume mount → verify: `docker compose config` resolves with
  no unknown-service error, and `reverse_proxy`/`forward_proxy` strings are unchanged
- [x] 4.4 Edit `docker/prometheus/prometheus.yml` **by hand**: `job_name` and the scrape
  target → verify: the target names the renamed Compose service
- [x] 4.5 Update `.dockerignore` and `crates/voidwall/benches/run.sh` binary paths →
  verify: `grep -rn 'pii-proxy' .dockerignore crates/voidwall/benches/` returns nothing
- [x] 4.6 `git mv docker/grafana/dashboards/pii-proxy.json` to `voidwall.json` and rewrite
  its PromQL → verify: `grep -c 'pii_proxy_' docker/grafana/dashboards/voidwall.json`
  returns 0
- [x] 4.7 Update `docker/ctl` binary and config paths → verify: `docker/ctl start` brings
  the stack up, `/metrics` serves the seven `voidwall_*` families, and no family begins
  with `pii_proxy_`
- [x] 4.8 Load the renamed dashboard against the running stack → verify: every panel
  draws data, none is empty

## 5. Specs and OpenSpec context

- [x] 5.1 Update the `context` block in `openspec/config.yaml` — crate paths, package
  names, `VOIDWALL_CONFIG`, `voidwall_pii::Scanner`, `voidwall_pii::resolve_overlaps`,
  `voidwall_errors_total`, and `crates/voidwall-pii/src/overlap.rs` → verify: `openspec
  instructions proposal --change rename-to-voidwall --json` returns a context naming no
  retired token
- [x] 5.2 Confirm the six delta specs match what was built → verify: `openspec validate
  rename-to-voidwall --strict` passes
- [x] 5.3 Confirm no spec outside the six needs a delta → verify: `grep -rE
  'pii_proxy_|PII_PROXY_CONFIG|pii::' openspec/specs/` returns hits only in the six
  capabilities this change carries

## 6. Docs and instruction files

- [x] 6.1 Rewrite `AGENTS.md`: crate paths, package and binary names, `VOIDWALL_CONFIG`,
  metric names, and the module list → verify: no rule names PII as the only threat, and
  the `Spec-Driven Development (OpenSpec)` section is intact
- [x] 6.2 Fix the stale metric name at `AGENTS.md:97`, which reads
  `pii_detections_total{kind=...}` and never matched a registered family → verify: the
  line names `voidwall_pii_detections_total{pii_kind=...}`
- [x] 6.3 Correct the OpenSpec rule that reads "the change is a pivot phase, that is
  Phase 21 to Phase 31" — it sweeps in 21.5a and 21.5b, which ship no code, and stops at
  31, which is no longer last → verify: the rule reads as a pivot phase **that ships
  code**
- [x] 6.4 Rewrite `crates/voidwall-pii/AGENTS.md` → verify: its `CLAUDE.md` symlink still
  resolves, and `grep -rn 'crates/pii' crates/voidwall-pii/` returns nothing
- [x] 6.5 Update `ARCHITECTURE.md`, `docs/api-docs.md`, and `docs/config-validation.md` →
  verify: `grep -rn 'pii-proxy\|proxy\.toml' ARCHITECTURE.md docs/*.md` returns nothing
- [x] 6.6 Leave `docs/history/tasks-phases-1-20.md` untouched → verify: `git diff --stat`
  lists no change to that file

## 7. Agent tooling

- [x] 7.1 Sweep `crates/pii` and `-p pii` from the four skills that carry them —
  `add-pii`, `ai4privacy-eval`, `ai4privacy-sweep`, `ai4privacy-audit` → verify:
  `grep -rn 'crates/pii\|-p pii\b' .agents/skills/` returns nothing
- [x] 7.2 Confirm `ai4privacy-merge` and `code-review` need no edit → verify: both files
  are absent from `git diff --name-only`
- [x] 7.3 Confirm the `.claude/skills/` compatibility symlinks still resolve → verify:
  `ls -L .claude/skills/` lists 13 entries with no broken link
*7.4 dropped.* Running `add-pii` end to end would add a country — new detection code and
tests — which is feature work, not rename verification. Task 7.1's grep and the passing
workspace suite already prove the renamed paths resolve.

## 8. Cross-repo

- [x] 8.3 Amend the internal roadmap: substitute
  `voidwall-core` with `voidwall-pii` in all 12 places, correct the § 6.1 OpenSpec table
  from nine specs to six, and record that Phase 22 step 2 is answered by keeping `[pii]`
  → verify: `grep -c 'voidwall-core' roadmap.md` returns 0

## 9. Acceptance

- [x] 9.1 Run the full build → verify: `cargo test --workspace` passes, and `cargo clippy
  --workspace --all-targets` reports no *new* warning. The 15 warnings it does report are
  pre-existing: 13 `is_multiple_of` lints in `validators.rs`, a file byte-identical to
  HEAD, and 2 in `scanner.rs` on lines byte-identical to HEAD. A newer clippy flags them;
  fixing them is an unrelated refactor and belongs in its own change
- [x] 9.2 Sweep the whole repo → verify: `grep -rn 'pii_proxy_\|PII_PROXY_CONFIG\|pii-proxy\|crates/pii'
  --exclude-dir=target --exclude-dir=.git .` returns hits only in
  `docs/history/tasks-phases-1-20.md`
- [x] 9.3 Confirm no behavior changed → verify: the integration suite passes unmodified
  except for metric-name and env-var assertions
- [x] 9.4 Review the diff against the six delta specs and then `ARCHITECTURE.md` →
  verify: the `code-review` skill reports no finding above informational
