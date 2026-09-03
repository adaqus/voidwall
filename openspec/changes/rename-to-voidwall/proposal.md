## Why

The project is named Voidwall, but the code still calls itself `pii-proxy`. The package,
the binary, the library crate, the config environment variable, and all seven metric
families carry the old identity. Every one of them is user-facing, and a metric rename
breaks dashboards.

Phase 31 makes the source repository public. After that, the cost of this rename
multiplies by the number of users. Today the only deployment is the local Docker stack, so
the rename costs one change. This is the last cheap moment to do it.

## What Changes

**Identity**

- **BREAKING** Package `pii-proxy` becomes `voidwall`; the binary becomes `voidwall`.
  Directory `crates/proxy/` becomes `crates/voidwall/`.
- **BREAKING** Library crate `pii` becomes `voidwall-pii`. Directory `crates/pii/` becomes
  `crates/voidwall-pii/`. Rust paths change from `pii::` to `voidwall_pii::`.
- **BREAKING** Environment variable `PII_PROXY_CONFIG` becomes `VOIDWALL_CONFIG`.
- **BREAKING** Metric families are renamed. Three are PII-tier scoped and four are
  engine-wide:

  | Old | New |
  |---|---|
  | `pii_proxy_detections_total` | `voidwall_pii_detections_total` |
  | `pii_proxy_redacted_total` | `voidwall_pii_redacted_total` |
  | `pii_proxy_blocked_total` | `voidwall_pii_blocked_total` |
  | `pii_proxy_requests_total` | `voidwall_requests_total` |
  | `pii_proxy_request_duration_seconds` | `voidwall_request_duration_seconds` |
  | `pii_proxy_errors_total` | `voidwall_errors_total` |
  | `pii_proxy_specialization_errors_total` | `voidwall_specialization_errors_total` |

- **BREAKING** Docker artifacts are renamed: `docker/proxy.toml` to
  `docker/voidwall.toml`, `docker/Dockerfile.proxy` to `docker/Dockerfile.voidwall`, the
  Compose service `proxy` to `voidwall`, the container config path `/etc/pii-proxy/` to
  `/etc/voidwall/`, the Prometheus job `pii-proxy` to `voidwall`, and the Grafana dashboard
  file to `voidwall.json`.

**Framing**

- The binary's `--help` description and the library crate description state the
  destination and the current reality: an AI guardrails engine that does PII detection
  today. They stop describing PII as the only thing the product does.
- `AGENTS.md` and `crates/voidwall-pii/AGENTS.md` are rewritten so no rule names PII as
  the only threat. Their `CLAUDE.md` compatibility symlinks are unchanged.

**Explicitly unchanged.** These carry entity names, not project names, and renaming them
would churn a user-facing surface for no gain:

- The `[pii]` config table and its keys `countries`, `languages`, `scanner_threads`,
  `detect`, `ignore`, and `custom`.
- The `pii_kind` metric label.
- The Rust types `PiiKind`, `PiiMatch`, `PiiError`, `UserPiiDefinition`, and `PiiConfig`.
- The `pii-scanning`, `custom-pii`, and `dictionary-detection` capability directory names.
- `docs/history/tasks-phases-1-20.md`. It is history.

## Capabilities

### New Capabilities

None. This change renames identifiers and moves files. It adds no behavior.

### Modified Capabilities

- `metrics`: all seven metric family names change.
- `actions`: the three metric names cited in action requirements change.
- `configuration`: the config environment variable name changes.
- `pii-scanning`: the cited metric name and the `pii::` crate paths change.
- `dictionary-detection`: the cited metric name and the `pii::` crate path change.
- `specializations`: the cited metric name changes.

Three capabilities that an earlier scoping listed are **not** modified, because the
decisions above keep every token they cite: `custom-pii` and `security` cite only
`pii_kind` and `pii.custom`, and `http-api` cites only `pii.custom`.

## Impact

**Code.** 18 Rust files use `pii::` paths (129 references). `crates/proxy/src/metrics.rs`
registers the seven families; 5 integration test files assert on their names.
`crates/proxy/src/config.rs` holds the clap `name` and `about` strings and four test
argument vectors.

**Build and deploy.** Both `Cargo.toml` manifests, the workspace `members` list,
`Cargo.lock`, `.dockerignore`, `docker/Dockerfile.voidwall`, `docker/docker-compose.yml`,
`docker/prometheus/prometheus.yml`, `docker/ctl`, and
`crates/voidwall/benches/run.sh`. Renaming the Compose service cascades into three
`depends_on` blocks and the Prometheus scrape target.

**Docs.** `docs/api-docs.md` and `docs/config-validation.md` cite the old binary and config
file names. `ARCHITECTURE.md` and `AGENTS.md` cite the old crate paths.

**Agent tooling.** Four skills under `.agents/skills/` reference `crates/pii`: `add-pii`,
`ai4privacy-eval`, `ai4privacy-sweep`, and `ai4privacy-audit`. `ai4privacy-merge` and
`code-review` are already clean.

**Downstream plan.** Later pivot phases name a `voidwall-core` crate that this change does
not create. That crate name is abandoned in favour of `voidwall-pii`; the roadmap needs
the substitution recorded before Phase 23 starts.

**Not affected.** No request or response behavior changes. No config key changes. No
detection result changes. A running proxy scans, redacts, and blocks exactly as before.
