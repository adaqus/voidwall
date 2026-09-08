# Voidwall — Architecture

This document holds the shape of the system and the reasons behind it. It does not
state behaviour.

| You want | Read |
|---|---|
| What the system does today | `openspec/specs/<capability>/spec.md` |
| Work in flight | `openspec/changes/` |
| Work not started | `docs/backlog.md` |
| How Phases 1 to 20 were built | `docs/history/tasks-phases-1-20.md` |

---

## 1. What this is

An HTTP proxy and REST API that inspects traffic for personally identifiable
information. It can block a message, redact the PII in place, or add a header naming
what it found. It always records the detection as a metric, whatever action is
configured.

It is not an ingress controller. It sits in front of one, or beside one, or replaces
one in a small deployment.

The detection library is a separate crate and can be used on its own.

---

## 2. Shape

```
                    Single Binary / Container
  ┌─────────────────────────────────────────────────────────┐
  │                                                         │
  │  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐  │
  │  │ Reverse Proxy│  │ Forward      │  │ HTTP API     │  │
  │  │ HTTP :8082   │  │ Proxy        │  │ HTTP :8083   │  │
  │  │              │  │ :8084        │  │              │  │
  │  │              │  │  [NOT BUILT] │  │              │  │
  │  └──────┬───────┘  └──────┬───────┘  └──────┬───────┘  │
  │         │                 │                  │          │
  │         └────────┬────────┴──────────────────┘          │
  │                  │                                      │
  │          ┌───────▼────────┐                             │
  │          │Detection Engine│  interest → fan out → sort  │
  │          └───────┬────────┘                             │
  │                  │                                      │
  │          ┌───────▼────────┐                             │
  │          │ Regex PII Guard│  pool + resolve_overlaps    │
  │          └───────┬────────┘                             │
  │                  │                                      │
  │          ┌───────▼────────┐                             │
  │          │ Action Engine  │  block → redact → header    │
  │          └───────┬────────┘                             │
  │                  │                                      │
  │          ┌───────▼────────┐                             │
  │          │ Metrics        │                             │
  │          └────────────────┘                             │
  │                                                         │
  │  ┌────────────────────────────────────────────┐        │
  │  │ Admin                         HTTP :9090   │        │
  │  │ /metrics  /healthz  /readyz                │        │
  │  └────────────────────────────────────────────┘        │
  │                                                         │
  │  ┌────────────────────────────────────────────┐        │
  │  │ Ingress Controller Integration  [DEFERRED] │        │
  │  └────────────────────────────────────────────┘        │
  └─────────────────────────────────────────────────────────┘
```

One binary. Four modes, each enabled on its own. They share one detection engine.

### Why the ports are separate

The data plane and the admin surface bind different ports. In Kubernetes they become
two Services with independent NetworkPolicies, so metrics and probes never ride the
same path as customer traffic.

The admin port binds the loopback interface by default. Kubelet reaches a pod
directly for its probes, so that works with no external exposure. An operator moves it
to `0.0.0.0` only when Prometheus scrapes from another pod, and then restricts it with
a NetworkPolicy.

### Modules

`config`, `engine`, `scanner`, `action`, `reverse_proxy`, `forward_proxy`, `http_api`,
`admin`, `metrics`, `structured`, `tls`, `validate`, `error`.

`engine` holds the detection contract: the units a message decodes into, the findings a
guard returns, the `Guard` trait, and the `Engine` that runs the guards. Each guard owns
whatever it needs to detect — the regex PII guard owns the scanner pool.

`forward_proxy` and `tls` are empty files. See § 7.

---

## 3. The request path

1. The listener accepts the request and matches a route by the longest path prefix.
2. The handler buffers the body, up to the configured limit.
3. The body is classified by content type. JSON, CSV, and TSV are parsed into
   context-value fragments. Everything else stays flat text.
4. The handler builds the units — one for the body, one for the URL path, one for the
   query string, one per scanned header — and hands them to the detection engine.
5. The engine calls every guard whose declared interest matches a selected unit, awaits
   them, and merges what they return into one canonically ordered finding set.
6. Inside the regex PII guard, a scanner thread runs the detector chain and reduces its
   raw matches with `pii::resolve_overlaps` before returning them as findings.
7. The action engine applies block, then redact, then header. Redaction produces the
   replacement bytes from the findings; nothing before this point rewrites a message.
8. The proxy forwards to the upstream, or returns the block response.
9. The response travels the same path in the other direction, under its own action
   list.

Each stage has one job, and the boundary between stages is a plain data type. That is
why a stage can change without touching the rest.

---

## 4. Decisions

### 4.1 The scanner never runs on the async runtime

The PII scan is CPU-bound. It costs tens to hundreds of microseconds per request and
it does not yield.

Running it on the tokio runtime would block a worker thread for the whole scan, and
tokio sizes its pool for work that yields. Under load the runtime would stall on
scanning while sockets sat unread.

So `ScannerPool` spawns its own OS threads with `std::thread::spawn`. Each thread owns
one `pii::Scanner`. A bounded channel carries requests in, and a
`tokio::sync::oneshot` carries each reply back. The pool lives inside the regex PII
guard and is reachable from nowhere else, so a guard's threading is the guard's own
business.

The channel is bounded on purpose. A full channel blocks the caller on the tokio
blocking pool for a short timeout, then fails. That pushes backpressure up to the HTTP
layer instead of growing an unbounded queue in front of a saturated CPU.

Each thread owns its own scanner because the Vectorscan scratch space is not
shareable. That is also why the scanner is per-thread while the name gazetteer is not:
the gazetteer is immutable, so one memory-mapped copy serves every thread.

The pool has no explicit shutdown. It sits behind a boxed guard, so no caller can
reclaim it to shut it down; `Drop` closes the channel and joins every thread, and
`Engine::shutdown` logs only after the guards are released.

### 4.2 One resolved match set, everywhere

Detectors overlap. A national identity number can sit inside a longer digit run that
another pattern also matches. Left alone, one value would be counted twice, redacted
twice, and reported twice.

The regex PII guard therefore passes every detector result through
`pii::resolve_overlaps`, once per unit, before it returns a finding. Every number the
proxy publishes — the match count, the kind list, the Prometheus counter — derives from
that resolved set.

The policy itself lives in the library, in `crates/voidwall-pii/src/overlap.rs`. The proxy does
not reimplement it, and must not.

Resolution is scoped to a kind vocabulary, not to a message, and it runs once.
`resolve_overlaps` is a greedy pairwise pass, so resolving each guard's findings and
then resolving the union is not the same as resolving the union. While one guard is the
only producer of a vocabulary — which is the case today — that guard resolves and the
engine adds nothing. When a second producer of the same vocabulary appears, resolution
moves to the engine over the union and the per-guard pass goes away. Never both.

The same value at two distinct byte offsets stays two matches. Those are two separate
instances of PII, not a duplicate.

### 4.3 One engine, and a guard is one detection concern

Detection used to be a single hard-coded path: one function scanned, resolved,
redacted, and reported. A second detector had nowhere to go.

The seam is a **guard**: `name`, `interest`, `detect`. A guard returns findings and
does nothing else — it does not block, redact, add a header, or write a metric. One
`Engine` owns the guards and the stage order: select the units, drop the guards no unit
interests, fan out, merge, sort. A handler calls `Engine::guard` and acts on what comes
back.

The trait is defined in `voidwall`, not in a detection crate, because `voidwall-pii` cannot
depend on the binary crate and the tiers after it will not share one input shape. Each
guard adapts one detection crate to the contract.

Three consequences worth stating:

- **Output order is canonical, not arrival order.** Findings sort by unit, span start,
  span end, guard, then kind, with span-less findings last, and the kind list is a
  sorted set. Which guard finished first is invisible.
- **The fan-out polls, it does not spawn.** A guard future mostly awaits its own
  worker's reply, so spawning would buy no parallelism and cost a `'static` bound on
  everything the future borrows. `FuturesUnordered` lets a guard borrow the shared
  units instead of cloning them.
- **The engine short-circuits for a block and nothing else.** A blocked message is not
  going anywhere, so the remaining findings cannot change the outcome; a guard still
  running is abandoned and its findings do not appear. A redact or header outcome needs
  the full set, so it waits.

Redaction is an action, not a scan step. The guards report where the PII is; the action
engine turns those spans into replacement bytes. It reads the scanned content rather
than mutating it — an abandoned guard's worker may still hold a clone of the shared
units, so exclusive access is not guaranteed.

### 4.4 Structured bodies are parsed before they are scanned

Much PII is only recognizable next to a keyword: a bare seven-digit number is nothing,
but `phone: 555-1234` is a phone number.

In a JSON document the keyword and the value are separated by structure, not by
adjacency. Flat scanning of `{"phone_number": "555-1234"}` never sees them together.

So the proxy flattens the document into context-value fragments, then hands each one
to the library with its key path. The library synthesizes `"{context}: {value}"` and
runs the ordinary keyword pipeline. No detection logic changes.

The key-path walk exists because the separator pattern between a keyword and a value
accepts only a narrow character class. Any alphabetic segment sitting between them
breaks the match, so `data.user.phone_number` needs several attempts, each exposing a
different segment next to the separator. The common case resolves on the first.

Fragment offsets are document-absolute, so redaction can rewrite the original bytes
and keep the document valid.

### 4.5 Names need a dictionary, not a pattern

Keyword-gated regex has poor recall on values drawn from a finite vocabulary. Person
names are the case: recall sat between 12% and 38%. There is no format to match,
because a name is not generated, it is chosen from a list.

`DictionaryDetector` looks a candidate up in a finite-state transducer built offline
from public-domain sources. The cost is proportional to the text length and
independent of the dictionary size, which is what makes the approach viable at
microsecond scale.

A hit means "known name form", not "person here". `Rose`, `Will`, and `May` are names
and ordinary words. The build marks those forms, and a marked form fires only when
cheap evidence promotes it: mid-sentence capitalisation, an adjacent given and surname
pair, or a nearby honorific.

The residual call — is `will` a name here or a verb — is genuine disambiguation. A
lookup cannot make it. That is deferred, not solved.

The gazetteer carries no per-language flag. `Anna` and `Thomas` belong to many
languages at once, so a language bit would be ambiguous and usually wrong.

The detector runs last in the chain. Order does not change `mark_piis`, because the
proxy resolves the union anyway. It matters for `has_piis`, which short-circuits: the
cheap single-pass detectors should get first look, and the tokenisation-heavy one
should be skipped when something cheaper already matched.

### 4.6 An invalid config stops the start

There is no "skip the bad entries and carry on" mode.

Silently dropping a declared PII definition weakens detection without telling anyone.
The operator believes they are covered and they are not. A hard failure at startup is
loud, and it is caught before deployment by the `--validate` flag, which runs the
whole pipeline offline, including Vectorscan compilation.

For the same reason a per-route `scan` override replaces the defaults completely
rather than merging. A merge makes the effective configuration a function of two
places, and the operator reading the route cannot see what they will get.

Every configuration table carries `deny_unknown_fields`, so a key the schema does not
define fails the start and names itself. A misspelled key that is silently ignored
gives the operator a setting they believe is active and is not, which is the same
failure as a dropped PII definition.

### 4.7 No authentication

The HTTP API authenticates nobody. Access control belongs to the deployment: an
authenticating gateway in front, and network-level isolation around it.

Building a second credential system inside a data-plane component adds a key
distribution problem and a new attack surface, to duplicate what every deployment
already has.

---

## 5. Crates

Today:

| Crate | Holds |
|---|---|
| `crates/voidwall-pii` | the detector chain, `PiiKind`, `resolve_overlaps`, the gazetteer |
| `crates/voidwall` | HTTP, config, actions, metrics, the binary |

Read `crates/voidwall-pii/AGENTS.md` before editing the library. Vectorscan, the detector
chain, the keyword patterns, and the overlap policy all have rules there.

Planned:

| Crate | Holds |
|---|---|
| `voidwall-pii` | today's detector chain, plus the verdict types and the L1 gate |
| `voidwall-ml` | the model runtimes, behind one cargo feature each |
| `voidwall` | the proxy |

The library keeps the name `voidwall-pii` rather than becoming a `voidwall-core`. It is
one detection tier beside `voidwall-ml`, not a foundation under it, so a `core` name
would be wrong the moment the third crate lands.

The reason for a third crate is structural. A model cannot follow the detector
lifecycle: a `Detector` is built per `Scanner`, and a `Scanner` is built per OS
thread. A multi-gigabyte model cannot be built per thread. The cost classes differ by
six orders of magnitude, and the deadline logic has to see them apart. So a model tier
never joins the `Scanner` chain; the proxy orders the steps itself.

---

## 6. Platform

Linux only. Do not add platform-conditional code for another operating system.

Rust edition 2024. Vectorscan is a native dependency.

---

## 7. Not built

These appear in the config schema, in the module list, or in older documents. None of
them runs. `docs/backlog.md` holds the work.

| Item | State | Why it waits |
|---|---|---|
| Forward proxy mode | `forward_proxy.rs` is empty. `ForwardProxyConfig` parses and validates. The proxy logs one warning when the mode is enabled. | The reverse proxy and the API cover the current deployments. The egress case is the pivot's wedge, so it is being redesigned rather than built as specified. |
| TLS termination | `tls.rs` is empty. `TlsConfig` parses and validates. | Deployments terminate TLS at the ingress or the load balancer. |
| Forward proxy TLS interception | Not started. Needs the forward proxy first. | Certificate generation and distribution is a large surface. It only pays off with the egress case. |
| Ingress controller integration | Never started. | It needs an ext_proc or external-auth implementation per controller. Standalone modes came first. |
| Checksum validation toggle | Not started. `PiiConfig` has no `validate` field. Do not confuse it with the `--validate <path>` CLI flag, which is unrelated and does work. | It is an evaluation aid only. It disables every validator scanner-wide and inflates false positives. |

Container hardening is guidance, not enforcement. `docker/Dockerfile.voidwall` runs as
root and sets no security context. The Kubernetes settings below are what a deployment
should apply:

```yaml
securityContext:
  runAsNonRoot: true
  runAsUser: 65534
  readOnlyRootFilesystem: true
  allowPrivilegeEscalation: false
  capabilities:
    drop: [ALL]
```

---

## 8. Known limits

- **Name recall is capped by the gazetteer.** An out-of-vocabulary, foreign, or novel
  name is missed. Growing the dictionary raises recall and does nothing for precision.
- **Name precision is capped by homographs.** English female names and verb-names leak
  when the cheap gates fail. This axis does not improve with a larger dictionary. It
  needs a contextual model, which is a pivot phase.
- **The capitalisation gate weakens per language.** German capitalises every noun.
- **The keyword automaton is near a size threshold.** Adding another country's keyword
  list can regress clean throughput. Check before adding one.
- **Structured CSV scanning is the slow path.** Scanning runs per cell, so a
  name-dense CSV pays a fixed per-cell cost. Measured, not yet optimised.
