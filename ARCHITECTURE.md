# Voidwall — Architecture

This document holds the shape of the system and the reasons behind it. It does not
state behaviour.

| You want | Read |
|---|---|
| What the system does today | `openspec/specs/<capability>/spec.md` |
| Work in flight | `openspec/changes/` |
| Work not started | `docs/backlog.md` |

---

## 1. What this is

An HTTP proxy and REST API that inspects traffic and acts on what it finds. A guard
reports findings and the engine merges them. A detection blocks the message with a
fixed 403 naming the kinds that were found; there is no action to choose. The
detection is always recorded as a metric, whether the message is blocked or reported
on.

Personally identifiable information is the class of finding it detects today. Each
further class arrives as another guard behind the same contract. A model-backed guard
(§ 4.8) runs an ONNX classifier over the units its surface admits.

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
  │          │ Block or pass  │  detected ⇒ 403, or 400     │
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

One binary. Two traffic modes, each enabled on its own, plus the admin server, which always
runs. They share one detection engine. The forward proxy is not built, and validation rejects
it.

### Why the ports are separate

The data plane and the admin surface bind different ports. In Kubernetes they become
two Services with independent NetworkPolicies, so metrics and probes never ride the
same path as customer traffic.

The admin port binds the loopback interface by default. Kubelet reaches a pod
directly for its probes, so that works with no external exposure. An operator moves it
to `0.0.0.0` only when Prometheus scrapes from another pod, and then restricts it with
a NetworkPolicy.

### HTTP API routes

The HTTP API listener serves two routes, each behind its own switch:

- `POST /v1/scan` (`http_api.scan.enabled`): the raw body is the content, parsed by its
  `Content-Type`.
- `POST /beta/litellm_basic_guardrail_api` (`http_api.litellm.enabled`): LiteLLM's
  Generic Guardrail API. `structured::litellm` decodes the payload, and
  `structured::chat_completions` selects the fields of the Chat Completions messages,
  tools, and tool calls to scan. Each top-level entry becomes one body unit.

Both default to true. `http_api.enabled` starts the listener, and enabling it with every
route off fails validation. A route that is off does not exist, so it answers 404. Both
routes report and never block, and they share the metric and error helpers.

### Reverse proxy route formats

A route without `format` scans each body by its content type, as § 3 states. A route with
`format = "openai-chat"` decodes OpenAI Chat Completions instead: `structured::openai_chat`
parses the request and the response, and `structured::chat_completions` holds every field
rule. Each message, tool, choice, and kept top-level field becomes one body unit, and a
top-level key the tables do not list is scanned. The route ignores `content_types`.

The format also decides the shape of every answer on the route. `reverse_proxy` builds
each answer through one `answer` and one `block` function, so no path can answer the
route in the flat shape. A detection answers 400 in the OpenAI error shape, and each error
keeps its status with an OpenAI-shaped body. The 404 for an unmatched path is outside every
route and stays plain.

The response content type is read before the body. A body that is neither JSON nor a
`text/event-stream` is unscannable and follows `on_error`; under `fail_open` it streams
through unbuffered. Upstreams are reached over plain HTTP only (§ 7).

A `text/event-stream` response is scanned as a stream, whatever the request said about
`stream`. `structured::sse` frames the events and keeps each one's raw bytes;
`structured::openai_chat_stream` joins the text of each choice and field, keyed by the path
the field has under `choices[].message`, and reads it by the same field rules. The route's
`stream` key picks the mode:

- `holdback` (the default): the window in `reverse_proxy::holdback` keeps
  `stream_holdback_bytes` of each joined text back, scans every `stream_scan_bytes` of new
  text with `stream_context_bytes` of sent text before it, and releases whole upstream
  events, unchanged and in order, once a scan clears them. A finding that ends in the last
  2 bytes waits for more text; a finding without a span waits one scan. A text closes when
  its choice sends text for another field or tool call, or sends `finish_reason`: it is
  scanned as at the end and released whole, and it opens again if more text comes. The
  status and headers wait for the first release, so a stop before it answers as a
  buffered response does. After it, a stop sends one `data:` event with the same error
  body and closes, without `[DONE]`.
- `buffer`: the whole stream is read, scanned once, and then sent as the exact upstream
  bytes or answered with the 400.

The proxy does not decompress. A stream with a `Content-Encoding` other than `identity`
is unscannable in both modes and follows `on_error`.

For a stream, `upstream_timeout_secs` bounds only the wait for the headers. Each read of
the body runs under `stream_idle_timeout_secs`, and the body counts against
`max_body_size`; both stop the stream whatever `on_error` says.

### Modules

`config`, `engine`, `scanner`, `reverse_proxy`, `forward_proxy`, `http_api`,
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
   context-value fragments. Everything else stays flat text. On a route with
   `format = "openai-chat"` the body is decoded as Chat Completions instead (§ 2).
4. The handler builds the units — one for the body, one for the URL path, one for the
   query string, one per scanned header — and hands them to the detection engine.
5. The engine calls every guard whose declared interest matches a selected unit, awaits
   them, and merges what they return into one canonically ordered finding set.
6. Inside the regex PII guard, a scanner thread runs the detector chain and reduces its
   raw matches with `pii::resolve_overlaps` before returning them as findings.
7. A detection counts its kinds, counts the block, and answers 403 with those kind
   names, or 400 in the OpenAI error shape on an `openai-chat` route. Nothing anywhere on this path rewrites a message.
8. With no detection, the proxy forwards to the upstream unchanged.
9. The response travels the same path in the other direction, when `response.scan` is
   true. A `text/event-stream` on an `openai-chat` route is scanned as it arrives instead
   of buffered whole, in hold-back or buffer mode (§ 2).

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
another pattern also matches. Left alone, one value would be counted twice, listed
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

Detection classes differ in everything except their output. A regex chain, a dictionary
lookup, and a model share no input shape, no cost class, and no threading model. What
each one does share is that it reports where something was found, and nothing more.

The seam is a **guard**: `name`, `interest`, `detect`. A guard returns findings and
does nothing else — it does not block the message, change it, or write a metric. One
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
  running is abandoned and its findings do not appear. A caller that reports rather
  than blocks needs
  the full set, so it waits. An abandoned model guard cancels its run when its future
  is dropped: ONNX Runtime stops at the next graph node, a queued job is skipped, and
  the worker takes the next job. A cancelled run is not a failure and is not counted.

Nothing rewrites a message. A guard reads the units it was handed and reports spans; no
stage downstream turns those spans into replacement bytes. That is not only a policy
choice — an abandoned guard's worker may still hold a clone of the shared units, so
exclusive access to the content is never guaranteed anyway.

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

Fragment offsets are document-absolute, so a span from one fragment is directly
comparable with a span from another. Overlap resolution and the resolved match count
are defined over those spans, so fragment-local offsets would make two unrelated values
look like they overlap.

A decoder that keeps some fields and skips others, such as the Chat Completions one
behind `format = "openai-chat"` and the LiteLLM route, walks the parsed document and
records one decision per string leaf. It pairs the decisions with the flattener's
fragments by position, not by key path. A key path does not escape `.` or `[` inside a
key, so matching by path could take one key for another and drop a value unscanned. A
leaf count that differs between the two walks is a scanner failure.

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

For the same reason a route names the guards that run for it rather than overriding a
table of settings. `guards` is a list of names: an absent list takes every enabled
guard, and an empty list takes none. There is nothing to merge, so the effective
configuration is not a function of two places and the operator reading the route sees
what they will get.

Nearly every configuration table carries `deny_unknown_fields`, so a key the schema does
not define fails the start and names itself. A misspelled key that is silently ignored
gives the operator a setting they believe is active and is not, which is the same
failure as a dropped PII definition.

`[builtin_guards]` is the one deliberate exception. A key there names a guard rather
than a setting, so an unknown one is captured and rejected in semantic validation, which
can say "unknown built-in guard 'jailbreak'" and list the guards the build has. A schema
error would only say the field is unknown.

### 4.7 A guard's surface is four booleans, and the route decides what exists

Every guard carries a `surface` — `url_path`, `query_params`, `body`, `headers` — which
is the configuration form of its `Interest`. It is per guard, not global, so two enabled
guards may want different parts of the same message, and a unit kind no selected guard
admits is never built.

`headers` is a boolean rather than a list of header names, and that split is the point.
Which headers carry sensitive values is a property of the traffic, not of a detector, so
the *route* names the headers that become units at all. The guard's boolean then says
only whether it wants the ones that exist. Putting the list in the guard would make the
effective set a function of two places, and the engine could not enforce it anyway — a
unit carries its kind, not a header name.

A surface that disables all four describes a guard that can never be called, so it fails
the start.

The two guard kinds carry different defaults. A built-in guard defaults every target on:
a regex pass over a URL is nearly free and an email in a path is a real hit. A model
guard defaults to the body alone, because each unit it admits costs one model execution,
so a default of path plus query plus body would turn one request into three. They are
therefore separate types rather than one type with two default sets — a serde default on
the *field* would not change the inner per-field defaults, so a half-written model guard
surface would silently take the built-in's.

### 4.8 A model guard owns its model

A guard an operator configures is declared under `[guards.<name>]`. That one section
carries the adapter, the artifacts, `max_tokens`, the labels, the thresholds, and the
surface. There is no model section and no model reference, which makes "one guard owns
one model" structural rather than a rule: a guard's model is not addressable from
anywhere else. That is the same move `[builtin_guards.pii]` makes for the
second-PII-instance question.

`adapter` names a code path the build ships. It owns the runtime, the preprocessing, the
tensor contract, the output interpretation, and whether findings carry spans.
Configuration picks one by name and overrides none of it, so an unknown adapter is a
schema failure rather than a rule — the build fixes the set, so the schema can state it.
Nothing names a runtime: ONNX is the only one, so the key could only be written wrong.

`labels` names the kinds a guard reports. It may not be empty and may not name one kind
twice. `text_classifier` takes exactly one label, and it names class 1 of the model's two
outputs, not output position 0: every candidate injection model has a 2-logit head with
the attack class at 1, and the ONNX file carries no class names to check that against, so
the docs and the parity harness carry the class order. `text_multilabel_classifier` is
rejected at startup until its run side is built. `thresholds` has no default, because the build has no evaluated number for an
arbitrary model; a label absent from it reports nothing, and that absence is the only
detection-layer off switch. A threshold key absent from `labels` is rejected, so a
misspelling is an error rather than a silently disabled kind. A label itself is not
checked against a vocabulary: there is no closed set of finding kinds to check against.

Each section builds one `ModelGuard` (`engine/model.rs`) at startup. It loads its model
into `threads` workers — default the CPUs divided by the number of model guards, at least
1; a total above the CPU count only warns — and gives each worker its own OS thread, the
same pool shape as `ScannerPool`. A unit's score at or above the label's threshold is one
span-less finding with the score as its confidence. The guard scores one text per unit:
plain text decoded lossily, so one invalid byte cannot hide a unit, and a JSON body's
values joined with newlines in document order. API-aware decoders replace that join in
the decoder phases.

A model guard failure is an `Error::Inference` (500 under `fail_close`,
`reason="inference_failure"`); a unit past the window limit is an `Error::WindowLimit`
(413, body `tokenized content too long to scan`, `reason="window_limit"`). The error,
not the handler, names its status and reason, so no handler branches on a guard.

Loading takes seconds per guard, so `server::run` binds the admin server first, builds the
engine on the blocking pool, and binds the data plane only after every guard has loaded:
`/healthz` answers throughout, `/readyz` answers 503 until the data plane is up, and a
load failure exits non-zero with no partial start. `--validate` stays offline and loads
no model. The `voidwall_pii_*` metric families count only the `pii` guard's findings.

### 4.9 No authentication

The HTTP API authenticates nobody. Access control belongs to the deployment: an
authenticating gateway in front, and network-level isolation around it.

Building a second credential system inside a data-plane component adds a key
distribution problem and a new attack surface, to duplicate what every deployment
already has.

For the same reason the HTTP API listener sends no CORS header: a wildcard
`Access-Control-Allow-Origin` on a listener that authenticates nobody would let any
page on the internet post bodies to it, so cross-origin permission belongs to the
gateway that supplies the authentication.

---

## 5. Crates

Today:

| Crate | Holds |
|---|---|
| `crates/voidwall-pii` | the detector chain, `PiiKind`, `resolve_overlaps`, the gazetteer |
| `crates/voidwall-ml` | `AdapterKind`, the CPU floor check, the linked ONNX Runtime, and the model load: `LoadSettings`, trait `Adapter`, `load()` → N `Worker`s; `Worker::score` → one unit score or `RunError`, stoppable through a `Cancel`. The `test-fixtures` feature exposes tiny fixture models to other crates' tests |
| `crates/voidwall` | HTTP, config, metrics, the binary |
| `crates/voidwall-eval` | `ai4privacy-eval`: scores `voidwall-pii` against AI4Privacy openpii300k, through `docker/ctl ai4p-eval`. `piimb-spans`: writes its spans for the PII Masking Benchmark, which `docker/ctl piimb-eval` scores with the benchmark's own metric code. Depends on `voidwall-pii` only; not in the image |

Read `crates/voidwall-pii/AGENTS.md` before editing the library. Vectorscan, the detector
chain, the keyword patterns, and the overlap policy all have rules there.

Planned:

| Crate | Holds |
|---|---|
| `voidwall-pii` | today's detector chain, plus the verdict types and the L1 gate |
| `voidwall-ml` | the ONNX Runtime integration and the adapters |
| `voidwall` | the proxy |

`voidwall-pii` is one detection tier beside `voidwall-ml`, not a foundation under it.
It carries a tier name for that reason: nothing in it is a base layer for the model
crate, and a name suggesting otherwise would misdescribe the dependency.

`voidwall_ml::load(&LoadSettings)` turns one model guard's model into N workers. Each
worker owns one ONNX Runtime session with one intra-op thread, so a worker serves one OS
thread; `voidwall`'s model guard owns those threads and their channels, as the PII guard
owns `ScannerPool`'s.
The N sessions share one copy of the weights: the `.onnx` file is memory-mapped and decoded
once without copying its weight bytes, each initializer is copied once into a tensor every
session takes as an override, and one `PrepackedWeights` container holds the packed copies
for all N. ONNX Runtime parses a copy of the graph whose initializers of 1 KiB or more carry
no data, staged with an empty placeholder in a private temp directory (`TMPDIR`) for the
length of the load, so creating a session does not copy the weights again. A weight that
feeds only constant nodes keeps its data in that graph: ONNX Runtime's constant folding
reads it from the graph, not from the shared copy (PIGuard keeps 55.6 MiB of 701 MiB this
way; Wolf keeps none). Measured on a
256 MiB fixture with 4 sessions: 1.03× the weights kept, 2.00× at the startup peak, half of
which is mapped file pages the kernel can drop. The sessions load in parallel after the
first. A load returns only after the tensor contract, the tokenizer-against-embedding
check, and one smoke inference per session have passed, so a model that loads also runs.

`Worker::score(text, &Cancel)` scores one unit. It tokenizes with the model's `tokenizer.json`
(truncation and padding in the file do not apply) and cuts the tokens into overlapping
windows: the window is `max_tokens` minus the special tokens the tokenizer adds, the
overlap is `overlap_tokens` (default `min(128, max_tokens / 2)`, at most `max_tokens / 2`),
and the last window ends at the last token. Each window gets the special tokens, is padded
to N under attention mask 0 when the model fixes the sequence dimension at N, and runs
alone at batch size 1. The adapter turns a window's logits into a score (`text_classifier`:
`softmax[1]`), and the unit score is the highest window score. A unit that needs more than
`ceil(max_body_size / stride)` windows fails with `RunError::WindowLimit` before any
inference runs; a failed inference, a wrong output shape, or a non-finite logit fails
with the matching `RunError`, never a score. No `RunError` carries the unit's text.
A `Cancel` stops a run from another thread: the run checks it before it tokenizes and
before each window, and its `RunOptions` terminate flag stops an inference in progress at
the next graph node. A cancelled run returns `RunError::Cancelled`, which the model guard
treats as "nobody waits", never as a failure.
`crates/voidwall-ml/parity/` checks the scores against Python `tokenizers` and PyTorch on
real models; it needs model files, so it runs by hand, not in CI.

A model cannot follow the detector lifecycle: a `Detector` is built per `Scanner`, and a
`Scanner` is built per OS thread. A multi-gigabyte model cannot be built per thread. The
cost classes differ by six orders of magnitude, and the deadline logic has to see them
apart. So a model tier never joins the `Scanner` chain; the proxy orders the steps itself.

The reason the model code is a crate rather than a module of `voidwall` is the
dependency boundary. `voidwall-ml` cannot depend on `voidwall`, so an adapter cannot
reach the engine, metrics, HTTP, or configuration internals: it can only load a model
and return scores. `voidwall` turns scores into findings. A module could import any
sibling, and only review would stop it. This matters most for adapters contributed from
outside the project.

---

## 6. Platform

Linux only. Do not add platform-conditional code for another operating system.

Rust edition 2024. Vectorscan is a native dependency.

ONNX Runtime 1.28.0 is linked statically from pyke's prebuilt archive. `docker/fetch-ort.sh`
checks its SHA-256 and its build attestation before Cargo sees it, and
`.cargo/config.toml` points every build at the verified copy with downloads turned off.

The minimum CPU is x86-64-v3 (Intel Haswell or later, any AMD Ryzen). ONNX Runtime's static
constructors run AVX code before `main`, so the binary checks the CPU from its
`.preinit_array`, which runs first, and refuses to start with a message naming the missing
features. Without that, a CPU without AVX dies with SIGILL (exit 132) and no log line.

---

## 7. Not built

These appear in the config schema or the module list. None of them runs.
`docs/backlog.md` holds the work.

| Item | State | Why it waits |
|---|---|---|
| Forward proxy mode | `forward_proxy.rs` is empty. `ForwardProxyConfig` parses, and validation rejects `forward_proxy.enabled = true`. | The reverse proxy and the API cover the current deployments. Egress inspection is a larger design than the config schema implies, and its shape is still being settled. |
| TLS termination | `tls.rs` is empty. `TlsConfig` parses, and validation rejects `tls.enabled = true`. | Deployments terminate TLS at the ingress or the load balancer. |
| Upstream TLS | Every upstream client is `build_http()`. An `https://` upstream passes validation and fails with 502. | The `format = "openai-chat"` route was scoped to plain-HTTP servers such as vLLM and Ollama. |
| Forward proxy TLS interception | Not started. Needs the forward proxy first. | Certificate generation and distribution is a large surface. It only pays off with the egress case. |
| Ingress controller integration | Never started. | It needs an ext_proc or external-auth implementation per controller. Standalone modes came first. |
| Checksum validation toggle | Not started. `PiiGuardConfig` has no `validate` field. Do not confuse it with the `--validate <path>` CLI flag, which is unrelated and does work. | It is an evaluation aid only. It disables every validator scanner-wide and inflates false positives. |

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

## 8. Known limits of the PII tier

These bound what the regex PII guard and its detector chain can find. They are not
limits of the engine or of the guard contract.

- **Name recall is capped by the gazetteer.** An out-of-vocabulary, foreign, or novel
  name is missed. Growing the dictionary raises recall and does nothing for precision.
- **Name precision is capped by homographs.** English female names and verb-names leak
  when the cheap gates fail. This axis does not improve with a larger dictionary. It
  needs a contextual model, and no lookup substitutes for one.
- **The capitalisation gate weakens per language.** German capitalises every noun.
- **The keyword automaton is near a size threshold.** Adding another country's keyword
  list can regress clean throughput. Check before adding one.
- **Structured CSV scanning is the slow path.** Scanning runs per cell, so a
  name-dense CSV pays a fixed per-cell cost. Measured, not yet optimised.
