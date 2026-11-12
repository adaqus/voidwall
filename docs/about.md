# About Voidwall

AI agents, chatbots, and other apps send user input, documents, and tool output to large
language models. Hidden instructions in that text can take control of the model, and
personal data can leak to a third-party model provider. Voidwall finds both and blocks
the message before it reaches the model.

Voidwall is an AI guardrails proxy and API. It runs on your own infrastructure. Its
guards run on your hardware, so no other service gets your data for the check.

## How you use it

Voidwall has three entry points. You can use one or more of them.

```
client ──► Voidwall reverse proxy :8082 ──► upstream (for example an LLM API)
             │  clean   → forwarded unchanged
             └  finding → 403 {"error":"content blocked","kinds":["EMAIL"]}

client ──► LiteLLM proxy ──► upstream (for example an LLM API)
             │  pre_call and post_call → POST /beta/litellm_basic_guardrail_api :8083
             ├  clean   → {"action":"NONE"}, LiteLLM goes on
             └  finding → {"action":"BLOCKED","blocked_reason":"Voidwall blocked the message. Kinds: ..."}

application ──► POST /v1/scan :8083 ──► {"detected":true,"kinds":["EMAIL"],...}
```

- **Reverse proxy.** Put Voidwall in front of your model server. Your app needs no code
  change: point it at Voidwall instead of the server. Voidwall inspects the request and
  the response.
- **LiteLLM guardrail.** LiteLLM calls Voidwall before and after each model call.
- **HTTP API.** Your app sends a text to `/v1/scan` and gets the findings back. Nothing is
  forwarded.

See [api-reference.md](api-reference.md) for each answer.

## Guards

A guard is one detection concern. Each finding blocks the message. Voidwall does not
redact or rewrite a message.

- **Regex PII guard**: personal data and secrets, such as e-mail addresses, national IDs,
  bank accounts, and cloud keys, for many countries and languages. You can add your own
  rules.
- **Model guards**: an ONNX model that you choose, for example a prompt injection
  classifier or a model that finds names and postal addresses. The image ships two.
- **Hidden context guard**: a response that repeats a canary from the system prompt.

See [guards/README.md](guards/README.md).

## ONNX Runtime

Model guards run on [ONNX Runtime](https://onnxruntime.ai/), on the CPU. ONNX Runtime
1.28.0 is linked into the Voidwall binary, so the image needs no Python and no other
runtime. The build checks the ONNX Runtime archive by its SHA-256 hash and by the build
attestation of its publisher, pyke.

Each model guard loads its model at startup, and a model that does not load stops the
start. A model guard can run any ONNX text classifier or token classifier with a Hugging
Face `tokenizer.json`, if it fits an adapter. See
[guards/model-guards.md](guards/model-guards.md#adapters). The default models of the
image are pinned to a fixed revision and checked by SHA-256 before use.

There is no GPU support yet. For the CPU that ONNX Runtime needs, see
[hardware.md](hardware.md).

## Project status

Voidwall is alpha software. Every feature in these docs is built and has automated
tests: unit tests, and integration tests that start real servers and send real HTTP
requests. Each recipe was tested end to end on Linux, with the app versions it names.
Try Voidwall in development and test environments, and tell us what you find.

Known limits:

- The reverse proxy does not terminate TLS. Put a TLS proxy in front of it. It does
  connect to `https://` upstreams: see
  [HTTPS upstreams](configuration.md#https-upstreams).
- Streaming (SSE) is inspected only on routes with `format = "openai-chat"`.
- Docker Desktop on macOS and on Windows is not tested yet. See [hardware.md](hardware.md).

Until version 1.0, a release can change the configuration format, the HTTP API, or the
metrics. [CHANGELOG.md](../CHANGELOG.md) marks each such change with **BREAKING**. Pin
the image to a release tag, such as `ghcr.io/adaqus/voidwall:0.5.1`, and read the
changelog before you upgrade. The `0.5` tag follows the patch releases of 0.5, and
`latest` follows every release.

## Licence

Voidwall is licensed under the [Apache License 2.0](../LICENSE). See [NOTICE](../NOTICE)
for attribution. The licence texts of ONNX Runtime and other vendored parts are in
[licenses/](../licenses/). Both default models are licensed under Apache-2.0 by their
authors. The image holds a `LICENSE` file next to each model.
