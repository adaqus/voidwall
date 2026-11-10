# Voidwall Documentation

Voidwall is an AI guardrails proxy and API. It finds prompt injection and personal data
in HTTP traffic, and it blocks the message before it reaches the local LLM or external
LLM provider.

These docs describe one release. Open them at the tag of the image you run, for example
`github.com/adaqus/voidwall/tree/v0.5.0/docs`.

## Start here

- [About](about.md): what Voidwall is, how you use it, and the project status.
- [Quick start](quick-start.md): run the image and send test messages.
- [Hardware](hardware.md): the CPU, memory, and disk that Voidwall needs.

## Recipes

- [Recipes](recipes/README.md): choose a recipe, with notes on documents, embeddings,
  and streaming.
- [LM Studio](recipes/lm-studio.md): put Voidwall in front of LM Studio.
- [LiteLLM](recipes/litellm.md): Voidwall as a LiteLLM guardrail, also for hosted models.
- [AnythingLLM](recipes/anythingllm.md): AnythingLLM, Voidwall, and LM Studio or Ollama.
- [Ollama](recipes/ollama.md): put Voidwall in front of Ollama.

## Reference

- [API reference](api-reference.md): the HTTP API routes, the answers of the reverse
  proxy, and the admin server. The contract of the HTTP API is in
  [openapi.json](openapi.json).
- [Configuration](configuration.md): every key of the config file, its default, and how
  to check a file with `voidwall --validate`.

## Guards

- [Guards](guards/README.md): what a guard is, what it reads, and what a finding does.
- [Regex PII guard](guards/pii-regex.md): choose the PII kinds, add your own rules, and
  see every built-in kind.
- [Model guards](guards/model-guards.md): run an ONNX model as a guard.
- [Hidden context guard](guards/hidden-context.md): block a response that repeats a
  canary or other marker.
- [Add your own guard](guards/custom-guard.md): mount your own model and declare a guard
  for it.

## Security

- [OWASP coverage](owasp-coverage.md): Voidwall against the OWASP Top 10 for LLM
  Applications (2026), and why some risks need another layer.

## For contributors

[dev/](dev/) holds the backlog, the TODO list, and the load-test design. To build from
source, see [DEVELOPMENT.md](../DEVELOPMENT.md).

More topics come later.
