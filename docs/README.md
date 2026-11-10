# Voidwall Documentation

Voidwall is an AI guardrails proxy and API. It finds prompt injection and personal data
in HTTP traffic, and it blocks the message before it reaches the model.

These docs describe one release. Open them at the tag of the image you run, for example
`github.com/adaqus/voidwall/tree/v0.5.0/docs`.

## Reference

- [HTTP API](api-reference.md): the `/v1/scan` route and the LiteLLM route. The contract
  is in [openapi.json](openapi.json).
- [Configuration](configuration.md): check a config file with `voidwall --validate`
  before you start the proxy.

## Guards

- [Regex PII guard](guards/pii-regex.md): add your own PII rules.
- [Model guards](guards/model-guards.md): run an ONNX model as a guard.
- [Hidden context guard](guards/hidden-context.md): block a response that repeats a
  canary or other marker.

## For contributors

[dev/](dev/) holds the backlog, the TODO list, and the load-test design. To build from
source, see [DEVELOPMENT.md](../DEVELOPMENT.md).

More topics come later.
