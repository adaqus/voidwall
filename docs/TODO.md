# TODO

The order of items doesn't determine order of implementation.

- [ ] Forward proxy
- [ ] TLS
- [ ] GPU support
- [x] LiteLLM integration: `POST /beta/litellm_basic_guardrail_api` on the REST API,
  turned on or off with `http_api.litellm.enabled`; `/v1/scan` has its own switch,
  `http_api.scan.enabled`
- [ ] OpenAI and Anthropic API format support
- [ ] Streaming support (SSE)
- [ ] Verdict cache
- [ ] Distributed verdict cache
- [ ] Allowlists
- [ ] n8n node
- [ ] Configurable Graph Optimization Level for Guard
- [ ] ML PII Guard
- [ ] Documentation