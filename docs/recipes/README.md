# Recipes

A recipe puts Voidwall between an app and a model. Choose the recipe of your model
server or gateway:

| Recipe | How Voidwall runs | Model |
|---|---|---|
| [LM Studio](lm-studio.md) | As a reverse proxy in front of LM Studio | A model that LM Studio serves |
| [Ollama](ollama.md) | As a reverse proxy in front of Ollama | A model that Ollama serves |
| [AnythingLLM](anythingllm.md) | As a reverse proxy between AnythingLLM and LM Studio, Ollama, or a hosted provider | A local server, or a hosted model such as OpenAI |
| [LiteLLM](litellm.md) | As a LiteLLM guardrail, on the HTTP API | Any model that LiteLLM serves, hosted models too |

The reverse proxy reaches `https://` upstreams, such as OpenAI. See
[HTTPS upstreams](../configuration.md#https-upstreams), and
[A hosted model](anythingllm.md#a-hosted-model) in the AnythingLLM recipe.

The sections below apply to each recipe that runs Voidwall as a reverse proxy: LM Studio,
Ollama, and AnythingLLM. Their examples use the LM Studio port, `1234`. For Ollama, use
`11434`.

## Documents and embeddings

The generic route scans `/v1/embeddings` too. So a document that holds personal data
cannot be embedded through Voidwall: the request gets 403, for example
`{"error":"content blocked","kinds":["EMAIL","PERSON_NAME"]}`.

Also, when an app puts a part of a document into a prompt, the chat route scans that
part. A question about a document that holds personal data is then blocked, also when the
question itself is clean.

## Keep personal data on a local model

When the model runs on your own machine, personal data in a prompt does not leave it. You
can then run only the prompt injection guard on the chat route, and no guard on
embeddings. Add `guards` to the chat route, and add an embeddings route, in the block of
your server. For example, in the `lmstudio` block:

```toml
[[reverse_proxy.routes]]
path_prefix = "/v1/chat/completions"
upstream = "http://host.docker.internal:1234"
format = "openai-chat"
guards = ["prompt_injection"]

[[reverse_proxy.routes]]
path_prefix = "/v1/embeddings"
upstream = "http://host.docker.internal:1234"
guards = []

[[reverse_proxy.routes]]
path_prefix = "/"
upstream = "http://host.docker.internal:1234"
```

With this config, a question about a document with personal data gets its answer, a
document with personal data can be embedded, and a prompt injection is still blocked.
`guards = []` forwards that route without any inspection.

## Streaming

On a route with `format = "openai-chat"`, Voidwall scans a streamed answer
(`text/event-stream`) while it runs. The route's `stream` key sets the mode:

- `"holdback"`, the default: events reach the client while the stream runs, but the
  newest `stream_holdback_bytes` of text wait until a scan clears them. A detection
  before the first byte answers the usual 400. After the first byte, Voidwall sends one
  `data:` event with the same error body and closes the stream, with no `data: [DONE]`.
- `"buffer"`: Voidwall reads the whole stream, scans it once, and then sends it unchanged
  or answers 400.

On a generic route, a stream is not scanned. See
[../configuration.md](../configuration.md#reverse_proxyroutes) for the stream keys.

## Retries

OpenAI clients retry 500, 502, and 504 by default. So under `fail_close`, a guard failure
can reach Voidwall up to three times. A 400 or a 422 is not retried.
