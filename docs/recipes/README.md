# Recipes

| Recipe | How Voidwall runs | Model |
|---|---|---|
| [LiteLLM](litellm.md) | As a LiteLLM guardrail, on the HTTP API | Any model that LiteLLM serves, hosted models too |
| [AnythingLLM](anythingllm.md) | As a reverse proxy in front of the model server | A local server on plain HTTP |
| [Ollama](ollama.md) | As a reverse proxy in front of Ollama | A model that Ollama serves |

> **The reverse proxy reaches plain-HTTP upstreams only.** It does not originate TLS
> yet. An `https://` upstream, such as OpenAI, Azure OpenAI, or OpenRouter, passes
> validation and then fails with 502. To guard a hosted model, use the
> [LiteLLM recipe](litellm.md).

## Put Voidwall in front of LM Studio

The AnythingLLM recipe starts with these steps. Any app that calls an OpenAI-compatible
API can use them. They were tested with Voidwall 0.5.0 and LM Studio 0.4.28 on Linux.

```
app ──► Voidwall :8082 ──► LM Studio :1234
```

### 1. Let containers reach LM Studio

Voidwall runs in a container, and reaches LM Studio on the host at
`host.docker.internal`. By default, LM Studio listens only on `127.0.0.1`, and a
container cannot reach that address. Start the server on the address of the Docker
bridge, `172.17.0.1` by default:

```bash
lms server start --bind 172.17.0.1 --port 1234
```

Containers can reach this address, and other hosts on your network cannot. To find the
address, run `docker network inspect bridge --format '{{(index .IPAM.Config 0).Gateway}}'`.
"Serve on Local Network" in LM Studio also works, but it opens the server to your whole
network.

Load the model that the app will use, for example `lms load google/gemma-3-1b`.

### 2. Make a config file

Copy the config out of the image:

```bash
docker run --rm ghcr.io/adaqus/voidwall --print-config > voidwall.toml
```

In `voidwall.toml`:

1. Under `[reverse_proxy]`, set `enabled = true`.
2. Uncomment the lines between `# >>> lmstudio` and `# <<< lmstudio`: remove the `# ` in
   front of each line.

The block holds two routes:

```toml
[[reverse_proxy.routes]]
path_prefix = "/v1/chat/completions"
upstream = "http://host.docker.internal:1234"
format = "openai-chat"

[[reverse_proxy.routes]]
path_prefix = "/"
upstream = "http://host.docker.internal:1234"
```

The first route decodes Chat Completions message by message, and answers a block in the
OpenAI error shape, so an OpenAI client shows its usual error. The second route sends
every other path, such as `/v1/models` and `/v1/embeddings`, through the generic route.
Do not put `format = "openai-chat"` on a broad prefix such as `/v1`: every call there
that is not Chat Completions would then answer 400.

Check the file:

```bash
docker run --rm -v "$PWD/voidwall.toml:/etc/voidwall/voidwall.toml:ro" \
    ghcr.io/adaqus/voidwall --validate /etc/voidwall/voidwall.toml
```

### 3. Start Voidwall

```bash
docker network create guardrails
docker run -d --name voidwall --network guardrails \
    --add-host=host.docker.internal:host-gateway \
    -p 127.0.0.1:8082:8082 -p 127.0.0.1:9090:9090 \
    -v "$PWD/voidwall.toml:/etc/voidwall/voidwall.toml:ro" ghcr.io/adaqus/voidwall
```

Wait until `curl -s -o /dev/null -w '%{http_code}\n' localhost:9090/readyz` prints
`200`. A container on the `guardrails` network reaches Voidwall at
`http://voidwall:8082/v1`. An app on the host reaches it at `http://localhost:8082/v1`.

### 4. Test it

```bash
curl -s localhost:8082/v1/chat/completions -H 'content-type: application/json' -d '{
  "model": "google/gemma-3-1b",
  "messages": [{"role": "user", "content": "My e-mail is anna.smith@example.com."}]
}'
```

Voidwall answers 400 and does not send the message to LM Studio:

```json
{"error":{"message":"content blocked. Kinds: EMAIL","type":"invalid_request_error","param":null,"code":"content_filter","kinds":["EMAIL"]}}
```

A clean message gets the model's answer, unchanged. A `502` with `upstream error` means
that Voidwall cannot reach LM Studio: check step 1.

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
