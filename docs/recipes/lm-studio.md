# LM Studio

[LM Studio](https://lmstudio.ai/) runs models on your own machine. In this recipe, an app
sends its model calls to Voidwall, and Voidwall forwards them to LM Studio. A message with
a prompt injection or personal data is blocked before it reaches the model.

The [AnythingLLM recipe](anythingllm.md) starts with these steps. Any app that calls an
OpenAI-compatible API can use them.

> **Tested with** Voidwall 0.5.0 and LM Studio 0.4.28 with `google/gemma-3-1b`, on Linux.

```
app ──► Voidwall :8082 ──► LM Studio :1234
```

For a hosted model, see [A hosted model](anythingllm.md#a-hosted-model) in the
AnythingLLM recipe, or the [LiteLLM recipe](litellm.md).

## 1. Let containers reach LM Studio

Voidwall runs in a container, and reaches LM Studio on the host at
`host.docker.internal`. By default, LM Studio listens only on `127.0.0.1`, and a
container cannot reach that address. Start the server on the address of the Docker
bridge, `172.17.0.1` by default:

```bash
lms server start --bind 172.17.0.1 --port 1234
```

Containers can reach this address. Other hosts on your network do not normally reach
it. To find the address, run `docker network inspect bridge --format '{{(index .IPAM.Config 0).Gateway}}'`.
"Serve on Local Network" in LM Studio also works, but it opens the server to your whole
network.

Load the model that the app will use, for example `lms load google/gemma-3-1b`.

## 2. Make a config file

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

## 3. Start Voidwall

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

## 4. Test it

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

## More

These parts of the [recipes page](README.md) also apply to LM Studio:

- [Documents and embeddings](README.md#documents-and-embeddings)
- [Keep personal data on a local model](README.md#keep-personal-data-on-a-local-model)
- [Streaming](README.md#streaming)
- [Retries](README.md#retries)
