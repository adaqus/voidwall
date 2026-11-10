# OWASP Top 10 for LLM Applications (2026)

This page compares Voidwall with the
[OWASP Top 10 for LLM Applications 2026](https://genai.owasp.org/resource/owasp-genai-llm-top-10-2026/).
Voidwall is not affiliated with or endorsed by OWASP.

## Summary

| Risk | Name | Coverage |
|---|---|---|
| LLM01 | Prompt Injection | Direct |
| LLM02 | Sensitive Information Disclosure | Direct |
| LLM03 | Excessive Agency | Other layer |
| LLM04 | Supply Chain | Other layer |
| LLM05 | Data and Model Poisoning | Other layer |
| LLM06 | Unbounded Consumption | Partly |
| LLM07 | Misinformation | Not covered |
| LLM08 | Hidden Context Exposure | Partly |
| LLM09 | Vector and Embedding Weaknesses | Other layer |
| LLM10 | Improper Output Handling | Not covered |

The levels:

- **Direct**: Voidwall finds the risk in traffic and blocks it.
- **Partly**: Voidwall stops part of the risk. Other controls must stop the rest.
- **Not covered**: a guardrail could address the risk, but Voidwall does not.
- **Other layer**: the risk is outside the traffic that a guardrail sees. Another part of
  your stack must control it.

## Why some risks need another layer

A guardrail sees one thing: the text of each request and each response that passes
through it. It does not see the training data, the model files, the tools that an agent
may call, or the vector database. A risk that lives in one of those places cannot be
found in the traffic. It must be controlled where it lives.

So Voidwall is one layer of defense. It does not replace limits on what the model and its
tools may do, checks of the models and data before deployment, or access control in the
data stores.

## The risks

### LLM01 Prompt Injection: Direct

Text can carry instructions that take control of the model: in user input, in a
document, in tool output, or in a tool description. A classifier model scans this text
and blocks a message that holds hidden instructions, before it reaches the model.

- It scans text only. Images, audio, and other binary content are not scanned.
- A classifier can miss an attack, and it can flag clean text. Choose its threshold for
  your traffic. See [guards/model-guards.md](guards/model-guards.md).
- An injection that passes can still make the model misuse its tools. Limit the tools
  and permissions of the model too (see LLM03).

### LLM02 Sensitive Information Disclosure: Direct

Personal data and secrets can leak to a third-party model provider in a prompt, or leak
to a user in a response. Regex rules and a token classification model find personal data
and secrets, such as cloud keys and access tokens. They scan requests and responses, tool
calls too, and block the message. See [guards/pii-regex.md](guards/pii-regex.md).

- A value with no fixed shape, such as a name, is found by a model, and a model can miss
  a value.
- Voidwall blocks the message. It does not redact the value and send the rest.

### LLM03 Excessive Agency: Other layer

An agent can do harm when it has more tools, permissions, or autonomy than its task
needs. Voidwall does not control the tools or permissions of an agent. The agent
framework or the gateway that grants them must limit them: give each tool the least
permission it needs, and ask a person to approve actions with a high impact.

### LLM04 Supply Chain: Other layer

A model, a dataset, or a library from a third party can be compromised. Voidwall does not
check the models or the data that your application uses. Check them before deployment,
with model scanning and the provenance of each artifact.

Voidwall's own default models are pinned to a fixed revision and checked by SHA-256
before use. The ONNX Runtime that it links is checked by hash and by build attestation.
This protects Voidwall's own supply chain. It does not check yours.

### LLM05 Data and Model Poisoning: Other layer

Poisoned training data or a backdoor in a model can change what the model does. Voidwall
does not find poisoned training data or a backdoored model. The training and data
pipeline must find them.

A RAG pipeline can call `/v1/scan` to check a document for hidden instructions before it
indexes the document. Instructions hidden in a document or in memory are covered under
LLM01.

### LLM06 Unbounded Consumption: Partly

A client can send too much work and use up resources or money. A body size limit
(`max_body_size`) stops an oversize request, and timeouts (`upstream_timeout_secs`,
`stream_idle_timeout_secs`) stop an exchange that takes too long. There is no rate
limit, no token quota, and no spending cap. Set them in a gateway in front of the model.

### LLM07 Misinformation: Not covered

A model can give an answer that is false or not supported by its sources. Voidwall does
not check whether model output is true.

### LLM08 Hidden Context Exposure: Partly

The system prompt and other hidden context can hold secrets, and a model can repeat them
to the user. Request scanning blocks a secret, such as a cloud key or an access token,
that is in the system prompt. Response scanning blocks it if it leaks. The
[hidden context guard](guards/hidden-context.md) blocks a response that repeats a canary
or other marker.

- The hidden context guard finds only a word-for-word leak. A leak in other words, in
  another language, or in an encoding such as Base64 passes.
- The image does not turn on the hidden context guard. You add markers to the config.
- Keep secrets out of the model's context. Do not rely on the prompt to hide them.

### LLM09 Vector and Embedding Weaknesses: Other layer

A vector database can return data that a user must not see, or mix the data of two
tenants. Voidwall does not inspect embeddings or similarity search. Access control and
tenant separation belong in the vector database and the RAG framework.

### LLM10 Improper Output Handling: Not covered

Model output can carry content that harms the system that uses it, such as script or
markup. Voidwall blocks messages. It does not sanitize or encode model output for
downstream systems. The application that uses the output must encode it for its context.
