# Add Your Own Guard

You can add a guard with no code change and no rebuild: a model guard runs an ONNX model
that you supply. You mount the model into the container and declare the guard in the
config file.

A detector that is not a model, such as a new kind of rule, is a code change. See
[Write a guard in Rust](#write-a-guard-in-rust).

## Check the model

A model guard runs a model through an adapter. The model must fit one of them:

| Adapter | Use it for | The model must have |
|---|---|---|
| `text_classifier` | A verdict on the whole text, such as "prompt injection" | One `Float32` output of shape `[1, 2]`. Class 1 is the class the guard reports. |
| `token_classifier` | Spans in the text, such as names or addresses | One `Float32` output of shape `[1, tokens, labels]`, and a `config.json` with an `id2label` map |

Both adapters also need:

- The model as one ONNX file, with the inputs `input_ids` and `attention_mask`.
  `token_type_ids` is optional.
- The Hugging Face tokenizer of the model, as `tokenizer.json`.

The full contract is in [model-guards.md](model-guards.md#adapters). A model that does not
fit stops the start, and the message names the guard.

## Steps

The example adds a `text_classifier` guard named `my_classifier`. Its files are in
`./models/my-classifier/` on the host:

```
models/my-classifier/model.onnx
models/my-classifier/tokenizer.json
```

1. Copy the config file out of the image:

   ```bash
   docker run --rm ghcr.io/adaqus/voidwall --print-config > voidwall.toml
   ```

2. Add the guard at the end of `voidwall.toml`. The paths are paths in the container:

   ```toml
   [guards.my_classifier]
   adapter = "text_classifier"
   model_path = "/models/my-classifier/model.onnx"
   tokenizer_path = "/models/my-classifier/tokenizer.json"
   max_tokens = 512
   labels = ["MY_KIND"]

   [guards.my_classifier.thresholds]
   MY_KIND = 0.9
   ```

   `labels` names the kind that a finding reports. A label with no threshold reports
   nothing. Every key is in [configuration.md](../configuration.md#model-guards-guardsname).

3. Check the file. Mount the models, so that the check finds each file:

   ```bash
   docker run --rm -v "$PWD/voidwall.toml:/etc/voidwall/voidwall.toml:ro" \
       -v "$PWD/models:/models:ro" \
       ghcr.io/adaqus/voidwall --validate /etc/voidwall/voidwall.toml
   ```

   It prints `config OK: /etc/voidwall/voidwall.toml`. The check does not load the model.

4. Start Voidwall with the same mounts:

   ```bash
   docker run --rm -p 8083:8083 -p 9090:9090 \
       -v "$PWD/voidwall.toml:/etc/voidwall/voidwall.toml:ro" \
       -v "$PWD/models:/models:ro" ghcr.io/adaqus/voidwall
   ```

5. Wait until `curl -s -o /dev/null -w '%{http_code}\n' localhost:9090/readyz` prints
   `200`. Then send a test text:

   ```bash
   curl -s localhost:8083/v1/scan -H 'content-type: text/plain' -d '<a text your model flags>'
   ```

   A finding of your guard is in `guards`, with `"name":"my_classifier"` and
   `"kinds":["MY_KIND"]`.

6. Set the threshold. Send texts that the guard must flag and texts that it must not
   flag, and choose the threshold that separates them best. A guard blocks every message
   that it flags, so a low threshold blocks clean traffic.

With Docker Compose, mount the same two paths as volumes.

## Write a guard in Rust

A guard in Rust is one type with a name, an interest, and a `detect` function that returns
findings. It is a change to Voidwall, and it ships in the binary. Read
[ARCHITECTURE.md](../../ARCHITECTURE.md) and [CONTRIBUTING.md](../../CONTRIBUTING.md)
first. A pull request never adds model files to the image.
