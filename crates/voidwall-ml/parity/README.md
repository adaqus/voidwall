# Model parity

This harness checks that a Voidwall worker reads a model's output the way the
model's own Python stack does. Run it for every change to an adapter, the
windows, the tokenizer handling, or the `token_classifier` decoder, and for
every new model a guard is meant to run. CI cannot run it: it needs model files,
and the repository never holds model files.

| Piece | Does |
|---|---|
| `texts.jsonl` | The `text_classifier` text set: benign prompts, a known attack (`known_attack: true`), empty and non-ASCII text, and units of 2 to 5 windows with an attack line at several offsets. A line holds `text`, or `parts`: `[text, times]` pairs joined in order |
| `token-texts.jsonl` | The `token_classifier` text set, in the same format, with placeholder values only: every label of the default PII guard, units of several windows, non-ASCII text, and values with punctuation at their edges. A line must JSON-escape U+0085, U+001C to U+001E, and U+2028, because the script splits the file on every line break Python knows |
| `reference.py` | Tokenizes with Python `tokenizers` (truncation and padding off), cuts the same windows as the worker with its own code, runs the PyTorch model on each window, and writes `reference.json`. With `--adapter token_classifier` it pools each token's probabilities per type and decodes spans with a Python copy of the decoder, the executable specification of `src/decode.rs` |
| `src/parity.rs` | The ignored Rust test. It loads one worker per model and compares |

A `text_classifier` model passes when:

- every window's token IDs equal the reference's
- every unit score is within 1e-4 of the reference
- no unit score is on the other side of 0.5 from the reference
- the known attack scores at least 0.9

A `token_classifier` model passes when:

- every window's token IDs equal the reference's
- every token covers the same bytes as the reference's, whose character offsets the
  test turns into byte offsets
- every pooled probability, start probability, and span confidence is within 2e-4 of
  the reference. This is wider than 1e-4, because the fp32 ONNX export of the PII model
  alone differs from PyTorch 2.14 by up to 1.41e-4
- the spans and their types equal the reference's

The token test runs the fp32 ONNX export. The INT8 file the dev stack runs is not
compared with Python: the ONNX Runtime build Voidwall links and the Python wheel of the
same version round some fp32 operations apart, and dynamic quantization turns that into
whole quantization steps. On the text set, pooled probabilities differ by up to 0.276 and
1 of 78 spans differs. The cause is in `voidwall-internal/research/pii-model/int8-gap.md`.

Instead, a `token_classifier` directory that also holds `model_quantized.onnx` gets the
INT8 check (`quantized_logits_match_a_plain_session`). Every window of the text set runs
through an INT8 worker and through a plain ONNX Runtime session of the same file, with the
worker's session options and no shared or prepacked weights. The logits must be
bit-identical. This checks what the load adds: the staged graph, the shared weights, and
the prepacked weights.

## Run

For the two models the dev stack runs, one command does every step below with pinned
model files and new references:

```bash
docker/ctl parity
```

| Model | Adapter | Default window and overlap |
|---|---|---|
| wolf-small | `text_classifier` | 2048 and 64 |
| bards v2 (`bardsai/eu-pii-anonimization-multilang-v2`) | `token_classifier` | 512 and 128 |

`docker/ctl parity` also runs the INT8 check on the bards v2 INT8 file from
`docker/fetch-models.sh`. The defaults are the values in `docker/voidwall.toml`. `PARITY_MAX_TOKENS` and
`PARITY_OVERLAP` change the window and the overlap of both models. Each run deletes
`.cache/parity/run/` and makes it again with these two models only, so do not keep
other models there. See `DEVELOPMENT.md`.

For any other model, such as PIGuard, do the steps by hand:

1. Make a Python environment with `requirements.txt`.
2. Lay out one directory per model. `model.onnx` is the fp32 ONNX export, and
   `tokenizer.json` is the file the guard will use. A `token_classifier` model also
   needs its `config.json`:

   ```text
   $VOIDWALL_PARITY_DIR/
   ├── wolf/     model.onnx  tokenizer.json
   ├── piguard/  model.onnx  tokenizer.json
   └── pii/      model.onnx  tokenizer.json  config.json  [model_quantized.onnx]
   ```

   `model_quantized.onnx` is optional; with it the directory also gets the INT8 check.

3. Write each reference from the model's Hugging Face directory. Use the
   `max_tokens` and overlap the guard will run with:

   ```bash
   cd crates/voidwall-ml/parity
   python -I reference.py --model-dir <hf>/wolf --tokenizer "$VOIDWALL_PARITY_DIR/wolf/tokenizer.json" \
       --max-tokens 512 --overlap 128 --out "$VOIDWALL_PARITY_DIR/wolf/reference.json"
   python -I reference.py --model-dir <hf>/piguard --trust-remote-code \
       --tokenizer "$VOIDWALL_PARITY_DIR/piguard/tokenizer.json" \
       --max-tokens 512 --overlap 128 --out "$VOIDWALL_PARITY_DIR/piguard/reference.json"
   python -I reference.py --adapter token_classifier --model-dir <hf>/pii \
       --tokenizer "$VOIDWALL_PARITY_DIR/pii/tokenizer.json" \
       --max-tokens 512 --overlap 128 --out "$VOIDWALL_PARITY_DIR/pii/reference.json"
   ```

   `--trust-remote-code` runs the model class shipped in the model directory.
   PIGuard needs it (29 lines: a DeBERTa-v3 backbone, the first token, one linear
   layer). Read that code before you pass the flag for any model.

4. Run the test from the workspace root:

   ```bash
   VOIDWALL_PARITY_DIR=<dir> cargo test -p voidwall-ml --release -- --ignored parity --nocapture
   ```

   Without `VOIDWALL_PARITY_DIR` the tests fail; they never pass without checking.
   The parity test checks every directory under it that holds a `reference.json`, and
   reads the adapter from the reference. The INT8 check takes each directory that also
   holds `model_quantized.onnx`, and fails when there is none. With no INT8 file, run
   the parity test alone: `-- --ignored parity::scores_match_the_python_reference`.

## Class order

The ONNX file does not say which class is the attack. `text_classifier` scores
class 1. A model with the classes the other way round passes every load check
and scores attacks low. The known attack line catches that here.
