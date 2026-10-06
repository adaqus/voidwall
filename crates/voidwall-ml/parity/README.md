# `text_classifier` parity

This harness checks that a Voidwall worker scores text the way the model's own
Python stack does. Run it for every change to the adapter, the windows, or the
tokenizer handling, and for every new model a `text_classifier` guard is meant
to run. CI cannot run it: it needs model files, and the repository never holds
model files.

| Piece | Does |
|---|---|
| `texts.jsonl` | The text set: benign prompts, a known attack (`known_attack: true`), empty and non-ASCII text, and units of 2 to 5 windows with an attack line at several offsets. A line holds `text`, or `parts`: `[text, times]` pairs joined in order |
| `reference.py` | Tokenizes with Python `tokenizers` (truncation and padding off), cuts the same windows as the worker with its own code, runs the PyTorch model on each window, and writes `reference.json` |
| `src/parity.rs` | The ignored Rust test. It loads one worker per model and compares |

The test passes when, for every model:

- every window's token IDs equal the reference's
- every unit score is within 1e-4 of the reference
- no unit score is on the other side of 0.5 from the reference
- the known attack scores at least 0.9

## Run

1. Make a Python environment with `requirements.txt`.
2. Lay out one directory per model. `model.onnx` is the fp32 ONNX export, and
   `tokenizer.json` is the file the guard will use:

   ```text
   $VOIDWALL_PARITY_DIR/
   ├── wolf/     model.onnx  tokenizer.json
   └── piguard/  model.onnx  tokenizer.json
   ```

3. Write each reference from the model's Hugging Face directory. Use the
   `max_tokens` and overlap the guard will run with:

   ```bash
   cd crates/voidwall-ml/parity
   python -I reference.py --model-dir <hf>/wolf --tokenizer "$VOIDWALL_PARITY_DIR/wolf/tokenizer.json" \
       --max-tokens 512 --overlap 128 --out "$VOIDWALL_PARITY_DIR/wolf/reference.json"
   python -I reference.py --model-dir <hf>/piguard --trust-remote-code \
       --tokenizer "$VOIDWALL_PARITY_DIR/piguard/tokenizer.json" \
       --max-tokens 512 --overlap 128 --out "$VOIDWALL_PARITY_DIR/piguard/reference.json"
   ```

   `--trust-remote-code` runs the model class shipped in the model directory.
   PIGuard needs it (29 lines: a DeBERTa-v3 backbone, the first token, one linear
   layer). Read that code before you pass the flag for any model.

4. Run the test from the workspace root:

   ```bash
   VOIDWALL_PARITY_DIR=<dir> cargo test -p voidwall-ml --release -- --ignored parity --nocapture
   ```

   Without `VOIDWALL_PARITY_DIR` the test fails; it never passes without checking.

## Class order

The ONNX file does not say which class is the attack. `text_classifier` scores
class 1. A model with the classes the other way round passes every load check
and scores attacks low. The known attack line catches that here.
