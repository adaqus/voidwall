"""Writes the parity reference for one `text_classifier` model.

The reference is a second, independent implementation of what a Voidwall worker does
with a unit: tokenize with the model's `tokenizer.json` (Python `tokenizers`, the same
core as Rust, truncation and padding off), cut the tokens into overlapping windows, add
the special tokens to each window, score each window as softmax[1] with the PyTorch
model, and take the highest window score.

No transformers tokenizer runs: transformers 5 rebuilds some tokenizers and drops the
normalizer in `tokenizer.json`. transformers is used for the model forward pass only,
fed the token IDs from `tokenizers`.

Usage (see README.md):

    python -I reference.py --model-dir <hf dir> --tokenizer <tokenizer.json> \
        --max-tokens 512 --overlap 128 --texts texts.jsonl --out reference.json
"""

import argparse
import json
import math
import pathlib

import torch
from tokenizers import Tokenizer
from transformers import AutoModelForSequenceClassification


def unit_texts(path):
    """The units of `texts.jsonl`. A line holds `text`, or `parts`: a list of
    `[text, times]` pairs, joined in order."""
    for line in pathlib.Path(path).read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        row = json.loads(line)
        if "parts" in row:
            text = "".join(part * times for part, times in row["parts"])
        else:
            text = row["text"]
        yield row["id"], text, bool(row.get("known_attack", False))


def window_starts(n, window, stride):
    """Start offsets of the windows of a unit of `n` tokens. Every window is
    `window` long except when the unit is shorter; the last one ends at `n`."""
    if n <= window:
        return [0]
    return list(range(0, n - window, stride)) + [n - window]


def window_ids(tokenizer, text, start, end):
    """The token IDs of tokens [start, end) of `text`, special tokens added."""
    encoding = tokenizer.encode(text, add_special_tokens=False)
    encoding.truncate(end, direction="right")
    encoding.truncate(end - start, direction="left")
    return tokenizer.post_process(encoding, None, True).ids


def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--model-dir", required=True, help="Hugging Face model directory")
    parser.add_argument("--tokenizer", required=True, help="the model's tokenizer.json")
    parser.add_argument("--max-tokens", type=int, required=True)
    parser.add_argument("--overlap", type=int, required=True)
    parser.add_argument("--texts", default=pathlib.Path(__file__).with_name("texts.jsonl"))
    parser.add_argument("--out", required=True)
    parser.add_argument(
        "--trust-remote-code",
        action="store_true",
        help="run the model class shipped in the model directory (PIGuard needs it)",
    )
    args = parser.parse_args()

    torch.set_grad_enabled(False)
    tokenizer = Tokenizer.from_file(str(args.tokenizer))
    tokenizer.no_truncation()
    tokenizer.no_padding()
    model = AutoModelForSequenceClassification.from_pretrained(
        args.model_dir, dtype=torch.float32, trust_remote_code=args.trust_remote_code
    ).eval()

    window = args.max_tokens - tokenizer.num_special_tokens_to_add(False)
    stride = window - args.overlap
    assert stride > 0, "the window must be longer than the overlap"

    units = []
    for unit_id, text, known_attack in unit_texts(args.texts):
        n = len(tokenizer.encode(text, add_special_tokens=False).ids)
        windows, scores = [], []
        for start in window_starts(n, window, stride):
            ids = window_ids(tokenizer, text, start, min(start + window, n))
            input_ids = torch.tensor([ids], dtype=torch.long)
            mask = torch.ones_like(input_ids)
            logits = model(input_ids=input_ids, attention_mask=mask).logits[0].double()
            assert logits.shape == (2,), f"{unit_id}: logits of shape {tuple(logits.shape)}"
            assert all(math.isfinite(v) for v in logits.tolist()), f"{unit_id}: non-finite"
            windows.append(ids)
            scores.append(torch.softmax(logits, dim=0)[1].item())
        units.append(
            {
                "id": unit_id,
                "text": text,
                "known_attack": known_attack,
                "windows": windows,
                "window_scores": scores,
                "score": max(scores),
            }
        )
        print(f"{unit_id}: {n} tokens, {len(windows)} windows, score {max(scores):.6f}")

    reference = {"max_tokens": args.max_tokens, "overlap": args.overlap, "units": units}
    pathlib.Path(args.out).write_text(json.dumps(reference), encoding="utf-8")


if __name__ == "__main__":
    main()
