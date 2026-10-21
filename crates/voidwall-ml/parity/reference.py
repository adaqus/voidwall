"""Writes the parity reference for one `text_classifier` or `token_classifier` model.

The reference is a second, independent implementation of what a Voidwall worker does
with a unit: tokenize with the model's `tokenizer.json` (Python `tokenizers`, the same
core as Rust, truncation and padding off), cut the tokens into overlapping windows, add
the special tokens to each window, and run the PyTorch model on each window.

- `text_classifier`: score each window as softmax[1], and take the highest window score.
- `token_classifier`: pool each token's softmax per entity type, then decode spans with
  the Python copy of the decoder below. A blank unit runs no window.

No transformers tokenizer runs: transformers 5 rebuilds some tokenizers and drops the
normalizer in `tokenizer.json`. transformers is used for the model forward pass only,
fed the token IDs from `tokenizers`.

Usage (see README.md):

    python -I reference.py --model-dir <hf dir> --tokenizer <tokenizer.json> \
        --max-tokens 512 --overlap 128 --texts texts.jsonl --out reference.json
    python -I reference.py --adapter token_classifier --model-dir <hf dir> \
        --tokenizer <tokenizer.json> --max-tokens 512 --overlap 128 --out reference.json
"""

import argparse
import json
import math
import pathlib
import re

import numpy as np
import torch
from tokenizers import Tokenizer
from transformers import AutoModelForSequenceClassification, AutoModelForTokenClassification

HERE = pathlib.Path(__file__).parent
DEFAULT_TEXTS = {
    "text_classifier": HERE / "texts.jsonl",
    "token_classifier": HERE / "token-texts.jsonl",
}


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


def window_encoding(tokenizer, text, start, end):
    """Tokens [start, end) of `text` as one encoding, special tokens added."""
    encoding = tokenizer.encode(text, add_special_tokens=False)
    encoding.truncate(end, direction="right")
    encoding.truncate(end - start, direction="left")
    return tokenizer.post_process(encoding, None, True)


def window_ids(tokenizer, text, start, end):
    """The token IDs of tokens [start, end) of `text`, special tokens added."""
    return window_encoding(tokenizer, text, start, end).ids


# The decoder of a token classifier: a copy of `BardsDecoder.predict` (with
# `upstream=False`) and `vw_trim` from voidwall-internal/research/pii-model/scripts/vw.py,
# which ports steps 1-5 of bards.ai's `pii_detector.py`. It is the executable
# specification of crates/voidwall-ml/src/decode.rs: change the two together.
# Three changes from vw.py: the records come in as arguments; a label with no
# B-/I-/S- prefix is a type of its own name (vw.py assumed a prefix); and whitespace
# is the Unicode White_Space property, as Rust's `char::is_whitespace` has it, not
# Python's `str.isspace` and `\s`, which add U+001C to U+001F.

WHITESPACE = (
    "\t\n\v\f\r \x85\xa0\u1680\u2000\u2001\u2002\u2003\u2004\u2005\u2006"
    "\u2007\u2008\u2009\u200a\u2028\u2029\u202f\u205f\u3000"
)
WORD = re.compile('[^' + re.escape(WHITESPACE) + r',;|"<>()\[\]{}*^]+')
WORD_LEAD = "([{<\"'«„"
WORD_TRAIL = ")]}>\"'».,;:!?"
TRIM_BOTH = set(",.;:!?\"'“”‘’«»„")
TRIM_TRAIL_ONLY = set(")]}")


def vw_trim(text, s, e):
    while s < e and (text[s] in WHITESPACE or text[s] in TRIM_BOTH):
        s += 1
    while e > s and (text[e - 1] in WHITESPACE or text[e - 1] in TRIM_BOTH
                     or text[e - 1] in TRIM_TRAIL_ONLY):
        e -= 1
    return s, e


def label_type(label):
    """The type of a label that is not `O`, and whether it starts an entity."""
    for prefix, starts in (("B-", True), ("S-", True), ("I-", False)):
        if label.startswith(prefix):
            return label[len(prefix):], starts
    return label, False


class Pooling:
    """Sums each label's softmax into its type's slot: the types sorted, then `O`."""

    def __init__(self, id2label):
        n_labels = len(id2label)
        self.types = sorted({label_type(lab)[0] for lab in id2label.values() if lab != "O"})
        index = {t: i for i, t in enumerate(self.types)}
        self.o = len(self.types)
        self.pool = np.zeros((n_labels, self.o + 1), dtype=np.float32)
        self.is_b = np.zeros(n_labels, dtype=np.float32)
        for i, lab in id2label.items():
            if lab == "O":
                self.pool[i, self.o] = 1
            else:
                ty, starts = label_type(lab)
                self.pool[i, index[ty]] = 1
                self.is_b[i] = 1.0 if starts else 0.0


def softmax(x):
    x = x - x.max(-1, keepdims=True)
    e = np.exp(x)
    return e / e.sum(-1, keepdims=True)


def char_probs(text, records, slots):
    """Each record's pooled probabilities, summed at its token's first non-space
    character. `records` are (char start, char end, pooled, start probability)."""
    n = len(text)
    acc = np.zeros((n, slots), dtype=np.float32)
    cnt = np.zeros(n, dtype=np.float32)
    bmass = np.zeros(n, dtype=np.float32)
    for s, e, pt, pb in records:
        if e <= s:
            continue
        while s < e - 1 and text[s] in WHITESPACE:
            s += 1
        acc[s] += pt
        cnt[s] += 1
        bmass[s] += pb
    return acc, cnt, bmass


def decode(text, records, pooling):
    """[(start, end, type, confidence)] in character offsets. Confidence is the mean
    over the merged words of each word's winning pooled probability."""
    if not text.strip(WHITESPACE):
        return []
    acc, cnt, bmass = char_probs(text, records, pooling.o + 1)
    spans = []
    for m in WORD.finditer(text):
        ws, we = m.span()
        while ws < we and text[ws] in WORD_LEAD:
            ws += 1
        while we > ws and text[we - 1] in WORD_TRAIL:
            we -= 1
        if we <= ws:
            continue
        sel = cnt[ws:we] > 0
        if not sel.any():
            continue
        v = acc[ws:we][sel].sum(0) / cnt[ws:we][sel].sum()
        k = int(v.argmax())
        if k == pooling.o:
            continue
        first = ws + int(np.flatnonzero(sel)[0])
        start_b = bmass[first] / max(cnt[first], 1)
        t = pooling.types[k]
        gap = text[spans[-1][1]:ws] if spans else ""
        if (spans and spans[-1][2] == t and gap.strip(" ,-/.()") == ""
                and "\n\n" not in gap and start_b < 0.5):
            spans[-1][1] = we
            spans[-1][3].append(float(v[k]))
        else:
            spans.append([ws, we, t, [float(v[k])]])
    out = []
    for s, e, t, conf in spans:
        s, e = vw_trim(text, s, e)
        if e > s:
            out.append((s, e, t, sum(conf) / len(conf)))
    return out


def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument(
        "--adapter", choices=sorted(DEFAULT_TEXTS), default="text_classifier",
        help="the adapter the guard runs the model with",
    )
    parser.add_argument("--model-dir", required=True, help="Hugging Face model directory")
    parser.add_argument("--tokenizer", required=True, help="the model's tokenizer.json")
    parser.add_argument("--max-tokens", type=int, required=True)
    parser.add_argument("--overlap", type=int, required=True)
    parser.add_argument("--texts", help="the text set (default: the adapter's set beside this script)")
    parser.add_argument("--out", required=True)
    parser.add_argument(
        "--trust-remote-code",
        action="store_true",
        help="run the model class shipped in the model directory (PIGuard needs it)",
    )
    args = parser.parse_args()
    texts = args.texts or DEFAULT_TEXTS[args.adapter]

    torch.set_grad_enabled(False)
    tokenizer = Tokenizer.from_file(str(args.tokenizer))
    tokenizer.no_truncation()
    tokenizer.no_padding()

    window = args.max_tokens - tokenizer.num_special_tokens_to_add(False)
    stride = window - args.overlap
    assert stride > 0, "the window must be longer than the overlap"

    run = token_units if args.adapter == "token_classifier" else text_units
    reference = {
        "adapter": args.adapter,
        "max_tokens": args.max_tokens,
        "overlap": args.overlap,
        "units": run(args, tokenizer, texts, window, stride),
    }
    pathlib.Path(args.out).write_text(json.dumps(reference), encoding="utf-8")


def token_units(args, tokenizer, texts, window, stride):
    model = AutoModelForTokenClassification.from_pretrained(
        args.model_dir, dtype=torch.float32, trust_remote_code=args.trust_remote_code
    ).eval()
    id2label = {int(k): v for k, v in model.config.id2label.items()}
    pooling = Pooling(id2label)

    units = []
    for unit_id, text, _ in unit_texts(texts):
        n = len(tokenizer.encode(text, add_special_tokens=False).ids)
        windows, records = [], []
        for start in window_starts(n, window, stride):
            encoding = window_encoding(tokenizer, text, start, min(start + window, n))
            windows.append(encoding.ids)
            if not text.strip(WHITESPACE):
                continue  # a blank unit runs no inference
            input_ids = torch.tensor([encoding.ids], dtype=torch.long)
            mask = torch.ones_like(input_ids)
            logits = model(input_ids=input_ids, attention_mask=mask).logits[0].float().numpy()
            assert logits.shape == (len(encoding.ids), len(id2label)), (
                f"{unit_id}: logits of shape {logits.shape}"
            )
            assert np.isfinite(logits).all(), f"{unit_id}: non-finite"
            p = softmax(logits)
            pooled, bmass = p @ pooling.pool, p @ pooling.is_b
            for j, ((s, e), special) in enumerate(
                zip(encoding.offsets, encoding.special_tokens_mask)
            ):
                if not special:
                    records.append((s, e, pooled[j], float(bmass[j])))
        spans = decode(text, records, pooling)
        units.append(
            {
                "id": unit_id,
                "text": text,
                "windows": windows,
                "records": [
                    {"chars": [s, e], "pooled": pt.tolist(), "start": pb}
                    for s, e, pt, pb in records
                ],
                "spans": [
                    {"chars": [s, e], "type": t, "confidence": c} for s, e, t, c in spans
                ],
            }
        )
        found = ", ".join(t for _, _, t, _ in spans) or "none"
        print(f"{unit_id}: {n} tokens, {len(windows)} windows, spans: {found}")
    return units


def text_units(args, tokenizer, texts, window, stride):
    model = AutoModelForSequenceClassification.from_pretrained(
        args.model_dir, dtype=torch.float32, trust_remote_code=args.trust_remote_code
    ).eval()

    units = []
    for unit_id, text, known_attack in unit_texts(texts):
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
    return units


if __name__ == "__main__":
    main()
