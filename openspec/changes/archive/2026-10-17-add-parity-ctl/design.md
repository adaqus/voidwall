## Context

See `proposal.md` for the motivation and `specs/model-runtime/spec.md` for the
requirements.

Facts that shape the design:

- `docker/fetch-models.sh` already fetches and verifies `models/wolf-small/model.onnx` and
  `models/wolf-small/tokenizer.json` at revision
  `bcab2eff97bcabd7227849639e2d0d7a61b46c92`. It does not fetch the PyTorch files that
  `reference.py` needs.
- At that revision, Hugging Face reports these SHA-256 values. Both equal the files that
  made the current wolf-small parity reference:

  | File | Size | SHA-256 |
  |---|---|---|
  | `config.json` | 2,084 B | `b5bfba7b100b4b1aa361e8160e5593695164d81ca09b47f3b26561332b520218` |
  | `model.safetensors` | 562,583,392 B | `88574ea37b2aaff38468194c544a5918b5e160fb9ee630bb11bba0aa3f533cf9` |

- The ignored test `parity::scores_match_the_python_reference` reads every directory under
  `VOIDWALL_PARITY_DIR` that holds a `reference.json`. Each directory needs `model.onnx`,
  `tokenizer.json`, and `reference.json`. The test takes the window and the overlap from
  `reference.json`, so the runner sets them in one place: the `reference.py` call.
- `reference.py` loads a transformers tokenizer never. It loads the model with
  `AutoModelForSequenceClassification.from_pretrained(--model-dir)` and the tokenizer from
  `--tokenizer`.
- `docker/ctl piimb-eval` already has a Python version check, a venv under `.cache/`, and
  a marker file that records the pins the venv holds. `.cache/` is gitignored.

## Goals / Non-Goals

**Goals:**

- One command that a developer can run before a merge of a `parity/requirements.txt` bump.
- The inputs are fixed by pins, so a wrong local directory cannot give a false result.

**Non-Goals:**

- CI. The check needs about 1.1 GB of model files, and the repository holds no model file.
- A GPU run. The reference runs on CPU.

## Decisions

### Directory layout under `.cache/parity/`

```text
.cache/parity/
├── venv/                      Python environment, with .voidwall-pins marker
├── hf/wolf-small/             --model-dir for reference.py
│   ├── config.json            fetched, SHA-256 pinned
│   └── model.safetensors      fetched, SHA-256 pinned
└── run/                       VOIDWALL_PARITY_DIR
    └── wolf-small/
        ├── model.onnx      -> ../../../../models/wolf-small/model.onnx
        ├── tokenizer.json  -> ../../../../models/wolf-small/tokenizer.json
        └── reference.json     written on every run
```

`model.onnx` and `tokenizer.json` are symbolic links to the files that `fetch-models.sh`
verified, so the runner does not copy 563 MB and checks the same files the dev stack runs.

*Alternative:* copy the two files into `run/` — rejected: a second 563 MB copy, and a copy
can go out of date when `fetch-models.sh` changes its pins.

### Fetch the PyTorch files in `docker/ctl`, not in `fetch-models.sh`

A small download-and-verify function in `docker/ctl` fetches the two files. It skips a file
whose SHA-256 already equals its pin. It downloads to a temporary name and renames the file
only after the hash matches, as `fetch-models.sh` does.

*Alternative:* add the two files to `fetch-models.sh` — rejected: `docker/ctl start` runs
`fetch-models.sh`, and the dev stack would then download 560 MB it never uses. A shared
fetch helper for both scripts would change `fetch-models.sh`, which the proposal leaves
unchanged.

### A new reference on every run, with no stale file

The runner deletes `run/wolf-small/reference.json` before it runs `reference.py`.
`reference.py` writes to `reference.json.part`, and the runner renames it after
`reference.py` exits with status zero. If `reference.py` fails, no `reference.json` exists,
the script stops (`set -e`), and the parity test does not run.

### torch from the CPU wheel index, in two pip steps

1. `pip install --index-url https://download.pytorch.org/whl/cpu torch==<pin>`, with the
   `torch` pin read from `requirements.txt`.
2. `pip install -r crates/voidwall-ml/parity/requirements.txt` from PyPI. The installed
   `torch 2.13.0+cpu` satisfies `torch==2.13.0` (PEP 440 ignores the local label for `==`),
   so pip keeps it.

*Alternative:* one call with `--extra-index-url` — rejected: pip then picks between two
indexes by version rules, and a later release can make it fetch the CUDA build from PyPI
(more than 2 GB).

### The venv marker is the content of `requirements.txt`

The marker `.cache/parity/venv/.voidwall-pins` holds the content of `requirements.txt` and
the CPU index URL. When the marker differs, the runner deletes the venv and makes it again.
This is the `piimb-eval` pattern, with the file content in place of an inline pin string.

### Window settings

`PARITY_MAX_TOKENS` (default 2048) and `PARITY_OVERLAP` (default 64) go to
`reference.py --max-tokens` and `--overlap`. The runner does not validate them:
`reference.py` already rejects a value that is not an integer (`argparse`) and an overlap
that leaves no stride (its `assert`), with a non-zero exit status.

### Python version check

The same check and messages as `piimb-eval`: no `python3`, or `python3` older than 3.11,
stops the run with status 2. A host without the `venv` module gets the same message as in
`piimb-eval`.

### The Rust test

`VOIDWALL_PARITY_DIR=.cache/parity/run cargo test -p voidwall-ml --release -- --ignored
parity --nocapture`. Its exit status is the exit status of the command.

## Risks / Trade-offs

- [`from_pretrained` may need a file other than `config.json` and `model.safetensors`] →
  The first implementation task runs `reference.py` on a directory with these two files
  only, and compares the result with the current reference.
- [The first run downloads about 1.1 GB: model files and the CPU `torch` wheel] → Later
  runs skip verified files and an up-to-date venv.
- [A `requirements.txt` bump makes the venv again] → This is the purpose of the marker: a
  bump must take effect.
- [Symbolic links break when `models/wolf-small/` is missing] → The runner calls
  `fetch-models.sh` first, which makes the files.
