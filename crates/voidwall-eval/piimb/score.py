"""Scores `piimb-spans` output with the PII Masking Benchmark's own metric code.

Run it with `docker/ctl piimb-eval`, which fetches the benchmark, builds the venv, and
writes the spans. See `openspec/specs/evaluation/spec.md`.

usage: score.py <piimb src dir> <test_sentences.jsonl> <spans.jsonl> <revision> <task>...

It loads `piimb/models.py` and `piimb/metrics.py` from their files, unmodified, and skips
`piimb/__init__.py`, which imports the benchmark's ML dependencies. The report holds task
names, counts, and scores only, never sentence text.
"""

import importlib.util
import json
import sys
import types

ENGLISH_TASKS = ["ai4privacy-en", "gretel", "nemotron-pii", "privy"]

LEGEND = """\
F2         like F1, but R weighs twice as much as P: 5·P·R / (4·P + R); the leaderboard
           ranks by Avg F2
F1         harmonic mean of P and R
P          share of predicted characters that fall inside a true PII span
R          share of true PII characters that a prediction covers
counting   characters, not entities: overlapping spans are merged per sentence, and
           labels are ignored; counts are summed over a task's sentences before the ratio
Avg        simple mean of the task values, as on the leaderboard"""


def fail(message: str) -> None:
    sys.exit(f"score.py: {message}")


def load_piimb(src: str):
    """Loads `piimb.models` and `piimb.metrics` without running `piimb/__init__.py`."""
    sys.modules["piimb"] = types.ModuleType("piimb")
    for name in ("models", "metrics"):
        spec = importlib.util.spec_from_file_location(f"piimb.{name}", f"{src}/piimb/{name}.py")
        module = importlib.util.module_from_spec(spec)
        sys.modules[f"piimb.{name}"] = module
        spec.loader.exec_module(module)
    return sys.modules["piimb.models"].Entity, sys.modules["piimb.metrics"].compute_masking_metrics


def read_jsonl(path: str):
    with open(path, encoding="utf-8") as f:
        for line in f:
            if line.strip():
                yield json.loads(line)


def main(argv: list[str]) -> None:
    if len(argv) < 5:
        fail("usage: score.py <piimb src dir> <test_sentences.jsonl> <spans.jsonl> <revision> <task>...")
    src, data, spans_path, revision, tasks = argv[0], argv[1], argv[2], argv[3], argv[4:]
    Entity, compute_masking_metrics = load_piimb(src)

    # Spans pair with sentences by position, as piimb pairs predictions with rows: a uid
    # is not unique in the benchmark. The uid at each position must still agree.
    sentences = [r for r in read_jsonl(data) if r["task_name"] in tasks]
    spans = list(read_jsonl(spans_path))
    if len(spans) != len(sentences):
        fail(f"{len(spans)} span lines for {len(sentences)} {', '.join(tasks)} sentences")
    for i, (r, s) in enumerate(zip(sentences, spans, strict=True)):
        if (s["uid"], s["task_name"]) != (r["uid"], r["task_name"]):
            fail(f"span line {i + 1} is for another sentence than the benchmark row it pairs with")
    rows = {t: [] for t in tasks}
    for r, s in zip(sentences, spans, strict=True):
        rows[r["task_name"]].append((r, s["entities"]))

    results = []
    for task in tasks:
        task_rows = rows[task]
        if not task_rows:
            fail(f"revision {revision} holds no {task} sentences")
        y_true = [[Entity(**e) for e in r["entities"]] for r, _ in task_rows]
        y_pred = [[Entity(**e) for e in pred] for _, pred in task_rows]
        lengths = [len(r["text"]) for r, _ in task_rows]

        perfect = compute_masking_metrics(y_true=y_true, y_pred=y_true, text_lengths=lengths)
        if (perfect.precision, perfect.recall, perfect.f1, perfect.f2) != (1.0, 1.0, 1.0, 1.0):
            fail(f"self-check failed: {task} ground truth does not score 1.0 against itself")

        m = compute_masking_metrics(y_true=y_true, y_pred=y_pred, text_lengths=lengths)
        results.append((task, len(task_rows), m.f2, m.f1, m.precision, m.recall))

    print()
    print("=== PII Masking Benchmark (piimb), sentences subset: voidwall-pii regex engine ===")
    print(f"revision={revision}")
    print()
    print(f"{'task':<14} {'sentences':>9} {'F2':>7} {'F1':>7} {'P':>7} {'R':>7}")
    print("-" * 56)
    for task, n, f2, f1, p, r in results:
        print(f"{task:<14} {n:>9} {f2:>7.3f} {f1:>7.3f} {p:>7.3f} {r:>7.3f}")
    if sorted(tasks) == sorted(ENGLISH_TASKS):
        avg = [sum(col) / len(results) for col in list(zip(*results))[2:]]
        print(f"{'Avg':<14} {'':>9} {avg[0]:>7.3f} {avg[1]:>7.3f} {avg[2]:>7.3f} {avg[3]:>7.3f}")
    else:
        print()
        print("This run scores part of the English tasks only; it is not a full benchmark result.")
    print()
    print("--- Legend ---")
    print(LEGEND)


if __name__ == "__main__":
    main(sys.argv[1:])
