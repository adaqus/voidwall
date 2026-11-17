"""Write the Phase 0 Tier A1 cases (no homoglyphs) with the prototype's view.

Usage: python3 -I proto_a1.py HARNESS_DIR CORPUS_DIR OUT.jsonl
The prototype's `phase1` without its homoglyph part: its source is cut where
the homoglyph folding starts.
"""

import inspect
import json
import sys

harness, corpus, out = sys.argv[1:4]
sys.path.insert(0, harness)
import proto_decode  # noqa: E402

source = inspect.getsource(proto_decode.phase1)
cut = source.index('    s = "".join(out)')
source = source[:cut] + '    return "".join(out)\n'
source = source.replace("def phase1(", "def phase1_no_homoglyph(", 1)
namespace = vars(proto_decode)
exec(source, namespace)
view = namespace["phase1_no_homoglyph"]

with open(out, "w", encoding="utf-8") as f:
    for name in ["attack_injection", "attack_pii", "benign_transformed"]:
        for line in open(f"{corpus}/{name}.jsonl", encoding="utf-8"):
            case = json.loads(line)
            if case["tier"] != "A1" or case["transform"] == "homoglyph":
                continue
            case["prototype"] = view(case["text"], [])
            f.write(json.dumps(case, ensure_ascii=False) + "\n")
