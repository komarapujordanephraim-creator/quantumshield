"""Score QuantumShield against ShorList rows, reading the catalogue as data only.

Simplified re-implementation of ShorList's documented line-exact rules (README "Scoring"):
positive row -> hit / parent_only / wrong_family / miss on the literal's line;
decoy -> false_alarm if an in-scope family is reported anywhere in the planted tree.
Defect rows (CWE axis) are skipped: QuantumShield reports no CWE.
Usage: python -I bench/shorlist/score.py <path-to-shorlist-checkout> . results.json
"""
import json
import sys
import tempfile
from collections import Counter, defaultdict
from pathlib import Path

import yaml

sl, qs_src, out = Path(sys.argv[1]), sys.argv[2], sys.argv[3]
sys.path.insert(0, qs_src)
sys.path.insert(0, str(Path(__file__).parent))
from quantumshield.scanner import scan_path  # noqa: E402
from family_map import to_family  # noqa: E402

fams = yaml.safe_load((sl / "schema/families.yaml").read_text())
QUANTUM = set(fams["quantum_vulnerable"]) | set(fams["post_quantum"])
WEAK = set(fams["classically_weak"])
PARENT = {k: v.get("parent") for k, v in fams["quantum_vulnerable"].items()}

res = []
for f in sorted((sl / "forms").glob("SL-*.yaml")):
    row = yaml.safe_load(f.read_text())
    if row.get("row_kind") == "defect":
        continue
    exp = (row.get("expected") or {}).get("family") or row.get("family")
    axis = "quantum" if exp in QUANTUM else "weak" if exp in WEAK else "other"
    scope = QUANTUM if axis == "quantum" else QUANTUM | WEAK
    with tempfile.TemporaryDirectory() as d:
        p = Path(d) / row["context_filename"]
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(row["context_template"])
        lines = row["context_template"].splitlines()
        lit_line = next((i for i, l in enumerate(lines, 1) if row["literal"] in l), None)
        recs = [(fi.file, fi.line, to_family(fi.rule_id, fi.snippet)) for fi in scan_path(d).findings]
    if row.get("negative"):
        outcome = "false_alarm" if any(r[2] in scope for r in recs) else "ok"
    else:
        on = [r[2] for r in recs if r[1] == lit_line and r[2] in scope]
        if exp in on:
            outcome = "hit"
        elif PARENT.get(exp) and PARENT[exp] in on:
            outcome = "parent_only"
        elif on:
            outcome = "wrong_family"
        else:
            outcome = "miss"
    res.append({"id": row["id"], "axis": axis, "family": exp, "form_kind": row.get("form_kind"),
                "negative": bool(row.get("negative")), "outcome": outcome})

summary = {}
for axis in ("quantum", "weak"):
    pos = Counter(r["outcome"] for r in res if r["axis"] == axis and not r["negative"])
    neg = Counter(r["outcome"] for r in res if r["axis"] == axis and r["negative"])
    n = sum(pos.values())
    summary[axis] = {"positive": dict(pos), "n_positive": n,
                     "hit_rate": round(pos["hit"] / n, 4) if n else None,
                     "decoys": dict(neg)}
by_kind = defaultdict(Counter)
for r in res:
    if r["axis"] == "quantum" and not r["negative"]:
        by_kind[r["form_kind"]][r["outcome"]] += 1
by_fam = defaultdict(Counter)
for r in res:
    if r["axis"] == "quantum" and not r["negative"]:
        by_fam[r["family"]][r["outcome"]] += 1
json.dump({"summary": summary, "by_form_kind": by_kind, "by_family": by_fam, "rows": res},
          open(out, "w"), indent=1, default=dict)
print(json.dumps(summary, indent=1))
print("by form_kind:", {k: dict(v) for k, v in by_kind.items()})
print("by family:", {k: dict(v) for k, v in by_fam.items()})
