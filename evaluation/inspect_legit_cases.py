"""
evaluation/inspect_legit_cases.py — quick lookup: what verdict did each
system give on each legitimate case? Used to find the specific false
positives / inconclusive cases for the README's honest-findings section.
"""

import json
from pathlib import Path

ROOT = Path(__file__).parent
results = json.loads((ROOT / "results.json").read_text())

for case_id in sorted(results["cases"]):
    if not case_id.startswith("legit"):
        continue
    print(f"\n{case_id}:")
    for system in ["S1", "S2", "S3", "S4"]:
        row = results["per_case"][system].get(case_id, {})
        verdict = row.get("verdict", "?")
        marker = "  <-- WRONG" if verdict == "phishing" else (
            "  <-- inconclusive" if verdict == "inconclusive" else ""
        )
        print(f"  {system}: {verdict}{marker}")
