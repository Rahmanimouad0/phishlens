"""
PhishLens — Week 0, step 4: freeze the dev/final split.

Splits the 40 cases in evaluation/cases/ into:
  - dev_set.json      (30 cases) — look at these as much as you want while building
  - final_frozen.json (10 cases) — locked. Do not inspect results on these
                                    until Week 3's final evaluation run.

The split is STRATIFIED so both sets stay representative:
  - 20 phishing (easy)          -> 15 dev / 5 final
  - 15 legitimate (easy)        -> 11 dev / 4 final
  -  5 legitimate (hard)        ->  4 dev / 1 final
                                     -----------------
                                     30 dev / 10 final

Uses a fixed random seed so the split is reproducible from this script alone
-- but the OUTPUT FILES are what actually matter. Once final_frozen.json
exists, this script refuses to overwrite it, so you can't "accidentally"
re-roll a bad split later. Delete the file yourself if you genuinely need
to redo this step (and be honest in your README if you do).
"""

import json
import random
from pathlib import Path

ROOT = Path(__file__).parent
CASES_DIR = ROOT / "cases"
DEV_PATH = ROOT / "dev_set.json"
FINAL_PATH = ROOT / "final_frozen.json"
MANIFEST_PATH = ROOT / "manifest.json"

SEED = 42

# (expected, difficulty) -> (dev_count, final_count)
SPLIT_PLAN = {
    ("phishing", "easy"): (15, 5),
    ("legitimate", "easy"): (11, 4),
    ("legitimate", "hard"): (4, 1),
}


def load_cases():
    cases = []
    for path in sorted(CASES_DIR.glob("*.json")):
        case = json.loads(path.read_text())
        cases.append(case)
    return cases


def group_cases(cases):
    groups = {}
    for c in cases:
        key = (c["expected"], c.get("difficulty", "easy"))
        groups.setdefault(key, []).append(c)
    return groups


def main():
    if FINAL_PATH.exists():
        print(f"REFUSING to run: {FINAL_PATH.name} already exists.")
        print("The final evaluation set is frozen once created.")
        print("If you genuinely need to redo the split, delete final_frozen.json")
        print("yourself first, and note why in your README.")
        return

    cases = load_cases()
    groups = group_cases(cases)

    print("Cases found by group:")
    for key, plan in SPLIT_PLAN.items():
        found = len(groups.get(key, []))
        needed = sum(plan)
        status = "OK" if found >= needed else f"SHORT by {needed - found}"
        print(f"  {key}: found {found}, need {needed} ({status})")

    rng = random.Random(SEED)
    dev_cases, final_cases = [], []

    for key, (n_dev, n_final) in SPLIT_PLAN.items():
        pool = groups.get(key, [])[:]
        if len(pool) < n_dev + n_final:
            print(f"\nERROR: not enough cases for {key} "
                  f"(have {len(pool)}, need {n_dev + n_final}). "
                  f"Fix your cases/ folder before splitting.")
            return
        rng.shuffle(pool)
        final_cases.extend(pool[:n_final])
        dev_cases.extend(pool[n_final:n_final + n_dev])

    DEV_PATH.write_text(json.dumps(
        {"set": "dev", "count": len(dev_cases),
         "case_ids": [c["id"] for c in dev_cases]},
        indent=2,
    ))
    FINAL_PATH.write_text(json.dumps(
        {"set": "final_frozen", "count": len(final_cases),
         "frozen": True,
         "case_ids": [c["id"] for c in final_cases]},
        indent=2,
    ))

    manifest = json.loads(MANIFEST_PATH.read_text())
    manifest["split"]["dev_actual"] = len(dev_cases)
    manifest["split"]["final_actual"] = len(final_cases)
    manifest["split"]["seed"] = SEED
    manifest["split"]["frozen"] = True
    MANIFEST_PATH.write_text(json.dumps(manifest, indent=2))

    print(f"\nWrote dev_set.json ({len(dev_cases)} cases)")
    print(f"Wrote final_frozen.json ({len(final_cases)} cases) — LOCKED")
    print("\nCommit both files to git now, so the split itself is provable later:")
    print('  git add evaluation/dev_set.json evaluation/final_frozen.json evaluation/manifest.json')
    print('  git commit -m "Freeze Week 0 dev/final evaluation split"')


if __name__ == "__main__":
    main()
