"""
evaluation/archive_final_set.py — Week 3 prep: archive HTML for every
case in the frozen final set, so evaluate.py can replay from disk and
NEVER live-fetch during actual evaluation runs.

Phishing cases already have archived HTML from Week 0 (fetch_dataset.py
archived it immediately, since phishing sites die fast). Legitimate
cases were deliberately skipped then (assumed stable) -- this script
fills that gap now, using the exact same sandboxed Docker fetcher the
tools themselves use, so the archived content matches what a live fetch
would have returned at the time of archiving.

Run once, before evaluate.py. Safe to re-run -- skips cases that
already have archived_html set.
"""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))  # so `tools` is importable

from tools._sandbox import fetch_html_sandboxed

ROOT = Path(__file__).parent
FINAL_SET_PATH = ROOT / "final_frozen.json"
CASES_DIR = ROOT / "cases"
HTML_DIR = CASES_DIR / "html"


def main():
    final = json.loads(FINAL_SET_PATH.read_text())
    HTML_DIR.mkdir(parents=True, exist_ok=True)

    print(f"Archiving HTML for all {len(final['case_ids'])} cases in the frozen final set...\n")

    archived, skipped, failed = 0, 0, 0

    for case_id in final["case_ids"]:
        case_path = CASES_DIR / f"{case_id}.json"
        case = json.loads(case_path.read_text())

        if case.get("archived_html"):
            html_path = ROOT / case["archived_html"]
            if html_path.exists():
                print(f"  [skip] {case_id} -- already archived")
                skipped += 1
                continue

        print(f"  [fetch] {case_id} ({case['url'][:60]})...")
        html, error = fetch_html_sandboxed(case["url"])

        if error:
            print(f"    WARNING: fetch failed ({error})")
            print(f"    This is a real, documentable limitation -- S3/S4 will get a "
                  f"fetch_error for this case's HTML-based tools during evaluation. "
                  f"Note it in your findings rather than silently retrying or hiding it.")
            failed += 1
            continue

        html_path = HTML_DIR / f"{case_id}.html"
        html_path.write_text(html, encoding="utf-8", errors="replace")
        case["archived_html"] = f"cases/html/{case_id}.html"
        case_path.write_text(json.dumps(case, indent=2))
        print(f"    saved -> {html_path.name}")
        archived += 1

    print(f"\nDone. Archived: {archived}, already had it: {skipped}, failed: {failed}.")
    if failed:
        print(f"{failed} case(s) will show a fetch_error during evaluation for "
              f"HTML-based tools -- that's fine, just report it honestly.")
    print("\nCommit the updated case JSON files and any new HTML archives:")
    print("  git add evaluation/cases/")
    print('  git commit -m "Archive HTML for legitimate cases in frozen final set"')


if __name__ == "__main__":
    main()
