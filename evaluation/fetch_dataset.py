"""
PhishLens — Week 0, step 2: source the evaluation dataset.

Pulls:
  - Phishing URLs from the OpenPhish free feed (no registration needed,
    updated every 6 hours: https://openphish.com/feed.txt)
  - Legitimate domains from the Tranco top-1m list
    (https://tranco-list.eu/top-1m.csv.zip)

For each phishing URL, immediately archives the raw HTML to
evaluation/cases/html/<id>.html — phishing sites disappear fast, and the
evaluation harness (Week 3) must always replay from this archive, never
re-fetch live pages.

Writes:
  evaluation/cases/phish_XXX.json      (one per phishing case)
  evaluation/cases/legit_XXX.json      (one per legitimate case)
  evaluation/manifest.json              (updated with provenance + case list)

Run from the repo root:
    pip install requests
    python evaluation/fetch_dataset.py

This only builds the "easy" bulk of the set (20 phishing + 15 legitimate).
The 5 "hard" legitimate cases need your own judgment — see the printed
instructions at the end of this script.
"""

import csv
import io
import json
import zipfile
from datetime import datetime, timezone
from pathlib import Path

import requests

ROOT = Path(__file__).parent
CASES_DIR = ROOT / "cases"
HTML_DIR = CASES_DIR / "html"
MANIFEST_PATH = ROOT / "manifest.json"

OPENPHISH_FEED = "https://openphish.com/feed.txt"
TRANCO_ZIP = "https://tranco-list.eu/top-1m.csv.zip"

N_PHISHING = 20
N_LEGIT_EASY = 15
FETCH_TIMEOUT = 8  # seconds — phishing infra is often slow/half-dead
HEADERS = {"User-Agent": "PhishLens-research-dataset/0.1 (student project)"}


def fetch_phishing_urls(n=N_PHISHING):
    print(f"Fetching OpenPhish feed...")
    resp = requests.get(OPENPHISH_FEED, headers=HEADERS, timeout=15)
    resp.raise_for_status()
    all_urls = [line.strip() for line in resp.text.splitlines() if line.strip()]
    print(f"  Feed has {len(all_urls)} URLs. Sampling first {n} that we can archive...")
    return all_urls


def fetch_legit_domains(n=N_LEGIT_EASY):
    print("Fetching Tranco top-1m list...")
    resp = requests.get(TRANCO_ZIP, headers=HEADERS, timeout=30)
    resp.raise_for_status()
    with zipfile.ZipFile(io.BytesIO(resp.content)) as z:
        csv_name = z.namelist()[0]
        with z.open(csv_name) as f:
            reader = csv.reader(io.TextIOWrapper(f, encoding="utf-8"))
            domains = [row[1] for row in reader if len(row) >= 2]
    # Skip the absolute top (google.com etc.) — too easy / not representative
    # of what a small business or a student would actually check.
    candidates = domains[200:2000]
    print(f"  Sampling {n} domains from rank 200-2000...")
    return candidates[:n]


def try_archive_html(url, out_path):
    """Attempt to fetch and save raw HTML. Returns True on success."""
    try:
        resp = requests.get(url, headers=HEADERS, timeout=FETCH_TIMEOUT, verify=False)
        out_path.write_text(resp.text, encoding="utf-8", errors="replace")
        return True
    except Exception as e:
        print(f"    [skip] {url[:60]}... ({type(e).__name__})")
        return False


def build_phishing_cases(urls, n=N_PHISHING):
    cases = []
    HTML_DIR.mkdir(parents=True, exist_ok=True)
    i = 0
    for url in urls:
        if len(cases) >= n:
            break
        i += 1
        case_id = f"phish_{len(cases)+1:03d}"
        html_path = HTML_DIR / f"{case_id}.html"
        print(f"  [{len(cases)+1}/{n}] archiving {url[:70]}")
        ok = try_archive_html(url, html_path)
        if not ok:
            continue  # site already dead, try the next URL in the feed
        case = {
            "id": case_id,
            "url": url,
            "expected": "phishing",
            "difficulty": "easy",
            "source": "openphish",
            "pulled_at": datetime.now(timezone.utc).isoformat(),
            "archived_html": f"cases/html/{case_id}.html",
        }
        (CASES_DIR / f"{case_id}.json").write_text(json.dumps(case, indent=2))
        cases.append(case)
    return cases


def build_legit_cases(domains, n=N_LEGIT_EASY):
    cases = []
    for domain in domains:
        if len(cases) >= n:
            break
        url = f"https://{domain}"
        case_id = f"legit_{len(cases)+1:03d}"
        print(f"  [{len(cases)+1}/{n}] {url}")
        case = {
            "id": case_id,
            "url": url,
            "expected": "legitimate",
            "difficulty": "easy",
            "source": "tranco",
            "pulled_at": datetime.now(timezone.utc).isoformat(),
            "archived_html": None,  # legit sites are stable; fetch live in Week 2 if needed
        }
        (CASES_DIR / f"{case_id}.json").write_text(json.dumps(case, indent=2))
        cases.append(case)
    return cases


def update_manifest(phish_cases, legit_cases):
    manifest = json.loads(MANIFEST_PATH.read_text())
    manifest["dataset_version"] = "v1-auto-sourced"
    manifest["created"] = datetime.now(timezone.utc).isoformat()
    manifest["cases"] = [c["id"] for c in phish_cases + legit_cases]
    manifest["_note"] = (
        "5 hard legitimate cases NOT included yet — add them manually "
        "(see script output) as legit_016.json .. legit_020.json, then "
        "re-run the split step."
    )
    MANIFEST_PATH.write_text(json.dumps(manifest, indent=2))


def main():
    CASES_DIR.mkdir(parents=True, exist_ok=True)

    phishing_urls = fetch_phishing_urls()
    phish_cases = build_phishing_cases(phishing_urls)

    legit_domains = fetch_legit_domains()
    legit_cases = build_legit_cases(legit_domains)

    update_manifest(phish_cases, legit_cases)

    print()
    print(f"Done: {len(phish_cases)} phishing cases, {len(legit_cases)} easy legitimate cases.")
    print()
    print("=" * 70)
    print("NEXT: add 5 HARD legitimate cases by hand (legit_016..legit_020).")
    print("These need judgment, not scraping. Suggestions:")
    print("  - A URL shortener landing page (e.g. a real bit.ly/tinyurl link")
    print("    you trust) — structurally resembles what a naive URL heuristic")
    print("    flags as suspicious, but is legitimate.")
    print("  - A small business or personal site on an unusual TLD (.io, .dev,")
    print("    .co) that you can verify is real and legitimate.")
    print("  - A newly-registered but legitimate site (a recent product launch,")
    print("    a new open-source project's docs site, etc.)")
    print("Use the same JSON shape as the generated legit_*.json files.")
    print("=" * 70)


if __name__ == "__main__":
    main()
