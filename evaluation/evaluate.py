"""
evaluation/evaluate.py — Week 3: the 4-system comparison.

Runs all 4 systems over the FROZEN final set (evaluation/final_frozen.json).
S3/S4's HTML-based tools always replay from local archives (never
live-fetch during evaluation) -- run evaluation/archive_final_set.py once
before this, if you haven't already.

Systems:
  S1 -- ML only              (existing XGBoost classifier)
  S2 -- LLM only               (Qwen3, no tools, no ML)
  S3 -- Agent + tools, no ML   (analyze_url, analyze_html, check_dns, extract_links)
  S4 -- Agent + tools + ML     (all 5 tools -- the project's actual contribution)

RESILIENCE (added after a real crash during development -- see
evaluation/observations.md): every system call is wrapped so a timeout,
network hiccup, or any other exception is recorded as a FAILURE row for
that (case, system) pair -- never crashes the whole run. Results are
saved to evaluation/results.json after EVERY case, not just at the end,
and a re-run skips cases that already have all 4 systems recorded, so
an interrupted run resumes cheaply instead of restarting from scratch.

NOTE on confidence: S1's "confidence" is a real calibrated probability
from the trained model. S2/S3/S4's "confidence" is the LLM's own
qualitative label (low/medium/high) -- NOT a calibrated probability, and
never plotted on the same axis as S1's number. See README for why.
"""

import json
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))  # so `agent`/`tools` are importable

from agent.investigate import investigate
from agent.llm import get_provider
from agent.schemas import Verdict, VERDICT_JSON_SCHEMA
from tools.url_analysis import analyze_url, ANALYZE_URL_SCHEMA
from tools.phishing_model import run_phishing_model, RUN_PHISHING_MODEL_SCHEMA
from tools.html_analysis import analyze_html, ANALYZE_HTML_SCHEMA
from tools.dns_check import check_dns, CHECK_DNS_SCHEMA
from tools.link_extraction import extract_links, EXTRACT_LINKS_SCHEMA
from tools._sandbox import set_archived_html, clear_archived_html

ROOT = Path(__file__).parent
FINAL_SET_PATH = ROOT / "final_frozen.json"
CASES_DIR = ROOT / "cases"
RESULTS_PATH = ROOT / "results.json"

ALL_TOOLS = {
    "analyze_url": analyze_url,
    "run_phishing_model": run_phishing_model,
    "analyze_html": analyze_html,
    "check_dns": check_dns,
    "extract_links": extract_links,
}
ALL_SCHEMAS = [ANALYZE_URL_SCHEMA, RUN_PHISHING_MODEL_SCHEMA, ANALYZE_HTML_SCHEMA,
               CHECK_DNS_SCHEMA, EXTRACT_LINKS_SCHEMA]

NO_ML_TOOLS = {k: v for k, v in ALL_TOOLS.items() if k != "run_phishing_model"}
NO_ML_SCHEMAS = [s for s in ALL_SCHEMAS if s["function"]["name"] != "run_phishing_model"]

LLM_ONLY_PROMPT = """You are a phishing detection expert. Based only on the
URL text below (no tools, no additional lookups available), classify it.

URL: {url}

Respond with JSON matching:
{{"verdict": "phishing" | "legitimate" | "inconclusive",
  "confidence": "low" | "medium" | "high",
  "evidence": "brief reasoning based on the URL text alone"}}
"""

FAILURE_ROW = lambda note: {
    "verdict": "inconclusive", "confidence": None, "latency_ms": 0,
    "tool_calls": 0, "failure": True, "error": note,
}


def load_final_cases():
    final = json.loads(FINAL_SET_PATH.read_text())
    return [json.loads((CASES_DIR / f"{cid}.json").read_text()) for cid in final["case_ids"]]


def load_existing_results():
    if RESULTS_PATH.exists():
        try:
            data = json.loads(RESULTS_PATH.read_text())
            return data.get("per_case", {"S1": {}, "S2": {}, "S3": {}, "S4": {}})
        except Exception:
            pass
    return {"S1": {}, "S2": {}, "S3": {}, "S4": {}}


def safe_run(fn, *args, **kwargs):
    """Runs fn; on ANY exception, returns a failure row instead of crashing."""
    try:
        return fn(*args, **kwargs)
    except Exception as e:
        print(f"    WARNING: {type(e).__name__}: {str(e)[:150]} -- recording as failure, continuing")
        return FAILURE_ROW(f"{type(e).__name__}: {e}")


def run_s1_ml_only(case):
    t0 = time.time()
    result = run_phishing_model(case["url"])
    latency_ms = (time.time() - t0) * 1000
    if "error" in result:
        return {"verdict": "inconclusive", "confidence": None, "ml_probability": None,
                "latency_ms": latency_ms, "tool_calls": 0, "failure": True}
    return {
        "verdict": result["prediction"],
        "confidence": None,
        "ml_probability": result["phishing_probability"],
        "latency_ms": latency_ms,
        "tool_calls": 0,
        "failure": False,
    }


def run_s2_llm_only(case, provider):
    t0 = time.time()
    prompt = LLM_ONLY_PROMPT.format(url=case["url"])
    try:
        raw = provider.structured_complete(prompt, VERDICT_JSON_SCHEMA)
        verdict = Verdict(**raw)
        failure = False
    except Exception as e:
        verdict = Verdict(verdict="inconclusive", confidence="low", evidence=str(e)[:300])
        failure = True
    return {
        "verdict": verdict.verdict,
        "confidence": verdict.confidence,
        "latency_ms": (time.time() - t0) * 1000,
        "tool_calls": 0,
        "failure": failure,
    }


def run_agent_system(case, tools, schemas, system_label, provider):
    t0 = time.time()
    result = investigate(case["url"], tools=tools, tool_schemas=schemas,
                          provider=provider, system=system_label)
    return {
        "verdict": result["verdict"]["verdict"],
        "confidence": result["verdict"]["confidence"],
        "latency_ms": (time.time() - t0) * 1000,
        "tool_calls": len(result["timeline"]),
        "failure": (not result["completed"]) or bool(result["verdict_extraction_error"]),
    }


def compute_metrics(rows, cases_by_id):
    tp = fp = tn = fn = 0
    total_latency = total_tool_calls = failures = 0
    n = len(rows)
    if n == 0:
        return {"n": 0, "correct": 0, "tp": 0, "fp": 0, "tn": 0, "fn": 0,
                "precision": 0, "recall": 0, "f1": 0, "avg_latency_ms": 0,
                "avg_tool_calls": 0, "failure_rate": 0}

    for case_id, row in rows.items():
        expected = cases_by_id[case_id]["expected"]
        predicted = row["verdict"]
        total_latency += row["latency_ms"]
        total_tool_calls += row["tool_calls"]
        failures += int(row["failure"])

        if predicted == "phishing" and expected == "phishing":
            tp += 1
        elif predicted == "phishing" and expected == "legitimate":
            fp += 1
        elif predicted == "legitimate" and expected == "legitimate":
            tn += 1
        elif predicted == "legitimate" and expected == "phishing":
            fn += 1

    correct = tp + tn
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0

    return {
        "n": n, "correct": correct,
        "tp": tp, "fp": fp, "tn": tn, "fn": fn,
        "precision": round(precision, 3), "recall": round(recall, 3), "f1": round(f1, 3),
        "avg_latency_ms": round(total_latency / n, 1),
        "avg_tool_calls": round(total_tool_calls / n, 2),
        "failure_rate": round(failures / n, 3),
    }


def save_progress(all_results, cases_by_id, case_order):
    metrics = {sys_name: compute_metrics(rows, cases_by_id) for sys_name, rows in all_results.items()}
    RESULTS_PATH.write_text(json.dumps(
        {"per_case": all_results, "metrics": metrics, "cases": case_order}, indent=2
    ))
    return metrics


def main():
    cases = load_final_cases()
    cases_by_id = {c["id"]: c for c in cases}
    case_order = [c["id"] for c in cases]
    provider = get_provider()

    all_results = load_existing_results()
    already_done = sum(
        1 for c in cases
        if all(c["id"] in all_results[s] for s in ["S1", "S2", "S3", "S4"])
    )
    if already_done:
        print(f"Resuming: {already_done}/{len(cases)} cases already fully evaluated, skipping those.\n")

    for i, case in enumerate(cases, 1):
        case_id = case["id"]

        if all(case_id in all_results[s] for s in ["S1", "S2", "S3", "S4"]):
            print(f"[{i}/{len(cases)}] {case_id} -- already done, skipping")
            continue

        print(f"\n[{i}/{len(cases)}] {case_id} (expected: {case['expected']})")

        clear_archived_html()
        if case.get("archived_html"):
            html_path = ROOT / case["archived_html"]
            if html_path.exists():
                set_archived_html(
                    case["url"], html_path.read_text(encoding="utf-8", errors="replace")
                )

        print("  S1 (ML only)...")
        all_results["S1"][case_id] = safe_run(run_s1_ml_only, case)

        print("  S2 (LLM only)...")
        all_results["S2"][case_id] = safe_run(run_s2_llm_only, case, provider)

        print("  S3 (Agent + tools, no ML)...")
        all_results["S3"][case_id] = safe_run(
            run_agent_system, case, NO_ML_TOOLS, NO_ML_SCHEMAS, "S3", provider
        )

        print("  S4 (Agent + tools + ML)...")
        all_results["S4"][case_id] = safe_run(
            run_agent_system, case, ALL_TOOLS, ALL_SCHEMAS, "S4", provider
        )

        save_progress(all_results, cases_by_id, case_order)
        print(f"  [saved progress to {RESULTS_PATH.name}]")

    clear_archived_html()
    metrics = save_progress(all_results, cases_by_id, case_order)

    print("\n\n=== SUMMARY (10 frozen final cases) ===")
    print(f"{'System':<6}{'Correct':<10}{'Precision':<11}{'Recall':<9}{'F1':<7}"
          f"{'AvgLatency(ms)':<16}{'AvgTools':<10}{'FailRate'}")
    for sys_name, m in metrics.items():
        print(f"{sys_name:<6}{m['correct']}/{m['n']:<8}{m['precision']:<11}{m['recall']:<9}"
              f"{m['f1']:<7}{m['avg_latency_ms']:<16}{m['avg_tool_calls']:<10}{m['failure_rate']}")

    print(f"\nFull results written to {RESULTS_PATH}")


if __name__ == "__main__":
    main()
