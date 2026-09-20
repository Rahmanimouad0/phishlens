"""
agent/investigate.py — the hand-rolled agent loop, now with structured-
output validation and SQLite logging.

Validation: every tool call's arguments are checked against a pydantic
schema BEFORE the tool runs (catches a flaky local model emitting
malformed args). The final verdict is extracted via a SEPARATE JSON-
schema-constrained call and validated with pydantic; on failure it
retries once, then falls back to a safe "inconclusive" default rather
than crashing or returning unparseable text downstream.

Logging: every tool call (name, args, result, success, latency) and
every completed investigation is written to phishlens.db (SQLite) via
agent/db.py. This table is the metrics source for Week 3.
"""

import json
import time
import uuid

from pydantic import ValidationError

from agent.llm import get_provider, LLMResponse
from agent.schemas import URLToolArgs, Verdict, VERDICT_JSON_SCHEMA
from agent.db import log_tool_call, log_investigation

MAX_STEPS = 8

SYSTEM_PROMPT = """You are PhishLens, a phishing URL investigation agent.

You have access to security analysis tools. Call tools to gather evidence
before making a verdict -- do not guess without calling at least one tool.

When you have enough evidence, respond with your final verdict WITHOUT
calling another tool. Your final response must state:
1. Verdict: "phishing" or "legitimate"
2. Confidence: low, medium, or high
3. Evidence: the specific findings that led to this verdict
"""

VERDICT_EXTRACTION_PROMPT = """Extract a structured verdict from this phishing
investigation report about the URL: {url}

Report:
{report}

Respond with JSON matching this shape exactly:
{{"verdict": "phishing" | "legitimate" | "inconclusive",
  "confidence": "low" | "medium" | "high",
  "evidence": "a short one-paragraph summary of the key evidence"}}
"""


def _extract_structured_verdict(provider, url: str, raw_text: str):
    """Returns (Verdict, error_or_None). Retries once, then falls back safely."""
    prompt = VERDICT_EXTRACTION_PROMPT.format(url=url, report=raw_text)
    last_error = None
    for _ in range(2):
        try:
            raw_json = provider.structured_complete(prompt, VERDICT_JSON_SCHEMA)
            return Verdict(**raw_json), None
        except Exception as e:
            last_error = f"{type(e).__name__}: {e}"
            continue
    fallback = Verdict(
        verdict="inconclusive",
        confidence="low",
        evidence=(raw_text or "no report text")[:500],
    )
    return fallback, last_error


def investigate(url: str, tools: dict, tool_schemas: list, provider=None,
                 system: str = "agent_full", investigation_id: str = None) -> dict:
    """
    tools: {tool_name: python_callable}
    tool_schemas: [{"type": "function", "function": {...}}, ...]
    system: label for which evaluation "system" this run represents.
            Week 3's evaluate.py passes "S1".."S4"; run_milestone.py
            leaves this at the default ("agent_full").
    """
    provider = provider or get_provider()
    investigation_id = investigation_id or str(uuid.uuid4())
    start_time = time.time()

    messages = [
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user", "content": f"Investigate this URL: {url}"},
    ]
    timeline = []

    for step in range(MAX_STEPS):
        resp: LLMResponse = provider.chat(messages, tools=tool_schemas)

        if resp.tool_call:
            name, args = resp.tool_call.name, resp.tool_call.args
            call_start = time.time()

            try:
                validated = URLToolArgs(**args)
            except ValidationError as e:
                result = {"error": f"invalid tool arguments: {e}"}
                success = False
            else:
                if name not in tools:
                    result = {"error": f"unknown tool requested: {name}"}
                    success = False
                else:
                    try:
                        result = tools[name](url=validated.url)
                        success = "error" not in result
                    except Exception as e:
                        result = {"error": f"{type(e).__name__}: {e}"}
                        success = False

            latency_ms = (time.time() - call_start) * 1000
            timeline.append({"step": step, "tool": name, "args": args, "result": result})
            log_tool_call(investigation_id, step, name, args, result, success, latency_ms)

            messages.append({
                "role": "assistant", "content": "",
                "tool_calls": [{"function": {"name": name, "arguments": args}}],
            })
            messages.append({"role": "tool", "content": json.dumps(result)})

        else:
            verdict, extraction_error = _extract_structured_verdict(
                provider, url, resp.final_report
            )
            total_latency_ms = (time.time() - start_time) * 1000
            log_investigation(
                investigation_id, url, system, verdict.verdict, verdict.confidence,
                step + 1, True, total_latency_ms,
            )
            return {
                "investigation_id": investigation_id,
                "url": url,
                "verdict_text": resp.final_report,
                "verdict": verdict.model_dump(),
                "verdict_extraction_error": extraction_error,
                "timeline": timeline,
                "steps_used": step + 1,
                "completed": True,
            }

    messages.append({
        "role": "user",
        "content": "You've reached the tool-call limit. Give your final "
                    "verdict now based on the evidence gathered so far, "
                    "without calling another tool.",
    })
    resp = provider.chat(messages, tools=[])
    verdict, extraction_error = _extract_structured_verdict(provider, url, resp.final_report)
    total_latency_ms = (time.time() - start_time) * 1000
    log_investigation(
        investigation_id, url, system, verdict.verdict, verdict.confidence,
        MAX_STEPS, False, total_latency_ms,
    )
    return {
        "investigation_id": investigation_id,
        "url": url,
        "verdict_text": resp.final_report or "INCONCLUSIVE -- step limit reached",
        "verdict": verdict.model_dump(),
        "verdict_extraction_error": extraction_error,
        "timeline": timeline,
        "steps_used": MAX_STEPS,
        "completed": False,
    }
