"""
agent/investigate.py — the hand-rolled agent loop.

No framework. The LLM decides which tool to call next; we execute it and
feed the result back; repeat until the LLM gives a final verdict instead
of another tool call, or we hit MAX_STEPS (never let it hang forever).
"""

import json

from agent.llm import get_provider, LLMResponse

MAX_STEPS = 8

SYSTEM_PROMPT = """You are PhishLens, a phishing URL investigation agent.

You have access to security analysis tools. Call tools to gather evidence
before making a verdict — do not guess without calling at least one tool.

When you have enough evidence, respond with your final verdict WITHOUT
calling another tool. Your final response must state:
1. Verdict: "phishing" or "legitimate"
2. Confidence: low, medium, or high
3. Evidence: the specific findings that led to this verdict
"""


def investigate(url: str, tools: dict, tool_schemas: list, provider=None) -> dict:
    """
    tools: {tool_name: python_callable}
    tool_schemas: [{"type": "function", "function": {...}}, ...]
    """
    provider = provider or get_provider()

    messages = [
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user", "content": f"Investigate this URL: {url}"},
    ]
    timeline = []

    for step in range(MAX_STEPS):
        resp: LLMResponse = provider.chat(messages, tools=tool_schemas)

        if resp.tool_call:
            name, args = resp.tool_call.name, resp.tool_call.args

            if name not in tools:
                result = {"error": f"unknown tool requested: {name}"}
            else:
                try:
                    result = tools[name](**args)
                except Exception as e:
                    result = {"error": f"{type(e).__name__}: {e}"}

            timeline.append({"step": step, "tool": name, "args": args, "result": result})

            messages.append({
                "role": "assistant",
                "content": "",
                "tool_calls": [{"function": {"name": name, "arguments": args}}],
            })
            messages.append({"role": "tool", "content": json.dumps(result)})

        else:
            return {
                "url": url,
                "verdict_text": resp.final_report,
                "timeline": timeline,
                "steps_used": step + 1,
                "completed": True,
            }

    # Step limit hit — force a verdict from whatever evidence we've gathered
    # rather than letting the investigation hang indefinitely.
    messages.append({
        "role": "user",
        "content": "You've reached the tool-call limit. Give your final "
                    "verdict now based on the evidence gathered so far, "
                    "without calling another tool.",
    })
    resp = provider.chat(messages, tools=[])
    return {
        "url": url,
        "verdict_text": resp.final_report or "INCONCLUSIVE — step limit reached, no verdict given",
        "timeline": timeline,
        "steps_used": MAX_STEPS,
        "completed": False,
    }
