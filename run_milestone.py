"""
Week 1 milestone: URL -> agent -> analyze_url() -> verdict.

If this runs end to end and produces a sensible verdict, the core
architecture works. Every tool added after this (Week 2) plugs into the
exact same pattern: write the function, write its schema, add both to the
`tools` / `schemas` dicts below (or wherever investigate() is called from
in later scripts).

Prerequisites:
    ollama pull qwen3:8b
    (Ollama running in the background — the installer sets this up automatically)

Run:
    python run_milestone.py "https://some-url-to-test.com"
    python run_milestone.py            # uses a built-in suspicious example
"""

import sys

from agent.investigate import investigate
from tools.url_analysis import analyze_url, ANALYZE_URL_SCHEMA

DEFAULT_TEST_URL = "http://verify-account-login.secure-update.tk/confirm"


def main():
    url = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_TEST_URL

    tools = {"analyze_url": analyze_url}
    schemas = [ANALYZE_URL_SCHEMA]

    print(f"Investigating: {url}")
    print("(this may take 30-90 seconds on CPU inference — that's expected)\n")

    result = investigate(url, tools=tools, tool_schemas=schemas)

    print("=== Investigation result ===")
    print(f"URL:            {result['url']}")
    print(f"Steps used:     {result['steps_used']} / 8")
    print(f"Completed:      {result['completed']}")
    print(f"Tool calls:     {len(result['timeline'])}")
    for t in result["timeline"]:
        print(f"  step {t['step']}: {t['tool']}({t['args']})")
    print(f"\nVerdict:\n{result['verdict_text']}")


if __name__ == "__main__":
    main()
