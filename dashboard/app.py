"""
dashboard/app.py — PhishLens live demo.

Paste a URL, watch the full agent investigation (S4: all 5 tools) run,
and see the verdict with the evidence timeline that led to it.

This is the LIVE-fetch path -- analyze_html()/extract_links() hit real
pages via the sandboxed Docker fetcher here. This is kept deliberately
separate from evaluate.py, which always replays from archived HTML for
reproducibility. See README for why.

Run:
    streamlit run dashboard/app.py
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

import streamlit as st

from agent.investigate import investigate
from tools.url_analysis import analyze_url, ANALYZE_URL_SCHEMA
from tools.phishing_model import run_phishing_model, RUN_PHISHING_MODEL_SCHEMA
from tools.html_analysis import analyze_html, ANALYZE_HTML_SCHEMA
from tools.dns_check import check_dns, CHECK_DNS_SCHEMA
from tools.link_extraction import extract_links, EXTRACT_LINKS_SCHEMA

st.set_page_config(page_title="PhishLens", page_icon="🎣", layout="centered")

ALL_TOOLS = {
    "analyze_url": analyze_url,
    "run_phishing_model": run_phishing_model,
    "analyze_html": analyze_html,
    "check_dns": check_dns,
    "extract_links": extract_links,
}
ALL_SCHEMAS = [ANALYZE_URL_SCHEMA, RUN_PHISHING_MODEL_SCHEMA, ANALYZE_HTML_SCHEMA,
               CHECK_DNS_SCHEMA, EXTRACT_LINKS_SCHEMA]

TOOL_LABELS = {
    "analyze_url": "🔤 Analyzed URL structure",
    "run_phishing_model": "🤖 Ran ML classifier (XGBoost)",
    "analyze_html": "📄 Fetched & analyzed page HTML (sandboxed)",
    "check_dns": "🌐 Checked DNS records",
    "extract_links": "🔗 Extracted outbound links",
}

st.title("🎣 PhishLens")
st.caption("AI agent investigating phishing URLs — autonomous tool use + an existing ML classifier")

url = st.text_input("URL to investigate", placeholder="https://example.com")
run_button = st.button("Investigate", type="primary", disabled=not url)

if run_button and url:
    with st.spinner("Investigating... local model on CPU, expect 60-150 seconds"):
        try:
            result = investigate(
                url, tools=ALL_TOOLS, tool_schemas=ALL_SCHEMAS, system="dashboard_demo"
            )
        except Exception as e:
            st.error(f"Investigation failed: {type(e).__name__}: {e}")
            st.stop()

    verdict = result["verdict"]
    color = {"phishing": "🔴", "legitimate": "🟢", "inconclusive": "🟡"}.get(
        verdict["verdict"], "⚪"
    )

    st.subheader(f"{color} {verdict['verdict'].upper()}")
    st.caption(
        f"Confidence: {verdict['confidence']} · {result['steps_used']} steps · "
        f"{len(result['timeline'])} tool calls · completed: {result['completed']}"
    )

    st.markdown("**Evidence:**")
    st.write(verdict["evidence"])

    with st.expander("Full investigation timeline"):
        if not result["timeline"]:
            st.write("The agent gave a verdict without calling any tools.")
        for t in result["timeline"]:
            label = TOOL_LABELS.get(t["tool"], t["tool"])
            st.markdown(f"**Step {t['step']}: {label}**")
            st.json(t["result"])

    with st.expander("Raw agent output (before structuring)"):
        st.text(result["verdict_text"])

st.divider()
st.caption(
    "Built by Mouad Rahmani. v1 — WHOIS lookups, certificate analysis, and "
    "screenshot-based checks are explicitly out of scope. See the repo's README "
    "for the full 4-system evaluation against ML-only and LLM-only baselines."
)
