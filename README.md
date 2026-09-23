# PhishLens

![Tests](https://github.com/Rahmanimouad0/phishlens/actions/workflows/tests.yml/badge.svg)

**An AI agent that investigates phishing URLs by autonomously selecting specialized analysis tools and combining their evidence with an existing ML classifier.**

<img width="2864" height="1770" alt="Screenshot 2026-09-23 113509" src="https://github.com/user-attachments/assets/7787092f-080f-4790-8ca1-829febd15d4b" />
<img width="2872" height="1796" alt="Screenshot 2026-09-23 114452" src="https://github.com/user-attachments/assets/926dd31d-bc6b-4179-b391-7ea3c0ca60ef" />
<img width="2872" height="1828" alt="Screenshot 2026-09-23 115314" src="https://github.com/user-attachments/assets/37982eaf-0b27-4de3-b29b-446dea67e864" />

> Status: ✅ Complete — evaluated on a frozen 10-case set.

## What this is

PhishLens extends [Phishing URL Detector](../phishing-url-detector) — instead of a single ML model producing a label, a local LLM agent (Qwen3 8B, via Ollama) investigates a URL step by step: deciding which tools to call, gathering evidence, and producing a reasoned, structured verdict.

The project's core question, answered empirically rather than assumed:

> **Does giving an LLM agent access to specialized security tools (and an existing ML classifier) actually improve phishing detection over either approach alone?**

Short answer, from the evaluation below: **yes, modestly** — but the honest findings matter more than the headline number. See below.

## Architecture

```
                        URL
                         │
                         ▼
                 ┌───────────────┐
                 │  PhishLens    │
                 │  Agent        │
                 │  (Qwen3 8B,   │
                 │   local)      │
                 └───────┬───────┘
                         │
           decides which tools to call
                         │
     ┌──────────┬────────┼────────┬──────────┐
     ▼          ▼        ▼        ▼          ▼
 analyze_url  run_ml   check_dns  analyze_html extract_links
     │          │        │        │          │
     │          │        │        └────┬─────┘
     │          │        │      (sandboxed in Docker --
     │          │        │       see docker/fetcher/)
     └──────────┴────────┼──────────────┘
                         ▼
              Structured verdict (pydantic-validated)
                         │
                         ▼
                  Logged to SQLite (phishlens.db)
                         │
                         ▼
                Investigation Report
             (verdict + evidence + timeline)
```

`analyze_html()` and `extract_links()` fetch real pages inside a disposable, resource-limited Docker container (no volume mounts, `--rm`, never executes fetched content) — the tools themselves never touch the network directly. Every tool call's arguments are validated against a pydantic schema before running, and the final verdict is extracted via a separate JSON-schema-constrained call, validated, with a retry-then-safe-fallback if the model produces something malformed.

## Evaluation

Four systems, compared on a **frozen** 10-case held-out set (5 phishing, 5 legitimate — see `evaluation/manifest.json` for full provenance and `evaluation/final_frozen.json` for the locked case list). S3/S4's HTML-based tools always replay from archived HTML during evaluation (`evaluation/archive_final_set.py`), never live-fetch — reproducibility over freshness.

| System | Correct | Precision | Recall | F1 | Avg Latency | Avg Tool Calls |
|---|---|---|---|---|---|---|
| S1 — ML only | 8/10 | 0.714 | 1.0 | 0.833 | 0.6s | 0 |
| S2 — LLM only, no tools | 8/10 | 1.0* | 1.0* | 1.0* | 95.8s | 0 |
| S3 — Agent + tools, no ML | 8/10 | 0.714 | 1.0 | 0.833 | 284.0s | 1.9 |
| **S4 — Agent + tools + ML** | **9/10** | 0.833 | 1.0 | 0.909 | 364.4s | 2.2 |

\* **S2's "perfect" precision/recall is misleading, not a real win.** It marked 2 of the 5 legitimate cases "inconclusive" rather than guessing — which is invisible to precision/recall (neither a false positive nor a true negative) but still costs it on raw accuracy. S2 is tied at 8/10, not actually the best system. **Raw correctness, not precision/recall, is the honest headline number for S2.**

**On statistical significance:** with only 10 final cases, the 8/10 → 9/10 gap between S1/S3 and S4 is a *single case*. This is directionally suggestive that combining tools + ML helps, not strong proof. A larger final set (planned: expand to ~25, per the original eval design) would be needed to say this with real confidence.

**Every system caught all 5 real phishing cases (recall = 1.0 across the board).** The entire story here is about the 5 legitimate cases, and which ones tripped each system up.

### Case-level findings (the interesting part)


- **`taboola.com`** — fooled S1, S3, *and* S4 (only S2 got it right). Ad-tech/content-recommendation sites structurally resemble phishing infrastructure (heavy third-party redirection, many external domains) to both the ML model's lexical features and the agent's heuristics. This is PhishLens's single most important documented weakness.
- **`ksyuncdn.com`** (a CDN hostname that doesn't resolve directly) — S3 (tools, no ML) got this wrong, reading the DNS failure as a red flag with nothing to counterbalance it. S4 (tools + ML) got it right — the ML model's lexical-only signal, indifferent to DNS resolution, pulled the verdict back to correct. Direct evidence that the ML tool contributes real, complementary value.
- **`youtube-nocookie.com`** — the mirror case: S1 (ML-only) got this wrong (likely misreading the unusual "-nocookie" naming), while every reasoning-based system (S2, S3, S4) got it right. Evidence that agent reasoning corrects ML mistakes too, not just the other way around.

Together these three cases tell the real story: **neither pure ML nor pure agent reasoning is strictly better — they fail differently, and combining them (S4) came out ahead overall but not perfectly.**

### Agent behavior findings

- **Under-exploration on ambiguous evidence.** Across the full evaluation, S3/S4 averaged only **1.9–2.2 tool calls** out of 4–5 available. A single early test (a known-safe tinyurl link, `legit_018`) showed the agent explicitly noting weak evidence ("no obvious red flags," 52.59% ML probability) yet still stopping instead of gathering more — and the aggregate Week 3 data confirms this wasn't a one-off. The agent tends to stop once it reaches *a* conclusion, not necessarily once it's actually confident.
- **Verdict text can overclaim coverage it didn't perform.** In a live dashboard test (`mastersportal.com`), the agent's final evidence explicitly stated "no evidence of redirect chains, iframe injections, or credential harvesting patterns" — despite `analyze_html()` never being called in that investigation. It described something it never checked as checked-and-clear. This is a distinct, more concerning pattern than under-exploration alone, and worth flagging plainly: **don't take PhishLens's stated evidence list as a guarantee of what was actually inspected — cross-check the tool timeline.**

See `evaluation/observations.md` for the full, dated notes these findings are drawn from, and `evaluation/results.json` for complete per-case data.

## Setup

```bash
# 1. Local LLM
ollama pull qwen3:8b

# 2. Python environment
python -m venv phishlens_env
phishlens_env\Scripts\activate      # Windows
pip install -r requirements.txt

# 3. Copy your trained phishing model (not committed -- see tools/phishing_model.py)
#    into models/best_model_url.pkl

# 4. Build the sandboxed HTML fetcher
docker build -t phishlens-fetcher docker/fetcher/

# 5. Run
python run_milestone.py "https://example.com"      # single investigation, CLI
streamlit run dashboard/app.py                       # live web demo
python evaluation/evaluate.py                         # full 4-system evaluation
```

**Known environment note:** building the Docker image and pulling Ollama models can be slow or require a registry mirror when building from mainland China, where Docker Hub's auth service is frequently throttled. See comments in `docker/fetcher/Dockerfile` if you hit this.

## What's explicitly NOT in v1

- WHOIS / domain-age lookups (DNS records alone can't provide this — see `tools/dns_check.py` docstring)
- Certificate transparency checks
- Screenshot analysis
- Multi-agent orchestration
- A final eval set larger than 10 cases (planned expansion to ~25, not yet done)

These may be added in a future phase, but v1 ships as a complete, evaluated system with the five tools above.

## Project progression

1. [Phishing URL Detector](../phishing-url-detector) — ML classification
2. [FLUTE Broadcast Platform](../flute-broadcast-platform) — networking / Rust / systems
3. **PhishLens** (this repo) — AI agents, tool use, and rigorous evaluation

## License

MIT — see `LICENSE`.
