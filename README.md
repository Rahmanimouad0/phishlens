# PhishLens
![Tests](https://github.com/Rahmanimouad0/phishlens/actions/workflows/tests.yml/badge.svg)

**An AI agent that investigates phishing URLs by autonomously selecting specialized analysis tools and combining their evidence with an existing ML classifier.**

<img width="2864" height="1770" alt="Screenshot 2026-09-23 113509" src="https://github.com/user-attachments/assets/7787092f-080f-4790-8ca1-829febd15d4b" />
<img width="2872" height="1796" alt="Screenshot 2026-09-23 114452" src="https://github.com/user-attachments/assets/926dd31d-bc6b-4179-b391-7ea3c0ca60ef" />
<img width="2872" height="1828" alt="Screenshot 2026-09-23 115314" src="https://github.com/user-attachments/assets/37982eaf-0b27-4de3-b29b-446dea67e864" />


## What this is

PhishLens extends [Phishing URL Detector](../phishing-url-detector) — instead of a single ML model producing a label, an LLM-driven agent investigates a URL step by step: deciding which tools to call, gathering evidence, and producing a reasoned verdict.

The project's core question, answered empirically rather than assumed:

> **Does giving an LLM agent access to specialized security tools (and an existing ML classifier) actually improve phishing detection over either approach alone?**

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
     └──────────┴────────┼────────┴──────────┘
                         ▼
                  Evidence Store (SQLite)
                         │
                         ▼
                Investigation Report
             (verdict + evidence + timeline)
```

## Evaluation

Four systems are compared on a frozen, held-out set of URLs:

| System | Description |
|---|---|
| S1 — ML only | Existing XGBoost classifier |
| S2 — LLM only | Qwen3 8B, no tools |
| S3 — Agent + tools | No ML classifier access |
| S4 — Agent + tools + ML | Full system (this project's contribution) |

Results will be added to this README once the evaluation harness (Week 3) is complete. See `evaluation/manifest.json` for dataset provenance.

## Setup

```bash
ollama pull qwen3:8b
pip install -r requirements.txt
streamlit run dashboard/app.py
```

## What's explicitly NOT in v1

- WHOIS / domain-age lookups
- Certificate transparency checks
- Screenshot analysis
- Multi-agent orchestration

These may be added in a future phase, but v1 ships as a complete, evaluated system with the five tools above.

## Project progression

1. [Phishing URL Detector](../phishing-url-detector) — ML classification
2. [FLUTE Broadcast Platform](../flute-broadcast-platform) — networking / Rust / systems
3. **PhishLens** (this repo) — AI agents / tool use / evaluation
