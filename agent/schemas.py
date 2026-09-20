"""
agent/schemas.py — pydantic schemas for validating LLM output.

Two things get validated before they're trusted:
1. Tool call ARGUMENTS, before a tool actually runs. Ollama already
   structures tool_calls for us, but a flaky local model can still emit
   malformed args (missing the "url" key, wrong type, etc.) -- this
   catches that before it reaches the tool function and crashes.
2. The FINAL VERDICT, extracted via a dedicated JSON-schema-constrained
   call (see agent/investigate.py) so downstream code (logging, the
   evaluation harness, the dashboard) never has to regex-parse free text.
"""

from typing import Literal

from pydantic import BaseModel, field_validator


class URLToolArgs(BaseModel):
    """Every tool in this project takes exactly one argument: a URL."""
    url: str

    @field_validator("url")
    @classmethod
    def not_empty(cls, v):
        if not v or not v.strip():
            raise ValueError("url must not be empty")
        return v


class Verdict(BaseModel):
    verdict: Literal["phishing", "legitimate", "inconclusive"]
    confidence: Literal["low", "medium", "high"]
    evidence: str


VERDICT_JSON_SCHEMA = Verdict.model_json_schema()
