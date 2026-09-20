"""
agent/llm.py — provider-agnostic LLM interface.

The agent loop (investigate.py) only ever talks to an LLMProvider. To swap
in a different local model, or a hosted API later for comparison, add a new
provider class here and register it in get_provider() — nothing in the
agent loop or tools needs to change.
"""

import json
from dataclasses import dataclass
from typing import Optional

import requests


@dataclass
class ToolCall:
    name: str
    args: dict


@dataclass
class LLMResponse:
    tool_call: Optional[ToolCall] = None
    final_report: Optional[str] = None


class LLMProvider:
    def chat(self, messages: list, tools: list) -> LLMResponse:
        raise NotImplementedError


class OllamaProvider(LLMProvider):
    """Local inference via Ollama's REST API (http://localhost:11434)."""

    def __init__(self, model="qwen3:8b", host="http://localhost:11434"):
        self.model = model
        self.host = host

    def chat(self, messages, tools) -> LLMResponse:
        resp = requests.post(
            f"{self.host}/api/chat",
            json={
                "model": self.model,
                "messages": messages,
                "tools": tools,
                "stream": False,
            },
            timeout=180,  # CPU inference is slow — don't time out mid-response
        )
        resp.raise_for_status()
        data = resp.json()
        message = data["message"]

        tool_calls = message.get("tool_calls")
        if tool_calls:
            # Take one call at a time — simplest pattern to reason about and debug.
            call = tool_calls[0]
            fn = call["function"]
            args = fn["arguments"]
            if isinstance(args, str):
                args = json.loads(args)
            return LLMResponse(tool_call=ToolCall(name=fn["name"], args=args))

        return LLMResponse(final_report=message.get("content", ""))


def get_provider(name="ollama", **kwargs) -> LLMProvider:
    """Single place to switch providers. e.g. get_provider("ollama", model="qwen3:14b")."""
    if name == "ollama":
        return OllamaProvider(**kwargs)
    raise ValueError(f"Unknown provider: {name!r}")
