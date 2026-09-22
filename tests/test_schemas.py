"""Unit tests for the pydantic validation in agent/schemas.py."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

import pytest
from pydantic import ValidationError

from agent.schemas import URLToolArgs, Verdict


def test_url_tool_args_valid():
    args = URLToolArgs(url="https://example.com")
    assert args.url == "https://example.com"


def test_url_tool_args_rejects_empty():
    with pytest.raises(ValidationError):
        URLToolArgs(url="")


def test_url_tool_args_rejects_missing():
    with pytest.raises(ValidationError):
        URLToolArgs()


def test_verdict_accepts_valid_values():
    v = Verdict(verdict="phishing", confidence="high", evidence="test")
    assert v.verdict == "phishing"


def test_verdict_rejects_invalid_verdict_value():
    with pytest.raises(ValidationError):
        Verdict(verdict="maybe", confidence="high", evidence="test")


def test_verdict_rejects_invalid_confidence_value():
    with pytest.raises(ValidationError):
        Verdict(verdict="phishing", confidence="super-high", evidence="test")
