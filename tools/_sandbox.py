"""
tools/_sandbox.py — shared helper: fetch a URL's HTML inside a disposable
Docker container. Used by both analyze_html() and extract_links().

Also supports an ARCHIVE OVERRIDE for evaluation (Week 3): evaluate.py
preloads this module with a case's archived HTML before running an
investigation, so analyze_html()/extract_links() transparently replay
from disk instead of live-fetching. Neither tool file needs to know or
care -- they always just call fetch_html_sandboxed(url).

Normal usage (run_milestone.py, the future dashboard) sets no override,
so nothing changes there -- it fetches live exactly as before.
"""

import subprocess

DOCKER_IMAGE = "phishlens-fetcher"
HOST_TIMEOUT = 20  # seconds -- generous vs the container's own 10s request timeout

_html_override = {}  # url -> archived html content, set by evaluate.py


def set_archived_html(url: str, html: str):
    """Called by evaluate.py before running a case, so tools replay from disk."""
    _html_override[url] = html


def clear_archived_html():
    """Called by evaluate.py between cases, so overrides never leak across cases."""
    _html_override.clear()


def fetch_html_sandboxed(url: str):
    """Returns (html, error) -- exactly one is truthy."""
    if url in _html_override:
        return _html_override[url], ""

    try:
        result = subprocess.run(
            [
                "docker", "run", "--rm",
                "--memory=256m", "--cpus=0.5",
                "--network", "bridge",
                DOCKER_IMAGE, url,
            ],
            capture_output=True,
            text=True,
            encoding="utf-8",   # Windows defaults to cp1252 otherwise, which
            errors="replace",   # breaks on many real-world pages' characters
            timeout=HOST_TIMEOUT,
        )
    except subprocess.TimeoutExpired:
        return "", "host-side timeout waiting for sandboxed fetch"
    except FileNotFoundError:
        return "", "docker command not found -- is Docker Desktop running?"

    if result.returncode != 0:
        return "", result.stderr.strip() or "unknown fetch error in container"
    if result.stdout is None:
        return "", "subprocess returned no output (capture failed)"
    return result.stdout, ""
