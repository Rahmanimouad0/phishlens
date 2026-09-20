"""
tools/_sandbox.py — shared helper: fetch a URL's HTML inside a disposable
Docker container. Used by both analyze_html() and extract_links(), so the
sandboxing logic lives in exactly one place.

See docker/fetcher/ for what actually runs inside the container.
"""

import subprocess

DOCKER_IMAGE = "phishlens-fetcher"
HOST_TIMEOUT = 20  # seconds -- generous vs the container's own 10s request timeout


def fetch_html_sandboxed(url: str):
    """Returns (html, error) -- exactly one is truthy."""
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
            timeout=HOST_TIMEOUT,
        )
    except subprocess.TimeoutExpired:
        return "", "host-side timeout waiting for sandboxed fetch"
    except FileNotFoundError:
        return "", "docker command not found -- is Docker Desktop running?"

    if result.returncode != 0:
        return "", result.stderr.strip() or "unknown fetch error in container"
    return result.stdout, ""
