"""
docker/fetcher/fetch.py — runs INSIDE the container, never on the host.

Does exactly one thing: GET a URL, print the response text to stdout.
Never executes anything from the fetched page. Errors go to stderr with
a non-zero exit code, so the host side can distinguish success/failure.
"""

import sys

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def main():
    if len(sys.argv) < 2:
        sys.stderr.write("ERROR: no URL provided\n")
        sys.exit(1)

    url = sys.argv[1]
    try:
        resp = requests.get(
            url,
            timeout=10,
            verify=False,  # phishing infra often has broken/self-signed certs
            headers={"User-Agent": "PhishLens-sandboxed-fetcher/0.1 (student project)"},
        )
        sys.stdout.write(resp.text)
    except Exception as e:
        sys.stderr.write(f"FETCH_ERROR: {type(e).__name__}: {e}\n")
        sys.exit(1)


if __name__ == "__main__":
    main()
