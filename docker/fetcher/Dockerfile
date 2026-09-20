# Minimal, single-purpose image: fetch one URL, print its HTML, exit.
# No other tools, no shell access needed for the agent's purposes,
# nothing persisted between runs (the container is always run with --rm).
FROM python:3.11-slim

RUN pip install --no-cache-dir requests

COPY fetch.py /fetch.py

ENTRYPOINT ["python", "/fetch.py"]
