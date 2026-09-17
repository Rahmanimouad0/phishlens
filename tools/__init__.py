# PhishLens tools package.
#
# Planned tools (Week 1-2):
#   analyze_url()        - pure-Python URL/domain heuristics (Week 1)
#   run_phishing_model()  - wraps the existing XGBoost classifier (Week 2)
#   analyze_html()        - fetches (sandboxed, Docker) + parses page HTML (Week 2)
#   check_dns()            - DNS record lookups (types/TTL/anomalies only -
#                             NOT domain age, that's WHOIS data, out of scope for v1)
#   extract_links()        - outbound links found in parsed HTML (Week 2)
