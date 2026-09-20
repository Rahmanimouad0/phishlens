"""
tools/dns_check.py — check_dns(): DNS reconnaissance for a URL's domain.

Returns DNS record types and TTLs, and flags structural anomalies
associated with phishing infrastructure -- unusually low TTL or many
rotating A records ("fast-flux" DNS, a technique for evading blocklists
by rapidly changing which IP a domain resolves to).

Does NOT return domain registration/creation date. That is WHOIS data,
a completely different protocol and lookup -- DNS records alone cannot
tell you when a domain was registered. A separate check_whois() tool
would be needed for that and is explicitly out of scope for v1.
"""

from urllib.parse import urlparse

import dns.resolver

FAST_FLUX_TTL_THRESHOLD = 300  # seconds; legitimate sites are typically 3600+


def _safe_query(resolver, domain, record_type):
    try:
        answer = resolver.resolve(domain, record_type)
        return {
            "records": [str(r) for r in answer],
            "ttl": answer.rrset.ttl if answer.rrset else None,
        }
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers):
        return {"records": [], "ttl": None}
    except Exception as e:
        return {"records": [], "ttl": None, "error": f"{type(e).__name__}: {e}"}


def check_dns(url: str) -> dict:
    domain = urlparse(url).netloc.lower().split(":")[0]
    if not domain:
        domain = url.strip().lower()

    resolver = dns.resolver.Resolver()
    resolver.timeout = 5
    resolver.lifetime = 5

    a_result = _safe_query(resolver, domain, "A")
    mx_result = _safe_query(resolver, domain, "MX")
    ns_result = _safe_query(resolver, domain, "NS")
    txt_result = _safe_query(resolver, domain, "TXT")

    a_ttl = a_result.get("ttl")
    low_ttl = a_ttl is not None and a_ttl < FAST_FLUX_TTL_THRESHOLD

    return {
        "domain": domain,
        "resolved": len(a_result["records"]) > 0,
        "a_records": a_result["records"],
        "a_ttl_seconds": a_ttl,
        "unusually_low_ttl": low_ttl,  # possible fast-flux DNS (evasion technique)
        "num_a_records": len(a_result["records"]),
        "many_a_records": len(a_result["records"]) > 4,  # possible fast-flux (rotating IPs)
        "has_mx_records": len(mx_result["records"]) > 0,
        "ns_records": ns_result["records"],
        "has_txt_records": len(txt_result["records"]) > 0,
    }


CHECK_DNS_SCHEMA = {
    "type": "function",
    "function": {
        "name": "check_dns",
        "description": (
            "Look up DNS records for a URL's domain: A records (IPs), TTL, "
            "MX, NS, and TXT records. Flags anomalies associated with "
            "phishing infrastructure, such as unusually low TTL or many "
            "rotating A records ('fast-flux' DNS, used to evade blocklists). "
            "Does NOT provide domain registration/age -- that would require "
            "a separate WHOIS lookup, not available in this tool."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "url": {"type": "string", "description": "The full URL whose domain to check"}
            },
            "required": ["url"],
        },
    },
}
