from urllib.parse import urlparse

# ── Suspicious keyword lists ──────────────────────────────────────────────────

MALWARE_KEYWORDS = {
    # Malware families / types
    "malware", "exploit", "payload", "backdoor", "dropper", "ransomware",
    "trojan", "keylogger", "botnet", "rootkit", "spyware", "adware",
    "virus", "worm", "stager", "shellcode", "c2", "cnc", "command-and-control",
    # Phishing
    "phish", "phishing", "credential", "login-steal", "harvest",
    # Attack terminology
    "inject", "overflow", "rop-chain", "heap-spray", "spray",
    # Distribution
    "download", "downloader", "loader", "install", "setup", "update",
    # Obfuscation signals
    "obfuscate", "encode", "base64", "powershell", "cmd",
}

# TLDs that are inherently not real / commonly abused in test or sinkhole infra
SUSPICIOUS_TLDS = {".test", ".local", ".invalid", ".example", ".onion"}


def analyze_url(url: str) -> dict:
    """
    Parses a URL to flag potentially suspicious structures.
    Checks: scheme, subdomain depth, domain length, keyword presence in
    domain/path/query, and suspicious TLDs.
    """
    result = {
        "scheme": None,
        "domain": None,
        "path": None,
        "query": None,
        "suspicious_flags": []
    }

    try:
        parsed = urlparse(url)
        result["scheme"] = parsed.scheme
        result["domain"] = parsed.netloc
        result["path"] = parsed.path
        result["query"] = parsed.query

        # --- Scheme check ---
        if parsed.scheme and parsed.scheme.lower() not in ("https",):
            result["suspicious_flags"].append("Not using HTTPS protocol.")

        if parsed.netloc:
            domain_lower = parsed.netloc.lower()

            # --- Subdomain depth ---
            domain_parts = domain_lower.split(".")
            if len(domain_parts) > 4:
                result["suspicious_flags"].append("Unusually high number of subdomains.")

            # --- Domain length ---
            if len(parsed.netloc) > 50:
                result["suspicious_flags"].append("Domain length unusually long.")

            # --- Suspicious TLD ---
            for tld in SUSPICIOUS_TLDS:
                if domain_lower.endswith(tld):
                    result["suspicious_flags"].append(
                        f"Suspicious TLD '{tld}' — not a real public domain."
                    )
                    break

            # --- Malware keywords in domain ---
            for kw in MALWARE_KEYWORDS:
                if kw in domain_lower:
                    result["suspicious_flags"].append(
                        f"Malware-related keyword '{kw}' found in domain."
                    )
                    break

        # --- Malware keywords in path + query ---
        path_query = (parsed.path + "?" + parsed.query).lower() if parsed.query else parsed.path.lower()
        matched_path_kws = [kw for kw in MALWARE_KEYWORDS if kw in path_query]
        if matched_path_kws:
            result["suspicious_flags"].append(
                f"Malware-related keyword(s) [{', '.join(matched_path_kws[:3])}] found in URL path."
            )

        # --- IP address as host (no domain, direct IP) ---
        import re
        if parsed.netloc and re.match(r"^\d{1,3}(\.\d{1,3}){3}(:\d+)?$", parsed.netloc):
            result["suspicious_flags"].append(
                "URL uses a raw IP address instead of a domain — common in C2 and phishing."
            )

    except Exception as e:
        result["error"] = f"Failed to parse URL: {str(e)}"

    return result
