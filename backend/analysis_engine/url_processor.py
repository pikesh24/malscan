"""
analysis_engine/url_processor.py

URL and domain analysis — heuristic scoring for suspicious links.
No external dependencies.
"""

import re
from urllib.parse import urlparse, unquote

# ── Keyword lists ─────────────────────────────────────────────────────────────

MALWARE_KEYWORDS = {
    "malware", "exploit", "payload", "backdoor", "dropper", "ransomware",
    "trojan", "keylogger", "botnet", "rootkit", "spyware", "adware",
    "virus", "worm", "stager", "shellcode", "c2", "cnc", "command-and-control",
    "phish", "phishing", "credential", "login-steal", "harvest",
    "inject", "overflow", "rop-chain", "heap-spray",
    "download", "downloader", "loader",
    "obfuscate", "encode", "base64", "powershell",
}

# ── Suspicious TLDs (commonly abused for malware, phishing, spam) ─────────────

SUSPICIOUS_TLDS = {
    # Free/abused ccTLDs
    ".tk", ".ml", ".ga", ".cf", ".gq",
    # Common in malware campaigns
    ".xyz", ".top", ".club", ".work", ".click", ".link", ".online",
    ".site", ".space", ".tech", ".shop", ".store", ".icu", ".live",
    # Test/reserved
    ".test", ".local", ".invalid", ".example", ".onion",
    # Others frequently seen in phishing
    ".pw", ".cc", ".su", ".to", ".ws", ".biz",
}

# ── URL shorteners (need expanding before analysis) ───────────────────────────

URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "buff.ly",
    "adf.ly", "tiny.cc", "is.gd", "v.gd", "cutt.ly", "rb.gy",
    "shorturl.at", "tr.im", "snip.ly", "t.me", "wa.me",
    "youtu.be",   # YouTube short URLs are fine but flag for awareness
}

# ── Top brand domains for typosquatting detection ─────────────────────────────

BRAND_DOMAINS = {
    # Global
    "google.com", "youtube.com", "youtu.be", "facebook.com", "instagram.com",
    "twitter.com", "x.com", "linkedin.com", "amazon.com", "microsoft.com",
    "apple.com", "netflix.com", "paypal.com", "ebay.com", "dropbox.com",
    "whatsapp.com", "telegram.org", "signal.org",
    # Indian banks
    "sbi.co.in", "hdfcbank.com", "icicibank.com", "axisbank.com",
    "bankofbaroda.in", "pnbindia.in", "canarabank.com",
    # Indian fintech / UPI
    "paytm.com", "phonepe.com", "razorpay.com", "gpay.app",
    # Indian government
    "incometax.gov.in", "mca.gov.in", "uidai.gov.in", "npci.org.in",
    "india.gov.in", "irctc.co.in", "epfindia.gov.in",
    # Indian e-commerce
    "flipkart.com", "myntra.com", "snapdeal.com", "meesho.com",
}


def _levenshtein(a: str, b: str) -> int:
    """O(m*n) edit distance — fast enough for short domain names."""
    m, n = len(a), len(b)
    dp = list(range(n + 1))
    for i in range(1, m + 1):
        prev, dp[0] = dp[0], i
        for j in range(1, n + 1):
            temp = dp[j]
            dp[j] = prev if a[i - 1] == b[j - 1] else 1 + min(prev, dp[j], dp[j - 1])
            prev = temp
    return dp[n]


def _check_typosquatting(domain: str) -> str | None:
    """
    Returns the brand being impersonated if this domain looks like a typosquat,
    or None if it's clean.
    """
    # Strip www. prefix
    d = domain.lower().removeprefix("www.")

    # It IS the brand — either exactly, or a subdomain of it. A subdomain can
    # only be created by whoever controls the domain, so netbanking.hdfcbank.com
    # and mail.google.com are the real thing, not impersonations of it. Matching
    # on the substring alone (below) reported every brand subdomain as phishing,
    # which is worst exactly where it matters most: real bank and government
    # login pages.
    #
    # Deliberately anchored to the end. "hdfcbank.com.evil.tk" does not end with
    # ".hdfcbank.com", so genuine lookalikes are still caught below.
    if any(d == brand or d.endswith("." + brand) for brand in BRAND_DOMAINS):
        return None

    for brand in BRAND_DOMAINS:
        brand_host = brand.split(".")[0]  # e.g. "hdfcbank" from "hdfcbank.com"
        d_host     = d.split(".")[0]

        # Skip if brand is very short (too many false positives)
        if len(brand_host) < 5:
            continue

        # Levenshtein distance ≤ 2 on the hostname part
        if len(d_host) > 3 and _levenshtein(d_host, brand_host) <= 2:
            return brand

        # Brand name appears inside a longer domain (e.g. hdfcbank-secure.com)
        if brand_host in d and d != brand:
            return brand

    return None


# ── Flag weights ──────────────────────────────────────────────────────────────
# Every flag used to be worth a flat +20, which is wrong in both directions.
# Plain http is near-universal among harmless sites, so it dragged legitimate
# pages toward Suspicious in pairs; meanwhile a brand lookalike — rare, specific,
# and the single most useful phishing signal we have — could not reach the
# 35-point threshold on its own, so paypa1.com read as Clear.
#
# Weight is discriminative power, not how alarming the wording sounds: roughly
# how much more often the flag fires on something malicious than on something
# harmless. Values below are reasoned, not yet measured — the benign base-rate
# run (docs/TESTING.md, layer 3) is what turns them into evidence.
FLAG_WEIGHTS = {
    "typosquat":      35,   # rare and specific; enough alone to warrant a warning
    "raw_ip":         20,
    "dangerous_ext":  15,
    # An executable over https from a known vendor is ordinary; the same file over
    # plain http can be swapped in transit and cannot be verified on arrival. The
    # danger is the combination, so it is scored as its own signal rather than by
    # inflating either half.
    "http_executable": 15,
    "keyword_domain": 15,
    "long_domain":    10,
    "deep_subdomain": 10,   # legitimate multi-level CDN hosts do this too
    "shortener":      10,   # hides the destination; not evidence of malice
    "abused_tld":      5,   # .shop/.store/.online are mainstream commercial TLDs
    "not_https":       5,   # extremely common on harmless sites
    "keyword_path":    5,   # "/downloads/", "/base64-encoder" are ordinary paths
    "url_encoding":    5,   # signed CDN and S3 URLs are full of %-escapes
}

_DEFAULT_FLAG_WEIGHT = 20


def analyze_url(url: str) -> dict:
    """
    Heuristic analysis of a URL.

    Returns 'suspicious_flags' (human-readable, rendered in the report) and a
    parallel 'flag_weights' the scorer consumes. They are kept as two lists
    rather than one list of pairs so the report-facing shape is unchanged.
    """
    result = {
        "scheme": None, "domain": None, "path": None, "query": None,
        "suspicious_flags": [], "flag_weights": [],
    }

    if not url:
        return result

    try:
        parsed = urlparse(unquote(url))
        result["scheme"] = parsed.scheme
        result["domain"] = parsed.netloc
        result["path"]   = parsed.path
        result["query"]  = parsed.query

        flags = result["suspicious_flags"]

        def flag(kind: str, message: str):
            flags.append(message)
            result["flag_weights"].append(FLAG_WEIGHTS.get(kind, _DEFAULT_FLAG_WEIGHT))

        # ── Scheme ────────────────────────────────────────────────────────────
        if parsed.scheme and parsed.scheme.lower() not in ("https",):
            flag("not_https", "Not using HTTPS — connection is unencrypted.")

        if parsed.netloc:
            domain_lower = parsed.netloc.lower().split(":")[0]  # strip port

            # ── Raw IP as host ─────────────────────────────────────────────────
            if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", domain_lower):
                flag(
                    "raw_ip",
                    "URL uses a raw IP address instead of a domain — common in C2 and phishing.",
                )

            # ── Suspicious TLD ─────────────────────────────────────────────────
            for tld in SUSPICIOUS_TLDS:
                if domain_lower.endswith(tld):
                    flag("abused_tld", f"Suspicious domain extension '{tld}' — heavily abused in malware campaigns.")
                    break

            # ── URL shortener ──────────────────────────────────────────────────
            bare = domain_lower.removeprefix("www.")
            if bare in URL_SHORTENERS:
                flag(
                    "shortener",
                    f"URL shortener detected ({bare}) — hides the real destination, common in phishing.",
                )

            # ── Typosquatting ──────────────────────────────────────────────────
            impersonated = _check_typosquatting(domain_lower)
            if impersonated:
                flag(
                    "typosquat",
                    f"Domain appears to impersonate '{impersonated}' — possible phishing site.",
                )

            # ── Excessive subdomains ───────────────────────────────────────────
            parts = domain_lower.split(".")
            if len(parts) > 5:
                flag("deep_subdomain", "Unusually deep subdomain structure — common evasion technique.")

            # ── Very long domain ───────────────────────────────────────────────
            if len(domain_lower) > 60:
                flag("long_domain", "Excessively long domain name — may be generated or obfuscated.")

            # ── Malware keywords in domain ─────────────────────────────────────
            for kw in MALWARE_KEYWORDS:
                if kw in domain_lower:
                    flag("keyword_domain", f"Threat-related keyword '{kw}' in domain name.")
                    break

            # ── Homoglyph substitution heuristic ──────────────────────────────
            homoglyphs = {"0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "rn": "m"}
            normalised = domain_lower
            for fake, real in homoglyphs.items():
                normalised = normalised.replace(fake, real)
            if normalised != domain_lower:
                imp2 = _check_typosquatting(normalised)
                if imp2:
                    flag(
                        "typosquat",
                        f"Domain uses look-alike characters to impersonate '{imp2}' (e.g. 0→o, 1→l).",
                    )

        # ── Path + query analysis ──────────────────────────────────────────────
        path_query = ((parsed.path or "") + "?" + (parsed.query or "")).lower()
        matched = [kw for kw in MALWARE_KEYWORDS if kw in path_query]
        if matched:
            flag("keyword_path", f"Threat-related keyword(s) in URL path: {', '.join(matched[:3])}")

        # ── Suspicious file extension in URL ───────────────────────────────────
        dangerous_exts = (".exe", ".dll", ".bat", ".ps1", ".vbs", ".js", ".scr", ".hta", ".msi")
        path_lower = parsed.path.lower()
        for ext in dangerous_exts:
            if path_lower.endswith(ext):
                flag("dangerous_ext", f"URL points directly to a potentially dangerous file type ({ext}).")
                # Downloading an executable over an unencrypted connection is
                # dangerous in a way neither fact is alone: the file can be
                # swapped in transit and there is no way to tell on arrival.
                if (parsed.scheme or "").lower() != "https":
                    flag(
                        "http_executable",
                        "Executable is served over an unencrypted connection — the file can be "
                        "replaced in transit and cannot be verified.",
                    )
                break

        # ── Encoded characters hiding content ──────────────────────────────────
        if url.count("%") > 10:
            flag("url_encoding", "High number of URL-encoded characters — may be hiding malicious content.")

    except Exception as e:
        result["error"] = f"Failed to parse URL: {e}"

    return result
