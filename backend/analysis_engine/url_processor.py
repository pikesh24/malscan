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

# The subset of the above that names an ordinary infrastructure function as well
# as a malware capability. In a HOSTNAME these carry almost no signal — vendors
# name distribution hosts exactly this way (downloads.claude.ai,
# download.mozilla.org, downloads.apache.org, cdn.…/loader.js) — so they are
# scored as a weak flag rather than at full keyword weight. In a path they were
# already treated as ordinary; this applies the same judgement to the domain.
INFRASTRUCTURE_KEYWORDS = {
    "download", "downloader", "loader", "encode", "base64", "powershell",
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

# Other domains the same organisations genuinely operate. The substring test in
# _check_typosquatting cannot tell "brand name inside an attacker's domain" from
# "brand name inside the brand's own other domain", and it got the second badly
# wrong: login.microsoftonline.com — where every Microsoft 365 user signs in —
# was reported as impersonating microsoft.com, and every AWS S3 URL was reported
# as impersonating amazon.com.
BRAND_OWNED_DOMAINS = {
    # Google
    "googleapis.com", "gstatic.com", "googleusercontent.com", "ggpht.com",
    "googlevideo.com", "google.co.in", "goo.gl", "withgoogle.com",
    # Microsoft
    "microsoftonline.com", "live.com", "msn.com", "office.com", "office365.com",
    "outlook.com", "sharepoint.com", "windows.net", "azure.com", "bing.com",
    "msftauth.net", "microsoft.co.in",
    # Amazon
    "amazonaws.com", "awsstatic.com", "amazon.in", "media-amazon.com",
    "ssl-images-amazon.com", "primevideo.com",
    # Meta
    "fbcdn.net", "fb.com", "messenger.com", "facebook.net", "instagram.co",
    # Apple
    "icloud.com", "apple.news", "mzstatic.com",
    # Others in the brand list above
    "paytmbank.com", "paytmmall.com", "phonepe.in", "flipkart.net",
    "twimg.com", "licdn.com", "netflix.net", "nflxvideo.net",
}

# Second-level labels used by country registries ("co" in .co.in, "com" in
# .com.au), so the registrable label of amazon.co.uk is "amazon", not "co".
_SLD_SUFFIXES = {"co", "com", "net", "org", "gov", "edu", "ac", "or", "ne", "in"}


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

    # Other domains the same brands genuinely own. A brand's name appearing in a
    # domain is not impersonation when the brand owns that domain too, and the
    # substring test below cannot tell the difference:
    # login.microsoftonline.com is where every Microsoft 365 user signs in, and
    # it was reported as impersonating microsoft.com.
    if any(d == alt or d.endswith("." + alt) for alt in BRAND_OWNED_DOMAINS):
        return None

    # An established site is not a lookalike of another site — it is itself.
    # Spelling cannot separate telegraph.co.uk (a newspaper, one edit from
    # telegram.org) or wetter.com (German weather, two from twitter.com) or
    # google-analytics.com (Google's own, "google" as a token) from paypa1.com.
    # Traffic can. This replaces hand-maintaining BRAND_OWNED_DOMAINS entry by
    # entry, which was already three lists deep.
    #
    # It only ever suppresses the impersonation flag. Nothing here says the site
    # is safe — a popular domain can be compromised, and threat intel, not
    # reputation, is what decides that.
    try:
        from analysis_engine.public_suffix import is_established_domain
        if is_established_domain(d):
            return None
    except Exception:
        pass

    # The registrable label, i.e. "amazon" from "amazon.in". A brand operating on
    # another TLD is still the brand — amazon.in is Amazon India, google.co.in is
    # Google India. Comparing whole domains missed this and flagged both.
    labels = d.split(".")
    d_label = labels[0] if len(labels) < 3 else labels[-2 if labels[-2] not in _SLD_SUFFIXES else -3]

    # Tokens of everything except the public suffix. Dropping the suffix keeps
    # Amazon's own ".amazon" TLD from reading as the word "amazon" in someone
    # else's domain, while still covering a brand pushed into a SUBDOMAIN of an
    # unrelated registrable domain — "google.com.evil.tk", "paypal.com.login.ml"
    # — which is a standard phishing shape and lives outside the label.
    # Anything reaching here has already failed the brand-owned and
    # same-registrable-domain checks above, so the registrant is a stranger.
    try:
        from analysis_engine.public_suffix import public_suffix as _ps
        suffix = _ps(d)
        stem = d[: -(len(suffix) + 1)] if suffix and d.endswith(suffix) and d != suffix else d
    except Exception:
        stem = d
    label_tokens = set(re.split(r"[-_.]", stem))

    for brand in BRAND_DOMAINS:
        brand_host = brand.split(".")[0]  # e.g. "hdfcbank" from "hdfcbank.com"

        if len(brand_host) < 3:
            continue

        # Same brand on a different TLD — the label IS the brand, nothing added.
        if d_label == brand_host:
            return None

        # A short brand as a standalone token is safe and necessary: "sbi" is
        # three characters, so the old `len < 5` skip meant SBI — India's largest
        # bank, and a constant phishing target — could never be detected at all,
        # and "sbi-netbanking-verify.tk" scored nothing. As a token this is
        # precise: SBI's real "onlinesbi.com" tokenises to {"onlinesbi"} and does
        # not match, while "sbi-netbanking-verify" does.
        if brand_host in label_tokens:
            return brand

        # Near-miss spelling still needs length behind it. At three characters
        # almost every short word is within one edit of every other.
        if len(brand_host) < 5:
            continue

        # Near-miss spelling. The allowance scales with length: at a flat 2, a
        # third of a six-letter word could differ and ordinary words collided —
        # "moodle" vs "google", "media" vs "india", "applvn" vs "apple" are all
        # two edits apart, and all three are real sites in the Tranco top 10,000.
        # One edit on a short name, two once there is enough word to be sure.
        allowed = 1 if len(brand_host) <= 6 else 2
        if len(d_label) > 3 and _levenshtein(d_label, brand_host) <= allowed:
            return brand

        # Brand name used as a WORD inside the label — "hdfcbank-secure",
        # "amazon-security-alert", "microsoft-login". Requiring a token boundary
        # is what separates those from "googledomains.com", which is Google's own
        # registrar and where a bare substring test saw "google" and flagged it.
        if brand_host in label_tokens:
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
    "keyword_domain_weak": 5,   # "downloads.<vendor>" is a distribution host, not a threat
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
            # Split by how much the word actually discriminates. "trojan" or
            # "phishing" in a hostname is genuinely odd; "download" is how nearly
            # every vendor names a distribution host — downloads.claude.ai,
            # download.mozilla.org, downloads.apache.org. Scoring those the same
            # made being a normal software publisher look suspicious, which is
            # the same conclusion that already put keyword_path at 5.
            for kw in MALWARE_KEYWORDS:
                if kw in domain_lower:
                    weak = kw in INFRASTRUCTURE_KEYWORDS
                    flag(
                        "keyword_domain_weak" if weak else "keyword_domain",
                        f"Threat-related keyword '{kw}' in domain name."
                        + (" (common in legitimate distribution hosts.)" if weak else ""),
                    )
                    break

            # ── Homoglyph substitution heuristic ──────────────────────────────
            homoglyphs = {"0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "rn": "m"}
            normalised = domain_lower
            for fake, real in homoglyphs.items():
                normalised = normalised.replace(fake, real)
            # Only when the substitution is what created the resemblance. The
            # AWS host s3.dualstack.us-east-1.amazonaws.com collected this flag
            # on top of the plain typosquat flag — 35+35 — because normalising
            # "3" and "1" elsewhere in the string left "amazon" still matching.
            # Two flags for one observation is double-counting.
            if normalised != domain_lower and not impersonated:
                # Substituting the look-alikes turns the domain INTO a brand:
                # "g00gle.com" -> "google.com". That exact landing is the whole
                # signature of a homoglyph attack, and it used to be missed —
                # _check_typosquatting returns None for an exact brand match, so
                # asking it about the normalised form answered "this is Google".
                # The near-miss path caught g00gle only by accident, at
                # Levenshtein distance 2, and that allowance is now too tight.
                norm_bare = normalised.removeprefix("www.")
                if any(norm_bare == b or norm_bare.endswith("." + b) for b in BRAND_DOMAINS):
                    flag(
                        "typosquat",
                        f"Domain uses look-alike characters to impersonate "
                        f"'{norm_bare}' (e.g. 0→o, 1→l).",
                    )
                else:
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
