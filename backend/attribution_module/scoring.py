"""
attribution_module/scoring.py

calculate_score(analysis_data) is called directly by backend/app/main.py
after the static + OSINT pipeline runs.

Input shape (from main.py):
{
    "static": {
        "suspicious_sections": [{"name": str, "reason": str}],
        "is_pe": bool,
        "imphash": str | None,
    },
    "osint": {
        "whois": {"registrar": str, "creation_date": str, ...},
        "geoip": {"country": str, "countryCode": str, "isp": str, "asn": str},
        "dns":   {"A": [str], "MX": [str], "TXT": [str]},
    },
    "url":  {"domain": str, "suspicious_flags": [str], "flag_weights": [int]},
    "iocs": {"ips": [str], "domains": [str], "urls": [str]},
}

Output shape (stored in ScanJob.results JSON column):
{
    "score":         int (0-100),
    "verdict":       "Malicious" | "Suspicious" | "Clear" | "Inconclusive",
                     # "Inconclusive" = nothing found BUT a verdict-critical intel
                     # source (VirusTotal) did not complete, so absence of findings
                     # cannot be reported as clean. Always paired with partial=True.
                     # Malicious/Suspicious are never downgraded to it.
    "reasons":       [str],
    "indicators":    {"ips": [...], "domains": [...], "urls": [...]},
    "osint_summary": {"registrar", "asn", "country", "hosting", "domain_age_days", "virustotal_detections"},
    "graph_nodes":   [...],
    "graph_edges":   [...],
    "score_breakdown": [{"label": str, "points": int}],
    "risk_profile":    [{"key": str, "label": str, "value": int, "description": str}],
}
"""

from datetime import datetime
from typing import Optional
import logging

logger = logging.getLogger(__name__)

# ── Known-hash blocklist ─────────────────────────────────────────────────────

KNOWN_MALICIOUS_HASHES = {
    # EICAR Standard Antivirus Test File (SHA-256) — real, industry-standard test hash.
    # Live malware hash coverage comes from MalwareBazaar/ThreatFox lookups, not this list.
    "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f": {
        "score": 100,
        "family": "EICAR-Test-File",
        "attribution": "Unattributed",
        "reason": "EICAR standard antivirus test file detected by SHA-256 hash.",
    },
}

# ── Threat intelligence lists ────────────────────────────────────────────────

FLAGGED_REGISTRARS = {
    "namecheap", "namesilo", "reg.ru", "publicdomainregistry",
    "hosting concepts", "planet domains", "internet domain service",
    "pdr ltd", "openprovider",
}

# Providers whose business is shielding abuse — takedown requests go unanswered.
# Genuinely discriminative: almost nothing legitimate is here on purpose.
BULLETPROOF_ASNS = {
    "AS44050",  # Petersburg Internet Network
    "AS206728", # Media Land LLC
    "AS36352",  # ColoCrossing
    "AS8100",   # QuadraNet
}

# Mainstream budget hosting. Abused constantly *because* it is cheap and popular,
# which is exactly why being hosted here says little — OVH and LeaseWeb are among
# Europe's largest providers and carry an enormous amount of ordinary traffic.
# Kept as a weak signal rather than dropped: concentration here is mildly
# informative, it just cannot carry a verdict.
BUDGET_HOSTING_ASNS = {
    "AS16276",  # OVH
    "AS60781",  # LeaseWeb
    "AS51167",  # Contabo
    "AS9009",   # M247
    "AS197695", # Reg.ru
}

SUSPICIOUS_ASNS = BULLETPROOF_ASNS | BUDGET_HOSTING_ASNS  # kept for _build_graph

# Where infrastructure sits is weak evidence and easily misread — see
# _check_geoip for the measurement behind the low weight.
HIGH_RISK_COUNTRIES = {"RU", "KP", "CN", "IR", "BY", "SY"}

# Anycast CDNs and reverse proxies. An IP behind one of these resolves to
# whichever edge node happens to be nearest the lookup, so the "country" is where
# the CDN answered from — not where the site is hosted.
#
# Measured on 237 real popular sites: Canada was the most common country in the
# whole sample at 71, of which 63 were AS13335 (Cloudflare) and 6 AS54113
# (Fastly). None of those sites are Canadian. The report had been stating a
# location it could not know, including for an Indian bank.
ANYCAST_ASNS = {
    "AS13335":  "Cloudflare",
    "AS54113":  "Fastly",
    "AS16509":  "AWS CloudFront",
    "AS20940":  "Akamai",
    "AS16625":  "Akamai",
    "AS15133":  "Edgecast",
    "AS8075":   "Microsoft Azure Front Door",
    "AS13414":  "Twitter",
    "AS54994":  "QUANTIL/CDNetworks",
    "AS139057": "Cloudflare (APAC)",
}


def _anycast_provider(asn_raw: str) -> Optional[str]:
    """The CDN name when an ASN is anycast, else None."""
    if not asn_raw:
        return None
    return ANYCAST_ASNS.get(asn_raw.split()[0].upper())


# ── Helpers ──────────────────────────────────────────────────────────────────

# (format, width of the text it produces). The width is NOT len(fmt): "%Y-%m-%d"
# is 8 characters but formats to 10. Slicing by len(fmt) truncated every date to
# garbage ("2026-07-20" -> "2026-07-"), so no format ever matched and every
# lookup fell through to the year-only fallback below — which measures age from
# 1 January and reported a 5-day-old domain as ~205 days old. That silently
# disabled domain-age scoring for most of each year, losing the strongest
# phishing signal we have. Truncation is still deliberate: it drops trailing
# timezone offsets and fractional seconds that WHOIS records often carry.
_DATE_FORMATS = (
    ("%Y-%m-%d %H:%M:%S", 19),
    ("%Y-%m-%dT%H:%M:%S", 19),
    ("%Y-%m-%d", 10),
)


def _parse_age_days(creation_date_str) -> Optional[int]:
    if not creation_date_str:
        return None
    try:
        if isinstance(creation_date_str, list):
            creation_date_str = creation_date_str[0]
        ds = str(creation_date_str).strip()
        for fmt, width in _DATE_FORMATS:
            try:
                created = datetime.strptime(ds[:width], fmt)
                return (datetime.utcnow() - created).days
            except ValueError:
                continue
        # Last resort for records that carry only a year. Deliberately kept, but
        # it can only ever overstate age (never understate it), so a domain is
        # never wrongly scored as new because of it.
        year = int(ds[:4])
        return (datetime.utcnow() - datetime(year, 1, 1)).days
    except Exception:
        return None


def _build_graph(iocs: dict, geoip: dict, whois: dict):
    nodes, edges = {}, []

    def add_node(nid, label, ntype, risk="neutral"):
        if nid and nid not in nodes:
            nodes[nid] = {"id": nid, "label": label, "type": ntype, "risk": risk}

    add_node("artifact", "Artifact", "artifact", "high")

    for ip in (iocs.get("ips") or [])[:8]:
        add_node(ip, ip, "ip", "high")
        edges.append({"source": "artifact", "target": ip, "relationship": "connects_to"})

    for domain in (iocs.get("domains") or [])[:6]:
        add_node(domain, domain, "domain", "medium")
        edges.append({"source": "artifact", "target": domain, "relationship": "references"})

    asn_raw = geoip.get("asn") or geoip.get("as") or ""
    if asn_raw:
        asn_id = asn_raw.split()[0]
        add_node(asn_id, asn_raw, "asn", "neutral")
        for ip in (iocs.get("ips") or [])[:8]:
            edges.append({"source": ip, "target": asn_id, "relationship": "hosted_in_asn"})

    country_code = (geoip.get("countryCode") or geoip.get("country_code") or "").upper()
    if country_code:
        risk = "high" if country_code in HIGH_RISK_COUNTRIES else "neutral"
        add_node(country_code, geoip.get("country", country_code), "country", risk)
        if asn_raw:
            edges.append({"source": asn_raw.split()[0], "target": country_code, "relationship": "located_in"})

    registrar = whois.get("registrar") or ""
    if registrar:
        reg_id = "reg_" + registrar[:20].replace(" ", "_")
        is_flagged = any(f in registrar.lower() for f in FLAGGED_REGISTRARS)
        add_node(reg_id, registrar[:35], "registrar", "high" if is_flagged else "neutral")
        for domain in (iocs.get("domains") or [])[:6]:
            edges.append({"source": domain, "target": reg_id, "relationship": "registered_with"})

    return list(nodes.values()), edges


# ── Risk profile (radar chart) ───────────────────────────────────────────────
# Every score_breakdown label maps to exactly one of these five axes.

RISK_AXES = [
    {
        "key": "file_reputation",
        "label": "File Reputation",
        "description": "How this file scores against known-malware hash lists and its own static structure (type mismatches, suspicious strings).",
    },
    {
        "key": "network_reputation",
        "label": "Network Reputation",
        "description": "How the IPs, domains, and URLs this artifact talks to are rated by threat-intel feeds and multi-vendor scanners like VirusTotal.",
    },
    {
        "key": "hosting_risk",
        "label": "Hosting Risk",
        "description": "How risky the underlying infrastructure is — registrar reputation and the ASN/ISP any network indicators are hosted behind.",
    },
    {
        "key": "behavioral_signals",
        "label": "Behavioral Signals",
        "description": "Signs of active malicious behavior — YARA pattern matches, packed/encrypted PE sections, macros or scripts, dangerous app permissions.",
    },
    {
        "key": "domain_age_risk",
        "label": "Domain Age Risk",
        "description": "How newly registered any associated domain is — brand-new domains are disproportionately used in phishing and malware campaigns.",
    },
]

_LABEL_TO_AXIS = {
    "Known Malicious Hash Match":               "file_reputation",
    "MalwareBazaar Hash Match":                 "file_reputation",
    "File Structure Analysis":                  "file_reputation",
    "YARA Rule Matches":                        "behavioral_signals",
    "PE Section Entropy":                       "behavioral_signals",
    "Document Threat Analysis":                 "behavioral_signals",
    "APK Permissions":                          "behavioral_signals",
    # What a shortcut would execute is a statement about behaviour, not about
    # the file's reputation or where it is hosted.
    "Shortcut Command Line":                    "behavioral_signals",
    "HTML Attachment":                          "behavioral_signals",
    "ThreatFox IOC Match":                      "network_reputation",
    "URLhaus Malware Distribution":             "network_reputation",
    "AbuseIPDB Abuse Confidence":               "network_reputation",
    "VirusTotal Consensus":                     "network_reputation",
    "Benign VirusTotal Consensus (reduction)":  "network_reputation",
    "URLScan Verdict":                          "network_reputation",
    # The reputation of hosts the page pulls content from is still a statement
    # about network infrastructure, just one hop out from the domain itself.
    "Resource Chain":                           "network_reputation",
    "IOC Volume":                               "network_reputation",
    "URL Anomalies":                            "network_reputation",
    "Registrar Reputation":                     "hosting_risk",
    "Hosting / ASN Risk":                       "hosting_risk",
    "Domain Age Risk":                          "domain_age_risk",
    # Reductions belong on the axis they pull down, so the radar reflects the
    # same arithmetic the score-composition bars show. Without an entry here a
    # reduction still renders as a bar but silently vanishes from the radar —
    # test_every_emitted_label_has_an_axis guards that from drifting again.
    "Weak-IOC Corroboration Cap":               "network_reputation",
}


def _build_risk_profile(score_breakdown: list) -> list:
    totals = {axis["key"]: 0 for axis in RISK_AXES}
    for entry in score_breakdown:
        axis_key = _LABEL_TO_AXIS.get(entry["label"])
        if axis_key:
            totals[axis_key] += entry["points"]
    return [
        {
            "key":         axis["key"],
            "label":       axis["label"],
            "description": axis["description"],
            "value":       max(0, min(100, totals[axis["key"]])),
        }
        for axis in RISK_AXES
    ]


# ── Scoring checks ───────────────────────────────────────────────────────────

def _check_pe_sections(static):
    score, reasons = 0, []
    for s in (static.get("suspicious_sections") or []):
        score += 15
        reasons.append(f"High-entropy PE section '{s.get('name','?')}': {s.get('reason','')}")
    return min(score, 30), reasons


def _check_domain_age(whois):
    """Newly registered domains really are disproportionately malicious.

    Unlike the registrar and hosting checks, these weights are NOT measured. The
    Tranco base-rate sample cannot say anything useful here: it contains zero
    domains under 90 days old and its median age is 19.6 years, because a
    week-old legitimate business is by definition not among the world's most
    popular sites. Measuring this needs a source of newly-registered domains
    with known-good labels, which we do not have.

    So the change here is structural rather than empirical: no single piece of
    *contextual* evidence should reach "Suspicious" on its own. Age is a fact
    about a domain's paperwork, not about the artifact, and every legitimate
    business looks exactly like this on its first day. At 40 it cleared the
    35-point threshold unaided and flagged every new company. At 30 it still
    dominates the infrastructure signals and reaches Suspicious the moment
    anything corroborates it.
    """
    score, reasons, age = 0, [], None
    age = _parse_age_days(whois.get("creation_date"))
    if age is not None:
        if age <= 7:
            score, msg = 30, f"Domain registered only {age} day(s) ago — extremely new, high phishing risk."
        elif age <= 30:
            score, msg = 20, f"Domain is newly registered ({age} days old)."
        elif age <= 90:
            score, msg = 10, f"Domain is relatively young ({age} days old)."
        else:
            msg = None
        if score:
            reasons.append(msg)
    return score, reasons, age


def _check_registrar(whois):
    """Reports the registrar as context. Deliberately scores nothing.

    Measured against a pinned sample of the Tranco top 10,000
    (tests/live/base_rates.py): this check fired on 6.8% of them, every hit
    Namecheap — one of the largest registrars in the world. The list is also
    incoherent as a signal: Namecheap appears 11 times in the sample and is
    flagged, GoDaddy appears 16 times and is not, though it is larger and at
    least as abused. Flagging one and not the other tracks nothing real.

    Registrar choice barely correlates with intent at this granularity — big
    registrars sell to everyone — so it cannot carry points. It stays in the
    report because an analyst reading a throwaway-domain case still wants to see
    it; suppressing the score is not a reason to suppress the fact.
    """
    reasons = []
    registrar = (whois.get("registrar") or "").lower()
    for flagged in FLAGGED_REGISTRARS:
        if flagged in registrar:
            reasons.append(
                f"Registrar '{whois.get('registrar')}' is popular with throwaway phishing "
                f"domains — and with a great many legitimate ones, so on its own it means little."
            )
            break
    return 0, reasons


def _check_geoip(geoip):
    """Hosting signals, weighted from measurement rather than from how bad they sound.

    tests/live/base_rates.py enriched a pinned sample of the Tranco top 10,000
    and ran these very checks against the results:

      - the country check fired on 8.3% of them — Alibaba Cloud CDN, Selectel,
        NGENIX. One popular legitimate site in twelve.
      - worse, 39 of 141 geolocated to Canada, which is not where they are:
        those are Cloudflare anycast edges. For anything behind a CDN — most of
        the modern web — this field describes an edge node, not the host. So the
        signal is both common among benign sites and frequently measuring the
        wrong thing. It survives only as a faint corroborator.

    The ASN list mixed two different things. Bulletproof providers exist to
    ignore abuse reports, and almost nothing legitimate is there on purpose.
    OVH, LeaseWeb and Contabo are mainstream budget hosts, abused *because* they
    are cheap and popular, which is exactly why being on one says little.

    Caveat kept visible: the sample is popular sites, which sit behind Cloudflare
    and Akamai rather than budget hosts, and small businesses live in the long
    tail. So these rates are LOWER bounds on how often the checks fire on
    harmless sites — an argument for smaller weights, not larger.
    """
    score, reasons = 0, []
    cc = (geoip.get("countryCode") or geoip.get("country_code") or "").upper()
    asn_raw = (geoip.get("asn") or geoip.get("as") or "")
    isp = (geoip.get("isp") or "").lower()

    # Behind an anycast CDN the country field describes an edge node, so it is
    # not evidence of anything and must not be stated as the host's location.
    cdn = _anycast_provider(asn_raw)
    if cdn:
        reasons.append(
            f"Served through {cdn}, so the origin server's location and hosting are "
            f"hidden — the geolocation shown is the nearest {cdn} edge, not the host."
        )
        return score, reasons

    if cc in HIGH_RISK_COUNTRIES:
        score += 5
        reasons.append(f"Infrastructure in high-risk country: {cc} ({geoip.get('country','')}).")

    asn_id = asn_raw.split()[0].upper() if asn_raw else ""
    if asn_id in BULLETPROOF_ASNS:
        score += 20
        reasons.append(f"ASN {asn_raw} is a bulletproof host — a provider that does not act on abuse reports.")
    elif asn_id in BUDGET_HOSTING_ASNS:
        score += 5
        reasons.append(
            f"ASN {asn_raw} is budget hosting often used for malicious infrastructure — "
            f"and by a great many legitimate sites, so on its own it means little."
        )
    elif any(kw in isp for kw in ["m247","contabo","leaseweb","colocrossing","quadranet"]):
        score += 5
        reasons.append(f"Hosting provider '{geoip.get('isp')}' is frequently used for malicious infrastructure.")

    return score, reasons


def _check_url_flags(url_data):
    """Sum the per-flag weights url_processor assigned.

    Flags used to be worth a flat +20 each, which was wrong both ways: two
    ordinary facts about a harmless site (plain http on a .shop domain) added to
    40 and read as Suspicious, while a lone brand lookalike — the strongest
    phishing signal available — scored 20 against a 35-point threshold and read
    as Clear. Weights now come from url_processor.FLAG_WEIGHTS.

    Callers that supply flags without weights (older fixtures, hand-built input)
    fall back to the flat 20 so their behaviour is unchanged.
    """
    score, reasons = 0, []
    flags = url_data.get("suspicious_flags") or []
    weights = url_data.get("flag_weights") or []
    # A document can contain several links and only the riskiest is analysed, so
    # "URL anomaly detected: not using HTTPS" left the reader guessing which one
    # it meant. Name it.
    host = (url_data.get("domain") or "").split(":")[0]
    prefix = f"URL anomaly on {host}" if host else "URL anomaly detected"
    for i, flag in enumerate(flags):
        score += weights[i] if i < len(weights) else 20
        reasons.append(f"{prefix}: {flag}")
    return min(score, 60), reasons


def _check_virustotal(osint):
    """Score boost based on VirusTotal vendor consensus.
    
    Thresholds are calibrated to avoid false positives:
    - 1 vendor flagging is extremely common for benign sites (FP noise)
    - 2+ vendors is a meaningful signal worth scoring
    - 5+ vendors is a strong consensus for malicious content
    """
    score, reasons = 0, []
    vt = osint.get("virustotal")
    if vt and "stats" in vt:
        stats = vt["stats"]
        mal = stats.get("malicious", 0)
        sus = stats.get("suspicious", 0)
        total_scanned = mal + sus + stats.get("harmless", 0) + stats.get("undetected", 0)
        
        if mal >= 5:
            score = 100
            reasons.append(f"Flagged as malicious by {mal} security vendors on VirusTotal (CRITICAL).")
        elif mal >= 3:
            score = 50
            reasons.append(f"Flagged as malicious by {mal} security vendors on VirusTotal.")
        elif mal >= 2:
            score = 25
            reasons.append(f"Flagged as malicious by {mal} security vendors on VirusTotal.")
        # 1 vendor = likely false positive, no score added
        
        if sus >= 3 and mal == 0:
            score += 15
            reasons.append(f"Flagged as suspicious by {sus} vendors on VirusTotal.")
    return score, reasons


def _check_urlscan(osint):
    """Score boost based on URLScan.io verdict."""
    score, reasons = 0, []
    us = osint.get("urlscan")
    if us:
        if us.get("is_malicious"):
            score = 40
            reasons.append("URLScan.io sandbox analysis flagged this URL as malicious.")
        elif us.get("verdict_score", 0) > 0:
            score = 15
            reasons.append(f"URLScan.io assigned a risk score of {us['verdict_score']}.")
    return score, reasons


# Weights for shortcut findings, keyed on lnk_analyzer's stable codes rather
# than its display wording. Unlike the registrar and hosting weights these are
# NOT measured against a base-rate sample — no such sample exists for shortcuts.
# They are set from how often each thing appears in a shortcut somebody made on
# purpose: an ordinary Windows shortcut points at an application and passes no
# arguments at all, so most of these are near-zero events rather than merely
# unusual ones.
_LNK_WEIGHTS = {
    "encoded_command":        45,   # base64 payload inside a shortcut; no benign use
    "whitespace_padding":     45,   # exists only to hide the command from the user
    "invoke_expression":      35,
    "download_cradle":        35,
    "certutil_abuse":         35,
    "mshta_remote":           30,
    "document_icon_disguise": 30,   # the disguise itself
    "rundll32_script":        25,
    "base64_decode":          25,
    "hidden_execution":       20,
    "interpreter_target":     15,   # legitimate but uncommon on its own
    "hidden_window":          15,
    "unc_path":               10,
    "contains_url":           10,
    "long_command_line":      10,
    "user_writable_dir":       5,   # true of plenty of ordinary installers
}


def _check_lnk(analysis_data: dict):
    """Scores a Windows shortcut by what it would actually run.

    A .lnk is a stored command line, which is why it is a standard delivery and
    persistence artifact — it arrives looking like an invoice and executes
    whatever it says. Nothing here used to parse them, so a shortcut carrying an
    encoded PowerShell payload was scanned as an unremarkable small binary.

    An ordinary shortcut produces no findings at all: it points at an
    application and passes no arguments. That is what makes even the modest
    weights defensible — the baseline really is zero, not "a bit noisy".
    """
    lnk = analysis_data.get("lnk") or {}
    if not lnk.get("is_lnk"):
        return 0, []

    score = sum(_LNK_WEIGHTS.get(code, 0) for code in lnk.get("codes") or [])
    reasons = [f"Shortcut: {finding}" for finding in lnk.get("suspicious") or []]

    args = (lnk.get("arguments") or "").strip()
    if args and score:
        # The command line is the evidence; show it rather than only describing it.
        reasons.append(f"Shortcut command line: {args[:200]}")

    return min(score, 100), reasons


# HTML attachment weights. Most individual signals here are deliberately near
# zero: a "download" attribute and a scripted .click() describe every download
# button on the web, and copy-to-clipboard is on every code snippet. What
# separates a smuggling page from a normal one is the COMBINATION, so the
# conjunctions below carry the weight — the same shape as the APK
# overlay-plus-accessibility rule, which is the best-calibrated check here.
_HTML_WEIGHTS = {
    "smuggled_payload":       60,   # decoded to a real executable/archive: evidence, not a hint
    "int_array_payload":      35,   # payload as integers, purely to dodge base64 checks
    "meta_refresh_data_uri":  25,
    "data_uri_octet_stream":  25,
    "run_dialog_lure":        30,   # "press Windows+R" has no legitimate use in an attachment
    "shell_command_text":     20,
    "ms_save_blob":           15,   # legacy IE API, rare outside smuggling kits
    "obfuscation":            10,
    "large_encoded_blob":     10,
    "blob_construction":       5,
    "object_url":              5,
    "base64_decode":           5,
    "clipboard_write":         5,   # every documentation site has a copy button
    "forced_download":         0,   # ordinary download buttons
    "synthetic_click":         0,   # ordinary download buttons
}


def _check_html(analysis_data: dict):
    """Scores an HTML attachment for smuggling and clipboard-injection lures.

    An HTML attachment carries no macro and often no URL, so it used to read as
    inert text: low entropy, no indicators, no YARA hit, Clear. The payload is
    inside the page, assembled by script in the browser, which is precisely why
    nothing on the network path ever sees it.
    """
    html = analysis_data.get("html") or {}
    if not html.get("is_html") or not html.get("codes"):
        return 0, []

    codes = set(html["codes"])
    score = sum(_HTML_WEIGHTS.get(code, 0) for code in codes)
    reasons = [f"HTML: {finding}" for finding in html.get("findings") or []]

    # Assembling a file in memory AND handing it to the user is the technique.
    # Either half alone is ordinary.
    if {"blob_construction", "object_url"} <= codes and codes & {"forced_download", "synthetic_click"}:
        score += 30
        reasons.append(
            "HTML: builds a file in memory and downloads it without contacting the network — "
            "the HTML smuggling pattern (MITRE T1027.006), which is invisible to gateways "
            "that inspect downloads."
        )

    # A page that puts a command on the clipboard and tells the user to run it.
    # No file is ever downloaded, so the page is the only artifact that exists.
    if "clipboard_write" in codes and codes & {"run_dialog_lure", "shell_command_text"}:
        score += 40
        reasons.append(
            "HTML: writes a command to the clipboard and instructs the user to run it — "
            "the ClickFix / fake-CAPTCHA pattern. Nothing is downloaded, so no file scan "
            "would ever see the payload."
        )

    return min(score, 100), reasons


def _check_resource_chain(osint):
    """Scores the third parties a page loads, not just the page.

    The gap this closes: reputation was only ever asked about the submitted
    domain. deutschland.com scored 0/100 — 1 VirusTotal vendor, below the noise
    floor, and URLScan's own engines called it benign — while serving a script
    from an S3 bucket 9 vendors flagged. The bucket was in the report already,
    rendered as a chip and read by nothing.

    Weighting follows the split described in resource_chain.py:

    * A reputation hit on a third-party host is specific evidence and scores
      like one, though below a hit on the artifact itself — "this page loads
      something known-bad" is a weaker claim about the page than "this page IS
      known-bad", and a compromised ad network briefly poisons a lot of
      innocent sites.
    * Structure alone does not score. Object storage, free hosting and CDNs
      carry an enormous amount of the legitimate web, and per
      tests/live/base_rates.py a signal that fires across the Tranco top 10,000
      carries little information however sinister it sounds. It is reported so
      the analyst sees it, and it decides lookup order, which is where it earns
      its keep.
    * One exception scores, because the conjunction really is rare on ordinary
      pages: an executable or archive payload fetched from a third-party host.
      Legitimate sites do serve installers, but from their own domain — that is
      why first-party hosts are dropped before this check ever sees the list.
    """
    score, reasons = 0, []
    chain = osint.get("resource_chain") or {}
    if chain.get("skipped") or not chain.get("hosts"):
        return 0, reasons

    for hit in chain.get("intel_hits") or []:
        source = hit.get("source", "intel")
        indicator = hit.get("matched_ioc") or hit.get("matched_url") or ""
        score += 45
        reasons.append(
            f"A third-party resource this page loads is listed in "
            f"{source}: {indicator[:70]}"
        )

    for entry in chain.get("hosts") or []:
        stats = entry.get("virustotal") or {}
        mal = stats.get("malicious", 0)
        sus = stats.get("suspicious", 0)
        host = entry.get("host", "?")
        # Same shape as _check_virustotal: 1 vendor is noise, and the thresholds
        # sit one step below their artifact-level equivalents.
        if mal >= 5:
            score += 70
            reasons.append(
                f"This page loads content from {host}, flagged as malicious by "
                f"{mal} VirusTotal vendors."
            )
        elif mal >= 3:
            score += 40
            reasons.append(
                f"This page loads content from {host}, flagged by {mal} VirusTotal vendors."
            )
        elif mal >= 2:
            score += 20
            reasons.append(
                f"This page loads content from {host}, flagged by {mal} VirusTotal vendors."
            )
        elif sus >= 3 and mal == 0:
            score += 10
            reasons.append(
                f"This page loads content from {host}, marked suspicious by {sus} vendors."
            )

        facets = entry.get("facets") or []
        if "executable_payload" in facets:
            score += 25
            reasons.append(
                f"This page fetches an executable or script payload from a third-party host ({host})."
            )
        elif "archive_payload" in facets:
            score += 10
            reasons.append(f"This page fetches an archive payload from a third-party host ({host}).")

    # Context only — deliberately scores nothing, in the manner of
    # _check_registrar. Named so the report can show the analyst which hosts
    # were merely observed rather than letting a clean total imply they were
    # all vetted.
    unvetted = [
        e["host"] for e in chain.get("hosts") or []
        if not e.get("checked") and not e.get("virustotal")
    ]
    if unvetted:
        reasons.append(
            f"{len(unvetted)} third-party host(s) were observed but not "
            f"reputation-checked: {', '.join(unvetted[:5])}"
            + (" ..." if len(unvetted) > 5 else "")
        )

    return min(score, 100), reasons


def _check_ioc_volume(iocs):
    score, reasons = 0, []
    ip_count = len(iocs.get("ips") or [])
    url_count = len(iocs.get("urls") or [])
    if ip_count >= 5:
        score += 10
        reasons.append(f"{ip_count} embedded IP addresses found — unusually high volume.")
    elif ip_count >= 2:
        score += 5
    if url_count >= 3:
        score += 8
        reasons.append(f"{url_count} embedded URLs extracted from artifact.")
    return score, reasons


# Permissions carrying real evidence, tiered by how rare they are in legitimate
# apps. The old rule scored permission COUNT (5+ dangerous = +35), which measures
# app complexity rather than malice: WhatsApp, Truecaller and every default SMS
# app trip it, and the SMS-stealer and the legitimate SMS app in the corpus have
# byte-identical permission sets. Volume is now worth nothing and specific rare
# capabilities carry the weight.

# Almost never legitimate outside enterprise MDM. BIND_ACCESSIBILITY_SERVICE is
# the main Android banking-malware vector (reads the screen, clicks for you).
_CRITICAL_PERMISSIONS = {
    "android.permission.BIND_DEVICE_ADMIN":
        "can lock the device, wipe it, or block its own uninstall",
    "android.permission.BIND_ACCESSIBILITY_SERVICE":
        "can read everything on screen and tap on your behalf — the main banking-overlay technique",
    "android.permission.INSTALL_PACKAGES":
        "can install further apps without asking — dropper behaviour",
}

# Genuinely abused, but with mainstream legitimate uses: app stores and updaters
# request install prompts, and Truecaller-style caller ID, chat heads and screen
# recorders all need overlays. Real signal, not on its own.
_ELEVATED_PERMISSIONS = {
    "android.permission.REQUEST_INSTALL_PACKAGES":
        "can prompt to install other apps",
    "android.permission.SYSTEM_ALERT_WINDOW":
        "can draw over other apps — used by overlay phishing, and by caller ID and chat bubbles",
}


def _check_apk_permissions(apk_data):
    """Score Android permissions by discriminative power, not by how many there are."""
    score, reasons = 0, []
    if not apk_data or not apk_data.get("is_apk"):
        return score, reasons

    dangerous = apk_data.get("dangerous_permissions", [])
    perm_set = set(dangerous)

    for perm, why in _CRITICAL_PERMISSIONS.items():
        if perm in perm_set:
            score += 35
            reasons.append(f"APK requests {perm.rsplit('.', 1)[-1]} — {why}.")

    for perm, why in _ELEVATED_PERMISSIONS.items():
        if perm in perm_set:
            score += 15
            reasons.append(f"APK requests {perm.rsplit('.', 1)[-1]} — {why}.")

    # Combinations that mean more together than apart.
    if {"android.permission.READ_SMS", "android.permission.SEND_SMS"}.issubset(perm_set):
        score += 15
        reasons.append("APK requests both READ_SMS and SEND_SMS — common in SMS-stealing malware.")
    if {"android.permission.SYSTEM_ALERT_WINDOW",
        "android.permission.BIND_ACCESSIBILITY_SERVICE"}.issubset(perm_set):
        score += 25
        reasons.append(
            "APK combines screen overlay with accessibility control — the exact pattern used by "
            "banking-overlay trojans to capture credentials."
        )

    # Permission volume no longer scores, but the report still says what the app
    # asked for. Suppressing the score is not a reason to suppress the context.
    if dangerous and not score:
        reasons.append(
            f"APK requests {len(dangerous)} sensitive permission(s): {', '.join(p.rsplit('.', 1)[-1] for p in sorted(dangerous)[:5])}"
            f"{'...' if len(dangerous) > 5 else ''}. Normal for an app of this kind on its own."
        )

    return min(score, 60), reasons


# ── New threat intelligence checks ──────────────────────────────────────────

def _check_malwarebazaar(osint: dict):
    mb = osint.get("malwarebazaar", {}) or {}
    if mb.get("found"):
        name = mb.get("threat_name") or mb.get("signature") or "Unknown malware"
        first = mb.get("first_seen", "Unknown")
        return 100, [f"File hash confirmed in MalwareBazaar: {name} (first seen {first})."]
    return 0, []


def _check_threatfox(osint: dict):
    tf = osint.get("threatfox", {}) or {}
    if not tf.get("found"):
        return 0, []
    malware = tf.get("malware_printable") or tf.get("malware") or "Unknown"
    ioc = tf.get("matched_ioc", "")
    # ThreatFox confidence_level is 0-100. A weak/low-confidence hit is NOT
    # definitive — scale the score so a shaky match can't alone drive a
    # Malicious verdict (a 50%-confidence "Unknown" match on a benign IOC used
    # to score a full 70 and short-circuit to Malicious).
    try:
        conf = int(tf.get("confidence"))
    except (TypeError, ValueError):
        conf = 0
    if conf >= 75:
        score = 70
    elif conf >= 50:
        score = 35
    else:
        score = 15
    return score, [f"IOC found in ThreatFox: {malware} (confidence {conf}%) — matched '{ioc}'."]


def _check_urlhaus(osint: dict):
    uh = osint.get("urlhaus", {}) or {}
    if uh.get("found"):
        threat = uh.get("threat") or "malware distribution"
        url = uh.get("matched_url", "")
        return 60, [f"URL found in URLhaus malware database ({threat}): {url[:60]}"]
    return 0, []


def _check_abuseipdb(osint: dict):
    ab = osint.get("abuseipdb", {}) or {}
    if ab.get("skipped"):
        return 0, []
    confidence = ab.get("abuse_confidence", 0)
    ip = ab.get("checked_ip", "")
    if confidence >= 80:
        return 40, [f"IP {ip} has {confidence}% abuse confidence on AbuseIPDB — high-risk infrastructure."]
    if confidence >= 50:
        return 20, [f"IP {ip} has elevated abuse confidence score ({confidence}%) on AbuseIPDB."]
    return 0, []


def _check_document_threats(doc_data: dict):
    """PDF/Office threat scoring.

    Calibration note: /JavaScript and /OpenAction individually are extremely
    common in LEGITIMATE PDFs (interactive forms, "open at page 1" actions),
    so alone they are weak signals. The dangerous pattern is JavaScript wired
    directly to an auto-trigger, or a Launch action — those stay heavy.
    """
    score, reasons = 0, []
    if not doc_data or doc_data.get("doc_type") == "unknown":
        return score, reasons

    if doc_data.get("has_launch_action"):
        score += 45
        reasons.append("PDF contains a Launch action — can execute external programs on your device.")

    if doc_data.get("has_js_auto_combo"):
        # JS bound straight to an open/auto trigger — classic drive-by PDF.
        score += 45
        reasons.append("PDF runs embedded JavaScript automatically when opened — a pattern heavily used by malicious PDFs.")
    else:
        if doc_data.get("has_javascript"):
            score += 15
            reasons.append("PDF contains JavaScript — common in interactive forms, but worth caution.")
        if doc_data.get("has_auto_action"):
            score += 10
            reasons.append("PDF performs an action on open (often just page navigation).")

    if doc_data.get("has_embedded_files"):
        score += 10
        reasons.append("PDF contains embedded files — uncommon for an ordinary document.")
    if doc_data.get("has_macros"):
        score += 45
        reasons.append("Office document contains VBA macros — the primary delivery mechanism for macro malware.")
    kws = doc_data.get("suspicious_macro_keywords") or []
    if kws:
        score += 20
        reasons.append(f"Dangerous macro patterns detected: {', '.join(kws[:4])}.")
    for flag in (doc_data.get("suspicious_flags") or []):
        if flag not in " ".join(reasons):
            score += 5

    return min(score, 90), reasons


def _check_yara(osint: dict):
    yara_data = osint.get("yara", {}) or {}
    matches = yara_data.get("yara_matches") or []
    if not matches:
        return 0, []
    critical = [m for m in matches if m.get("severity") == "critical"]
    high     = [m for m in matches if m.get("severity") == "high"]
    if critical:
        score = min(len(critical) * 40 + len(high) * 20, 100)
    else:
        score = min(len(high) * 25, 80)
    reasons = [f"YARA: {m['description']}" for m in matches[:4]]
    return score, reasons


_NATURALLY_COMPRESSED = {
    "PDF Document",
    "ZIP Archive / Office Open XML / APK / JAR",
    "GZIP Compressed",
    "BZIP2 Compressed",
    "7-Zip Archive",
    "RAR Archive",
    "Microsoft Cabinet (CAB) File",
}

_ENTROPY_BASELINE_STRINGS = {
    "Large base64 blob — possible encoded payload",
}


def _check_enhanced_static(static: dict):
    score, reasons = 0, []
    magic_type = static.get("magic_type", "Unknown")

    # PDFs and compressed archives are inherently high-entropy — skip that check
    # to avoid false positives on legitimate documents.
    is_compressed = magic_type in _NATURALLY_COMPRESSED

    entropy = static.get("file_entropy", 0)
    if not is_compressed:
        if entropy > 7.2:
            score += 15
            reasons.append(f"Very high file entropy ({entropy}) — file appears to be packed or encrypted.")
        elif entropy > 6.8:
            score += 8
            reasons.append(f"Elevated file entropy ({entropy}) — may contain compressed or obfuscated content.")

    if static.get("type_mismatch"):
        score += 30
        reasons.append(
            f"File type mismatch: claims to be {static.get('extension', 'unknown')} "
            f"but is actually {static.get('magic_type', 'unknown')} — deliberate disguise."
        )

    for flag in (static.get("suspicious_strings") or [])[:5]:
        # Skip base64 blob flag for PDFs/compressed — base64 is used normally for images/fonts
        if is_compressed and flag in _ENTROPY_BASELINE_STRINGS:
            continue
        score += 8
        reasons.append(f"Suspicious code pattern: {flag}")

    return min(score, 60), reasons


# ── Known-hash check ─────────────────────────────────────────────────────────

def _check_known_hashes(file_hash: Optional[str], member_hashes=None):
    """Returns (score, reasons, family, attribution) if hash is in blocklist.

    Archive members are checked too. The blocklist keys on a sample's own hash,
    which a wrapper's hash never equals, so a known-malicious file simply zipped
    up would otherwise sail past the one check written specifically to catch it.
    The container is checked first: a direct hit describes the artifact itself.
    """
    candidates = [(file_hash, None)]
    candidates += [(m.get("sha256"), m.get("name")) for m in (member_hashes or [])]
    for h, member_name in candidates:
        if not h:
            continue
        entry = KNOWN_MALICIOUS_HASHES.get(h.lower())
        if not entry:
            continue
        reason = entry["reason"] if not member_name else f"{entry['reason']} Found inside the archive as '{member_name}'."
        return entry["score"], [reason], entry["family"], entry["attribution"]
    return 0, [], None, None


# ── Master entry point ───────────────────────────────────────────────────────

def calculate_score(analysis_data: dict) -> dict:
    """Called by backend/app/main.py. Returns dict stored in ScanJob.results."""
    static   = analysis_data.get("static", {})   or {}
    osint    = analysis_data.get("osint", {})     or {}
    url_data = analysis_data.get("url", {})       or {}
    iocs     = analysis_data.get("iocs", {})      or {}

    whois = osint.get("whois", {}) or {}
    geoip = osint.get("geoip", {}) or {}
    dns   = osint.get("dns", {})   or {}

    all_reasons = []
    score_breakdown = []
    family, attribution = None, None
    age = None  # populated by heuristic score path only

    def record(label, points):
        if points:
            score_breakdown.append({"label": label, "points": points})

    # Confirmed threat-intel evidence and heuristic suspicion are tracked
    # separately: a clean VirusTotal consensus may dampen heuristics, but it
    # must never water down a confirmed MalwareBazaar/ThreatFox/YARA hit.
    intel_total, heuristic_total = 0, 0

    # A third, cross-cutting tally: how much of the score comes from evidence
    # about THE ARTIFACT ITSELF (its hash, its bytes, its structure, a scanner's
    # verdict on it) rather than about the company it keeps (the registrar behind
    # a domain it mentions, the country an IP sits in, how new a domain is).
    #
    # Contextual evidence is real and worth reporting, but it describes
    # surroundings, not the thing submitted. "Malicious" is a statement about the
    # artifact, so it requires at least some evidence about the artifact — see
    # the artifact-evidence requirement near the end of this function. Without
    # that rule a five-day-old domain on a cheap host reads as confirmed malware
    # while nothing has actually been examined.
    artifact_total = 0

    # The submitted URL IS the artifact, so intel and heuristics about it are
    # artifact evidence. For a file upload the same signals describe indicators
    # merely embedded in it, which is much weaker.
    submitted_url = analysis_data.get("submitted_url")

    # ── Tier 1: Definitive hash matches (short-circuit if confirmed malware) ──
    file_hash = analysis_data.get("file_hash")

    # Internal blocklist
    hash_score, hash_reasons, hash_family, hash_attribution = _check_known_hashes(
        file_hash, analysis_data.get("archive_hashes")
    )
    if hash_score > 0:
        intel_total += hash_score; artifact_total += hash_score; all_reasons += hash_reasons
        family = hash_family; attribution = hash_attribution
    record("Known Malicious Hash Match", hash_score)

    # MalwareBazaar (external, authoritative hash DB)
    mb_score, r = _check_malwarebazaar(osint); intel_total += mb_score; artifact_total += mb_score; all_reasons += r
    record("MalwareBazaar Hash Match", mb_score)

    # YARA rule matches (pattern-based, very high confidence)
    yara_score, r = _check_yara(osint); intel_total += yara_score; artifact_total += yara_score; all_reasons += r
    record("YARA Rule Matches", yara_score)

    # ── Tier 2: IOC-based threat intelligence ─────────────────────────────────
    # ThreatFox can match on the file HASH (authoritative, like MalwareBazaar) or
    # on an embedded IP/domain/URL (weaker). check_iocs searches the hash first,
    # so matched_ioc == file_hash tells us which it was — this distinction drives
    # the corroboration cap below.
    tf_score, r = _check_threatfox(osint);  intel_total += tf_score; all_reasons += r
    record("ThreatFox IOC Match", tf_score)
    _tf = osint.get("threatfox", {}) or {}
    tf_matched_hash = bool(_tf.get("found") and file_hash and _tf.get("matched_ioc") == file_hash)
    uh_score, r = _check_urlhaus(osint);    intel_total += uh_score; all_reasons += r
    record("URLhaus Malware Distribution", uh_score)
    ab_score, r = _check_abuseipdb(osint);  intel_total += ab_score; all_reasons += r
    record("AbuseIPDB Abuse Confidence", ab_score)

    # ThreatFox on the file hash identifies the artifact. On an embedded IP or
    # domain it describes something the artifact merely references. Same feed,
    # very different strength — the same distinction the weak-IOC cap draws.
    if tf_matched_hash:
        artifact_total += tf_score
    elif submitted_url:
        artifact_total += tf_score

    # URLhaus matches an EXACT URL, so a hit is a statement about that precise
    # resource rather than about its neighbourhood — strong enough to count as
    # artifact evidence even when the URL was merely found inside a file.
    #
    # Without this, a text file whose entire content was a confirmed
    # malware-distribution URL scored 69/Suspicious, and the capping message told
    # the user the evidence concerned "an indicator it merely references". The
    # link was the point of the file. Under-warning on a forwarded scam message
    # is the failure this engine exists to avoid.
    #
    # AbuseIPDB stays contextual: it reports an address's abuse history, which
    # describes infrastructure rather than this artifact. ThreatFox on a
    # domain/IP likewise — that fuzziness is what produced the original
    # false positive this cap was written for (a 50%-confidence hit on an
    # incidental example.com).
    artifact_total += uh_score
    if submitted_url:
        artifact_total += ab_score

    # ── Tier 3: Document-specific threats ─────────────────────────────────────
    # Structure read out of the submitted file itself — artifact evidence.
    s, r = _check_document_threats(analysis_data.get("document", {})); heuristic_total += s; artifact_total += s; all_reasons += r
    record("Document Threat Analysis", s)

    # ── Tier 4: Heuristic signals (always run) ────────────────────────────────
    s, r      = _check_enhanced_static(static);    heuristic_total += s; artifact_total += s; all_reasons += r
    record("File Structure Analysis", s)
    s, r      = _check_pe_sections(static);        heuristic_total += s; artifact_total += s; all_reasons += r
    record("PE Section Entropy", s)
    s, r, age = _check_domain_age(whois);          heuristic_total += s; all_reasons += r
    record("Domain Age Risk", s)
    s, r      = _check_registrar(whois);           heuristic_total += s; all_reasons += r
    record("Registrar Reputation", s)
    s, r      = _check_geoip(geoip);               heuristic_total += s; all_reasons += r
    record("Hosting / ASN Risk", s)
    # URL anomalies describe the submitted URL when one was submitted; for a file
    # upload they describe links found inside it.
    s, r      = _check_url_flags(url_data);        heuristic_total += s; all_reasons += r
    if submitted_url:
        artifact_total += s
    record("URL Anomalies", s)
    s, r      = _check_ioc_volume(iocs);           heuristic_total += s; all_reasons += r
    record("IOC Volume", s)
    vt_score, r = _check_virustotal(osint);        intel_total += vt_score; artifact_total += vt_score; all_reasons += r
    record("VirusTotal Consensus", vt_score)
    s, r      = _check_urlscan(osint);             heuristic_total += s; all_reasons += r
    if submitted_url:
        artifact_total += s
    record("URLScan Verdict", s)
    # Counted as INTEL, not heuristic, and the distinction is load-bearing. The
    # benign-consensus dampening below halves heuristic suspicion whenever a
    # broad VirusTotal scan of the artifact came back clean — which is exactly
    # the state a page has when its own domain is fine and the danger is in a
    # third-party resource. Filed as a heuristic, this check would be halved
    # precisely when it is right. Reputation hits on a loaded host are specific
    # external evidence, and the one structural signal that scores here (an
    # executable fetched from someone else's host) is behavioural enough that it
    # should likewise not be discounted by the wrapper looking clean.
    s, r      = _check_resource_chain(osint);      intel_total += s; all_reasons += r
    if submitted_url:
        artifact_total += s
    record("Resource Chain", s)
    s, r      = _check_apk_permissions(analysis_data.get("apk", {})); heuristic_total += s; artifact_total += s; all_reasons += r
    record("APK Permissions", s)
    # Artifact evidence: the shortcut IS the submitted thing, and what it would
    # run is read out of its own structure rather than inferred.
    s, r      = _check_lnk(analysis_data);         heuristic_total += s; artifact_total += s; all_reasons += r
    record("Shortcut Command Line", s)
    s, r      = _check_html(analysis_data);        heuristic_total += s; artifact_total += s; all_reasons += r
    record("HTML Attachment", s)

    # Whether a verdict-critical intel source (VirusTotal) did NOT complete on
    # this run — set by app/main.py. A partial scan is stored but never cached,
    # so it gets retried instead of freezing a possibly-wrong answer.
    intel_partial = bool(analysis_data.get("intel_partial"))

    # ── Benign-consensus dampening ────────────────────────────────────────────
    # If a broad VirusTotal scan (40+ engines) found NOTHING, halve the purely
    # heuristic suspicion — fixes false positives on ordinary PDFs/documents
    # whose features (forms JS, open actions) merely look unusual. Only applies
    # when VT actually returned a verdict (40+ engines) AND the scan is complete;
    # a partial/absent VT result never dampens (that path is marked partial and
    # not cached, so it can't freeze a wrongly-low score).
    vt_stats = (osint.get("virustotal") or {}).get("stats") or {}
    vt_engines = sum(vt_stats.get(k, 0) for k in ("malicious", "suspicious", "harmless", "undetected"))
    if (
        not intel_partial
        and heuristic_total > 0
        and intel_total == 0
        and vt_engines >= 40
        and vt_stats.get("malicious", 0) == 0
        and vt_stats.get("suspicious", 0) == 0
    ):
        reduction = heuristic_total - heuristic_total // 2
        heuristic_total = heuristic_total // 2
        record("Benign VirusTotal Consensus (reduction)", -reduction)
        all_reasons.append(
            f"Reassuring signal: {vt_engines} antivirus engines on VirusTotal scanned this and none flagged it — risk score reduced accordingly."
        )

    final_score = min(intel_total + heuristic_total, 100)
    verdict = "Malicious" if final_score >= 70 else "Suspicious" if final_score >= 35 else "Clear"

    # ── Artifact-evidence requirement ─────────────────────────────────────────
    # "Malicious" is a claim about the submitted artifact, so it takes at least
    # some evidence about that artifact: its hash, its bytes, its structure, or a
    # scanner's verdict on it. Contextual signals — the registrar behind a domain
    # it mentions, the country an IP sits in, how recently a domain was
    # registered, a threat-intel hit on an indicator merely embedded in a file —
    # describe the surroundings, not the thing itself.
    #
    # Without this rule those signals stack: a five-day-old domain (+40) on a
    # flagged ASN (+40) with a cheap registrar (+15) reaches 95 and is declared
    # confirmed malware, having examined nothing. Every legitimate new business
    # on cheap hosting looks exactly like that. It also generalises the earlier
    # weak-IOC cap, which drew the same distinction for file uploads only.
    #
    # Deliberately a cap, not a suppression: the score, the reasons and every
    # indicator stay in the report. Only the claim "confirmed malicious" is
    # withheld, and the reason says so.
    if verdict == "Malicious" and artifact_total == 0:
        reduction = final_score - 69
        final_score = 69
        verdict = "Suspicious"
        record("Weak-IOC Corroboration Cap", -reduction)
        all_reasons.append(
            "Verdict capped at Suspicious: every signal here describes the artifact's "
            "surroundings — hosting, registrar, domain age, or a threat-intel match on "
            "an indicator it merely references — and nothing was found in the artifact "
            "itself (no hash match, YARA rule, structural finding, or antivirus "
            "detection). Treat as suspicious pending confirmation rather than "
            "confirmed-malicious."
        )

    score_breakdown.sort(key=lambda e: e["points"], reverse=True)
    risk_profile = _build_risk_profile(score_breakdown)

    graph_nodes, graph_edges = _build_graph(iocs, geoip, whois)

    # ── Degraded-scan honesty: Clear → Inconclusive ───────────────────────────
    # When a verdict-critical source (VirusTotal) did not complete, "Clear" is
    # not a finding — it is the ABSENCE of one, and we cannot tell "nothing is
    # wrong" apart from "we were unable to check". Reporting that as clean is
    # how a rate-limited scan of real malware ends up looking safe, so say so.
    #
    # Deliberately narrow: Malicious/Suspicious are NOT downgraded. Missing
    # intel did not prevent those detections, and relabelling a real detection
    # as "Inconclusive" would bury a true positive — the worse failure.
    # Why a Clear was withheld, in the report's own words. The presentation
    # layer used to hard-code the VirusTotal explanation for every Inconclusive
    # verdict, which would have made an unexaminable archive claim that
    # VirusTotal was down.
    inconclusive_reason = None

    if intel_partial:
        if verdict == "Clear":
            verdict = "Inconclusive"
            inconclusive_reason = (
                "This scan did not complete — VirusTotal, the verdict-critical source, "
                "was unavailable. No indicators were found, but that is not the same as "
                "safe. Re-scan before trusting this artifact."
            )
            all_reasons.append(
                "⚠ INCONCLUSIVE — not a clean bill of health. No indicators were found, "
                "but threat-intelligence was incomplete on this scan: VirusTotal (the "
                "verdict-critical source) did not return, so this artifact could not be "
                "fully checked. Re-scan to resolve."
            )
        else:
            all_reasons.append(
                "⚠ Threat-intelligence lookup was incomplete on this scan (a key "
                "source such as VirusTotal did not return in time). This result is "
                "provisional and may change — re-scan to refresh it."
            )

    # Same honesty rule, different cause: content that could not be examined at
    # all. A password-protected archive yields no members, so every per-file
    # detector is bypassed and "no indicators found" describes a scan that never
    # saw the files. Unlike the intel case, re-scanning will not help — the
    # password is needed — so the wording asks for that instead.
    #
    # Ordered after the intel branch and gated on Clear for the same reason it
    # is: a real detection must never be relabelled Inconclusive and buried.
    unexaminable = analysis_data.get("unexaminable") or []
    unsupported_container = analysis_data.get("unsupported_container")

    if unexaminable and verdict == "Clear":
        verdict = "Inconclusive"
        listed = ", ".join(unexaminable[:3]) + (" …" if len(unexaminable) > 3 else "")
        inconclusive_reason = (
            f"The contents of this archive are password-protected and could not be "
            f"extracted, so the {len(unexaminable)} file(s) inside were never scanned. "
            f"Nothing was found because nothing could be examined — that is not the "
            f"same as safe. Unpack it with the password and scan the contents."
        )
        all_reasons.append(
            f"⚠ INCONCLUSIVE — the archive is password-protected, so its "
            f"{len(unexaminable)} member(s) could not be extracted or scanned: {listed}. "
            f"No hash lookup, YARA rule or file analysis ran against them. This is a "
            f"known way of moving a sample past scanners — re-submit the contents "
            f"unpacked to get a real verdict."
        )
    elif unsupported_container and verdict == "Clear":
        # Distinct wording on purpose. Telling someone their 7-Zip archive is
        # password-protected would be a confident, specific, wrong explanation —
        # the same failure as the hard-coded VirusTotal sentence this replaced.
        verdict = "Inconclusive"
        inconclusive_reason = (
            f"This is a {unsupported_container} archive, a format this scanner cannot "
            f"open, so nothing inside it was examined. Nothing was found because "
            f"nothing could be read — that is not the same as safe. Extract it and "
            f"submit the contents individually."
        )
        all_reasons.append(
            f"⚠ INCONCLUSIVE — {unsupported_container} archives cannot be extracted by "
            f"this scanner, so no file inside was hashed, YARA-scanned or analysed. "
            f"Re-submit the contents unpacked to get a real verdict."
        )

    return {
        "score":       final_score,
        "verdict":     verdict,
        "family":      family or "Unknown",
        "attribution": attribution or "Unattributed",
        "partial":     intel_partial,
        "inconclusive_reason": inconclusive_reason,
        "reasons":     all_reasons,
        "indicators": {
            "ips":     iocs.get("ips", []),
            "domains": iocs.get("domains", []),
            "urls":    iocs.get("urls", []),
        },
        "osint_summary": {
            "registrar":       whois.get("registrar"),
            "domain_age_days": age,
            "asn":             geoip.get("asn") or geoip.get("as"),
            "country":         geoip.get("country"),
            "country_code":    (geoip.get("countryCode") or geoip.get("country_code")),
            "hosting":         geoip.get("isp"),
            # Lets the report label the map honestly instead of asserting a
            # country it cannot know for a CDN-fronted site.
            "anycast_cdn":     _anycast_provider(geoip.get("asn") or geoip.get("as") or ""),
            "lat":             geoip.get("lat"),
            "lon":             geoip.get("lon"),
            "city":            geoip.get("city"),
            "region":          geoip.get("region"),
            "dns_a_records":   dns.get("A", []),
            "virustotal":      osint.get("virustotal", {}).get("stats") if "virustotal" in osint else None,
            "virustotal_detections": osint.get("virustotal", {}).get("detections", []) if "virustotal" in osint else [],
            "urlscan":         osint.get("urlscan") if "urlscan" in osint else None,
            "resource_chain":  osint.get("resource_chain") if "resource_chain" in osint else None,
        },
        "graph_nodes": graph_nodes,
        "graph_edges": graph_edges,
        "score_breakdown": score_breakdown,
        "risk_profile":    risk_profile,
    }
