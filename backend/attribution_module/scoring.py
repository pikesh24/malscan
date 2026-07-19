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
    "url":  {"domain": str, "suspicious_flags": [str]},
    "iocs": {"ips": [str], "domains": [str], "urls": [str]},
}

Output shape (stored in ScanJob.results JSON column):
{
    "score":         int (0-100),
    "verdict":       "Malicious" | "Suspicious" | "Clear",
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

SUSPICIOUS_ASNS = {
    "AS9009",   # M247
    "AS16276",  # OVH
    "AS51167",  # Contabo
    "AS197695", # Reg.ru
    "AS60781",  # LeaseWeb
    "AS36352",  # ColoCrossing
    "AS8100",   # QuadraNet
    "AS44050",  # Petersburg Internet Network
    "AS206728", # Media Land LLC
}

HIGH_RISK_COUNTRIES = {"RU", "KP", "CN", "IR", "BY", "SY"}


# ── Helpers ──────────────────────────────────────────────────────────────────

def _parse_age_days(creation_date_str) -> Optional[int]:
    if not creation_date_str:
        return None
    try:
        if isinstance(creation_date_str, list):
            creation_date_str = creation_date_str[0]
        ds = str(creation_date_str).strip()
        for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d", "%Y-%m-%dT%H:%M:%S"):
            try:
                created = datetime.strptime(ds[:len(fmt)], fmt)
                return (datetime.utcnow() - created).days
            except ValueError:
                continue
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
    "ThreatFox IOC Match":                      "network_reputation",
    "URLhaus Malware Distribution":             "network_reputation",
    "AbuseIPDB Abuse Confidence":               "network_reputation",
    "VirusTotal Consensus":                     "network_reputation",
    "Benign VirusTotal Consensus (reduction)":  "network_reputation",
    "URLScan Verdict":                          "network_reputation",
    "IOC Volume":                               "network_reputation",
    "URL Anomalies":                            "network_reputation",
    "Registrar Reputation":                     "hosting_risk",
    "Hosting / ASN Risk":                       "hosting_risk",
    "Domain Age Risk":                          "domain_age_risk",
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
    score, reasons, age = 0, [], None
    age = _parse_age_days(whois.get("creation_date"))
    if age is not None:
        if age <= 7:
            score, msg = 40, f"Domain registered only {age} day(s) ago — extremely new, high phishing risk."
        elif age <= 30:
            score, msg = 30, f"Domain is newly registered ({age} days old)."
        elif age <= 90:
            score, msg = 15, f"Domain is relatively young ({age} days old)."
        else:
            msg = None
        if score:
            reasons.append(msg)
    return score, reasons, age


def _check_registrar(whois):
    score, reasons = 0, []
    registrar = (whois.get("registrar") or "").lower()
    for flagged in FLAGGED_REGISTRARS:
        if flagged in registrar:
            score = 15
            reasons.append(f"Registrar '{whois.get('registrar')}' frequently abused for throwaway phishing domains.")
            break
    return score, reasons


def _check_geoip(geoip):
    score, reasons = 0, []
    cc = (geoip.get("countryCode") or geoip.get("country_code") or "").upper()
    asn_raw = (geoip.get("asn") or geoip.get("as") or "")
    isp = (geoip.get("isp") or "").lower()

    if cc in HIGH_RISK_COUNTRIES:
        score += 20
        reasons.append(f"Infrastructure in high-risk country: {cc} ({geoip.get('country','')}).")

    asn_id = asn_raw.split()[0].upper() if asn_raw else ""
    if asn_id in SUSPICIOUS_ASNS:
        score += 20
        reasons.append(f"ASN {asn_raw} is associated with bulletproof or frequently-abused hosting.")
    elif any(kw in isp for kw in ["m247","contabo","leaseweb","colocrossing","quadranet"]):
        score += 10
        reasons.append(f"Hosting provider '{geoip.get('isp')}' commonly used for malicious infrastructure.")

    return score, reasons


def _check_url_flags(url_data):
    score, reasons = 0, []
    for flag in (url_data.get("suspicious_flags") or []):
        score += 20
        reasons.append(f"URL anomaly detected: {flag}")
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


def _check_apk_permissions(apk_data):
    """Score boost based on dangerous Android permissions."""
    score, reasons = 0, []
    if not apk_data or not apk_data.get("is_apk"):
        return score, reasons
    dangerous = apk_data.get("dangerous_permissions", [])
    if len(dangerous) >= 5:
        score = 35
        reasons.append(f"APK requests {len(dangerous)} dangerous permissions — highly suspicious.")
    elif len(dangerous) >= 3:
        score = 20
        reasons.append(f"APK requests {len(dangerous)} dangerous permissions.")
    elif len(dangerous) >= 1:
        score = 10
        reasons.append(f"APK requests dangerous permission(s): {', '.join(dangerous[:3])}.")

    # SMS read+send combo is a classic spyware pattern
    perm_set = set(dangerous)
    if {"android.permission.READ_SMS", "android.permission.SEND_SMS"}.issubset(perm_set):
        score += 15
        reasons.append("APK requests both READ_SMS and SEND_SMS — common in SMS-stealing malware.")
    if "android.permission.BIND_DEVICE_ADMIN" in perm_set:
        score += 15
        reasons.append("APK requests BIND_DEVICE_ADMIN — can lock device or prevent uninstall.")
    return score, reasons


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

def _check_known_hashes(file_hash: Optional[str]):
    """Returns (score, reasons, family, attribution) if hash is in blocklist."""
    if not file_hash:
        return 0, [], None, None
    entry = KNOWN_MALICIOUS_HASHES.get(file_hash.lower())
    if entry:
        return entry["score"], [entry["reason"]], entry["family"], entry["attribution"]
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

    # ── Tier 1: Definitive hash matches (short-circuit if confirmed malware) ──
    file_hash = analysis_data.get("file_hash")

    # Internal blocklist
    hash_score, hash_reasons, hash_family, hash_attribution = _check_known_hashes(file_hash)
    if hash_score > 0:
        intel_total += hash_score; all_reasons += hash_reasons
        family = hash_family; attribution = hash_attribution
    record("Known Malicious Hash Match", hash_score)

    # MalwareBazaar (external, authoritative hash DB)
    mb_score, r = _check_malwarebazaar(osint); intel_total += mb_score; all_reasons += r
    record("MalwareBazaar Hash Match", mb_score)

    # YARA rule matches (pattern-based, very high confidence)
    yara_score, r = _check_yara(osint); intel_total += yara_score; all_reasons += r
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

    # ── Tier 3: Document-specific threats ─────────────────────────────────────
    s, r = _check_document_threats(analysis_data.get("document", {})); heuristic_total += s; all_reasons += r
    record("Document Threat Analysis", s)

    # ── Tier 4: Heuristic signals (always run) ────────────────────────────────
    s, r      = _check_enhanced_static(static);    heuristic_total += s; all_reasons += r
    record("File Structure Analysis", s)
    s, r      = _check_pe_sections(static);        heuristic_total += s; all_reasons += r
    record("PE Section Entropy", s)
    s, r, age = _check_domain_age(whois);          heuristic_total += s; all_reasons += r
    record("Domain Age Risk", s)
    s, r      = _check_registrar(whois);           heuristic_total += s; all_reasons += r
    record("Registrar Reputation", s)
    s, r      = _check_geoip(geoip);               heuristic_total += s; all_reasons += r
    record("Hosting / ASN Risk", s)
    s, r      = _check_url_flags(url_data);        heuristic_total += s; all_reasons += r
    record("URL Anomalies", s)
    s, r      = _check_ioc_volume(iocs);           heuristic_total += s; all_reasons += r
    record("IOC Volume", s)
    vt_score, r = _check_virustotal(osint);        intel_total += vt_score; all_reasons += r
    record("VirusTotal Consensus", vt_score)
    s, r      = _check_urlscan(osint);             heuristic_total += s; all_reasons += r
    record("URLScan Verdict", s)
    s, r      = _check_apk_permissions(analysis_data.get("apk", {})); heuristic_total += s; all_reasons += r
    record("APK Permissions", s)

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

    # ── Weak-IOC corroboration cap ────────────────────────────────────────────
    # A single ThreatFox/URLhaus/AbuseIPDB hit on an indicator EMBEDDED in an
    # uploaded file (a domain/URL/IP the file merely references) is weaker
    # evidence than a match on the file itself. On its own it must not push a
    # file to "Malicious" — that produced false positives (a lone 75%-confidence
    # ThreatFox hit on an embedded `example.com` scored 70 = Malicious).
    #
    # So: for FILE uploads only (a submitted URL *is* the artifact, not an
    # embedded reference), if the Malicious verdict rests solely on such
    # IOC-based intel with NO corroboration from a file-hash source
    # (known-hash / MalwareBazaar / ThreatFox-on-hash / YARA) or VirusTotal,
    # cap the verdict at Suspicious. Hash-based hits keep full weight, so true
    # positives are untouched.
    submitted_url = analysis_data.get("submitted_url")
    corroborated = bool(hash_score or mb_score or yara_score or vt_score or tf_matched_hash)
    ioc_intel_score = (0 if tf_matched_hash else tf_score) + uh_score + ab_score
    if (
        verdict == "Malicious"
        and not submitted_url
        and not corroborated
        and ioc_intel_score > 0
    ):
        score_without_ioc_intel = min((intel_total - ioc_intel_score) + heuristic_total, 100)
        if score_without_ioc_intel < 70:
            reduction = final_score - 69
            final_score = 69
            verdict = "Suspicious"
            record("Weak-IOC Corroboration Cap", -reduction)
            all_reasons.append(
                "Verdict capped at Suspicious: the only malware-grade evidence is a "
                "threat-intel match on a network indicator embedded in the file, not "
                "on the file itself, and nothing corroborates it (no file-hash match, "
                "YARA rule, or VirusTotal detection). Treat as suspicious pending "
                "confirmation rather than confirmed-malicious."
            )

    score_breakdown.sort(key=lambda e: e["points"], reverse=True)
    risk_profile = _build_risk_profile(score_breakdown)

    graph_nodes, graph_edges = _build_graph(iocs, geoip, whois)

    if intel_partial:
        all_reasons.append(
            "⚠ Threat-intelligence lookup was incomplete on this scan (a key "
            "source such as VirusTotal did not return in time). This result is "
            "provisional and may change — re-scan to refresh it."
        )

    return {
        "score":       final_score,
        "verdict":     verdict,
        "family":      family or "Unknown",
        "attribution": attribution or "Unattributed",
        "partial":     intel_partial,
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
            "lat":             geoip.get("lat"),
            "lon":             geoip.get("lon"),
            "city":            geoip.get("city"),
            "region":          geoip.get("region"),
            "dns_a_records":   dns.get("A", []),
            "virustotal":      osint.get("virustotal", {}).get("stats") if "virustotal" in osint else None,
            "virustotal_detections": osint.get("virustotal", {}).get("detections", []) if "virustotal" in osint else [],
            "urlscan":         osint.get("urlscan") if "urlscan" in osint else None,
        },
        "graph_nodes": graph_nodes,
        "graph_edges": graph_edges,
        "score_breakdown": score_breakdown,
        "risk_profile":    risk_profile,
    }
