"""
attribution_module/scoring.py
Team Member 4 — Attribution & Security Engineer

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
    "osint_summary": {"registrar", "asn", "country", "hosting", "domain_age_days"},
    "graph_nodes":   [...],
    "graph_edges":   [...],
}
"""

from datetime import datetime
from typing import Optional
import logging

logger = logging.getLogger(__name__)

# ── Known-hash blocklist ─────────────────────────────────────────────────────

KNOWN_MALICIOUS_HASHES = {
    # EICAR Standard Antivirus Test File (SHA-256)
    "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f": {
        "score": 100,
        "family": "EICAR-Test-File",
        "attribution": "Unattributed",
        "reason": "EICAR standard antivirus test file detected by SHA-256 hash.",
    },
    # Common Emotet loader samples (illustrative — add real hashes here)
    "a3b15c8d4e1276f1e0c3b5a7d9e2f4c6a8b0d2e4f6a8c0b2d4e6f8a0c2b4d6e8": {
        "score": 100,
        "family": "Trojan.Win32.Emotet",
        "attribution": "TA542",
        "reason": "Known Emotet loader sample detected by SHA-256 hash.",
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

    total, all_reasons = 0, []
    family, attribution = None, None
    age = None  # populated by heuristic score path only

    # ── Hash-based detection (highest priority — short-circuit if matched) ────
    file_hash = analysis_data.get("file_hash")
    hash_score, hash_reasons, hash_family, hash_attribution = _check_known_hashes(file_hash)
    if hash_score > 0:
        total += hash_score
        all_reasons += hash_reasons
        family = hash_family
        attribution = hash_attribution
    else:
        # ── Heuristic scoring (only run if no direct hash match) ──────────────
        s, r      = _check_pe_sections(static);    total += s; all_reasons += r
        s, r, age = _check_domain_age(whois);      total += s; all_reasons += r
        s, r      = _check_registrar(whois);       total += s; all_reasons += r
        s, r      = _check_geoip(geoip);           total += s; all_reasons += r
        s, r      = _check_url_flags(url_data);    total += s; all_reasons += r
        s, r      = _check_ioc_volume(iocs);       total += s; all_reasons += r

    final_score = min(total, 100)
    verdict = "Malicious" if final_score >= 70 else "Suspicious" if final_score >= 35 else "Clear"

    graph_nodes, graph_edges = _build_graph(iocs, geoip, whois)

    return {
        "score":       final_score,
        "verdict":     verdict,
        "family":      family or "Unknown",
        "attribution": attribution or "Unattributed",
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
            "dns_a_records":   dns.get("A", []),
        },
        "graph_nodes": graph_nodes,
        "graph_edges": graph_edges,
    }
