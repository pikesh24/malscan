"""
The report embeds strings taken straight from a scanned artifact — its filename,
the URLs and IPs inside it, YARA descriptions, WHOIS and GeoIP fields. All of it
is attacker-controlled: whoever makes the file chooses those bytes.

The report is then served from the app's own origin and exported to PDF, so an
unescaped value is stored XSS on the scanner's domain, triggered by an analyst
opening a report — the one action they are guaranteed to take.

reporter.py sets autoescape=True and report_charts.py returns pre-escaped
Markup, so this should hold. But report_charts builds SVG by hand with
f-strings, where one un-escaped interpolation is enough, and nothing had ever
pushed a payload through every field at once.
"""

import re

from attribution_module import reporter

XSS = '"><script>alert(1)</script>'
BREAKOUT = "</title></head><body><script>alert(2)</script>"


def _score_data():
    """Every string field a scanned artifact can influence, poisoned."""
    return {
        "score": 55,
        "verdict": "Suspicious",
        "family": XSS,
        "attribution": XSS,
        "partial": False,
        "reasons": [XSS, BREAKOUT, "ordinary reason"],
        "indicators": {
            "ips": ["1.2.3.4"],
            "domains": [XSS, "evil.example"],
            "urls": ["http://evil.example/" + XSS],
        },
        "osint_summary": {
            "registrar": XSS, "asn": XSS, "country": XSS, "hosting": XSS,
            "city": XSS, "region": XSS, "domain_age_days": 5,
            "country_code": "XX", "dns_a_records": [XSS],
            "virustotal": {"malicious": 3, "suspicious": 1, "harmless": 20, "undetected": 30},
            "virustotal_detections": [{"engine": XSS, "result": XSS}],
        },
        "score_breakdown": [{"label": XSS, "points": 25},
                            {"label": "Normal Label", "points": 10}],
        "risk_profile": [
            {"key": "file_reputation", "label": XSS, "value": 40, "description": XSS},
            {"key": "network_reputation", "label": "Network", "value": 20, "description": "ok"},
        ],
        "graph_nodes": [{"id": XSS, "label": XSS, "type": "domain", "risk": "high"}],
        "graph_edges": [],
        "yara_matches": [{"rule": XSS, "description": XSS, "severity": "high"}],
        "archive_contents": [{"name": XSS, "size": 10}],
        "apk_info": {"is_apk": True, "package": XSS, "app_label": XSS,
                     "permissions": [XSS], "dangerous_permissions": [XSS]},
        "is_pe": True,
        "pe_sections": [{"name": XSS, "entropy": 7.5, "size": 100}],
        "clusters": {},
    }


def _render(tmp_path):
    reporter.REPORTS_DIR = str(tmp_path)
    meta = {"file_hash": "a" * 64, "original_filename": XSS}
    reporter.generate_report("job-xss-test", _score_data(), meta)
    with open(reporter.get_report_path("job-xss-test"), encoding="utf-8") as fh:
        return fh.read()


def test_no_executable_script_survives_into_the_report(tmp_path):
    html = _render(tmp_path)
    # The literal payload must never appear unescaped anywhere in the document.
    assert "<script>alert(1)</script>" not in html, "XSS payload rendered as live markup"
    assert "<script>alert(2)</script>" not in html, "tag-breakout payload rendered live"


def test_payload_is_present_but_escaped(tmp_path):
    """Escaped, not silently dropped — the report must still show what was found."""
    html = _render(tmp_path)
    assert "&lt;script&gt;" in html or "&lt;/title&gt;" in html, \
        "hostile strings vanished entirely instead of being escaped"


def test_no_unbalanced_script_tags(tmp_path):
    """A crude structural check: every <script> the template legitimately emits
    must be matched, so no injected fragment has opened one."""
    html = _render(tmp_path)
    opens = len(re.findall(r"<script\b", html, re.I))
    closes = len(re.findall(r"</script\s*>", html, re.I))
    assert opens == closes, f"unbalanced script tags: {opens} open, {closes} close"


def test_svg_charts_do_not_leak_raw_markup(tmp_path):
    """report_charts builds SVG with f-strings; one missed escape() is enough."""
    html = _render(tmp_path)
    for svg in re.findall(r"<svg\b.*?</svg>", html, re.S | re.I):
        assert "<script" not in svg.lower(), "script element inside a generated chart"
        assert "onerror=" not in svg.lower() and "onload=" not in svg.lower(), \
            "event handler injected into a generated chart"
