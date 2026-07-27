"""
VirusTotal response parsing — the single heaviest signal in the engine.

_check_virustotal awards up to +100 and, when it comes back clean across 40+
engines, halves the entire heuristic score. Both directions therefore matter a
great deal, and neither had a test: conftest replaces the client with a stub for
every other test in the suite.

The specific risk is quiet. If `stats` came back empty or mis-shaped, VT would
contribute nothing, no error would be raised, and the scan would simply look
like VirusTotal had no opinion — the same silent-capability-loss that hid the
uncompilable YARA ruleset.
"""

import pytest

from analysis_engine import vt_client


class _Resp:
    def __init__(self, payload, status=200):
        self._payload, self.status_code = payload, status

    def json(self):
        return self._payload

    def raise_for_status(self):
        if self.status_code >= 400:
            raise RuntimeError(str(self.status_code))


def _url_report(malicious=8, suspicious=1, harmless=51, undetected=33):
    """The documented v3 shape for GET /urls/{id}."""
    return {"data": {"attributes": {
        "last_analysis_stats": {
            "malicious": malicious, "suspicious": suspicious,
            "harmless": harmless, "undetected": undetected, "timeout": 0,
        },
        "last_analysis_results": {
            "Kaspersky": {"category": "malicious", "result": "phishing"},
            "BitDefender": {"category": "malicious", "result": "malware"},
            "CleanEngine": {"category": "harmless", "result": "clean"},
        },
        "reputation": -14,
    }}}


def test_detected_url_reports_its_stats(monkeypatch):
    monkeypatch.setattr(vt_client, "_get_with_rate_limit_retry",
                        lambda *a, **k: _Resp(_url_report()))
    out = vt_client.get_url_report("http://evil.example/", "key")
    assert out.get("stats", {}).get("malicious") == 8, \
        "last_analysis_stats not mapped to stats — VT would contribute nothing"
    assert out.get("vt_status") == "found"


def test_named_vendor_detections_are_extracted(monkeypatch):
    """The report lists which engines flagged it; an empty list reads as
    'no engine said anything', which is a different claim."""
    monkeypatch.setattr(vt_client, "_get_with_rate_limit_retry",
                        lambda *a, **k: _Resp(_url_report()))
    detections = vt_client.get_url_report("http://evil.example/", "key").get("detections") or []
    joined = " ".join(str(d) for d in detections).lower()
    assert "kaspersky" in joined or "bitdefender" in joined, \
        f"malicious vendor verdicts not surfaced: {detections}"


def test_clean_url_reports_a_full_engine_count(monkeypatch):
    """The benign-consensus dampener only fires at 40+ engines, so an
    under-reported count silently disables it."""
    monkeypatch.setattr(vt_client, "_get_with_rate_limit_retry",
                        lambda *a, **k: _Resp(_url_report(malicious=0, suspicious=0,
                                                          harmless=20, undetected=50)))
    stats = vt_client.get_url_report("http://ok.example/", "key")["stats"]
    assert sum(stats.get(k, 0) for k in ("malicious", "suspicious", "harmless", "undetected")) >= 40


def test_missing_api_key_is_an_error_not_a_clean_result(monkeypatch):
    """No key must never look like "VirusTotal found nothing"."""
    out = vt_client.get_url_report("http://x.example/", "")
    assert "error" in out
    assert not out.get("stats"), "a keyless call produced stats"


def test_network_failure_is_reported_not_swallowed(monkeypatch):
    """main.py keys `intel_partial` off this: a failed VT lookup must be
    distinguishable from a completed one, or a rate-limited scan of real malware
    gets reported as Clear."""
    def boom(*a, **k):
        raise ConnectionError("timeout")
    monkeypatch.setattr(vt_client, "_get_with_rate_limit_retry", boom)
    out = vt_client.get_url_report("http://x.example/", "key")
    assert "error" in out or out.get("vt_status") in ("error", "queued", "pending")
    assert not out.get("stats")
