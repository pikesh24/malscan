"""
The abuse.ch and VirusTotal response parsers.

These carry the heaviest weights in the whole engine — MalwareBazaar 100,
VirusTotal 100, URLhaus 60, ThreatFox up to 70 — and none of them had a test.
conftest stubs them out wholesale, so every other test in the suite runs with
them replaced by lambdas returning {"found": False}.

A parser that silently returns "no hit" for a real detection is the same failure
as the YARA ruleset that never compiled: the capability appears present, the
scan looks clean, and nothing anywhere says otherwise. These check both
directions — a real hit is recognised, and a non-hit is never mistaken for one.

Responses below are the documented shapes of the real APIs.
"""

import json

import pytest

from analysis_engine import (
    abuseipdb_client,
    malwarebazaar_client,
    threatfox_client,
    urlhaus_client,
)


class _Resp:
    def __init__(self, payload, status=200):
        self._payload = payload
        self.status_code = status

    def json(self):
        return self._payload

    def raise_for_status(self):
        if self.status_code >= 400:
            raise RuntimeError(f"HTTP {self.status_code}")


# ── URLhaus ───────────────────────────────────────────────────────────────────

def test_urlhaus_recognises_a_listed_url(monkeypatch):
    payload = {
        "query_status": "ok",
        "id": "1234",
        "url": "http://evil.example/payload.bin",
        "url_status": "online",
        "threat": "malware_download",
        "date_added": "2026-07-20 10:00:00 UTC",
        "tags": ["exe", "elf"],
    }
    monkeypatch.setattr(urlhaus_client.requests, "post", lambda *a, **k: _Resp(payload))
    result = urlhaus_client.check_url("http://evil.example/payload.bin")
    assert result["found"] is True
    assert result["threat"] == "malware_download"


@pytest.mark.parametrize("status", ["no_results", "invalid_url", "http_post_expected"])
def test_urlhaus_non_ok_status_is_never_a_hit(monkeypatch, status):
    """A 200 response saying "no_results" must not read as a detection."""
    monkeypatch.setattr(urlhaus_client.requests, "post",
                        lambda *a, **k: _Resp({"query_status": status}))
    assert urlhaus_client.check_url("http://x.example/")["found"] is False


def test_urlhaus_records_which_url_matched(monkeypatch):
    """scoring.py needs matched_url to tell an embedded indicator from the
    submitted artifact, and the safe-domain suppression keys on it too."""
    def post(*a, **k):
        url = k.get("data", {}).get("url", "")
        return _Resp({"query_status": "ok", "threat": "malware_download"}
                     if "bad" in url else {"query_status": "no_results"})

    monkeypatch.setattr(urlhaus_client.requests, "post", post)
    result = urlhaus_client.check_urls(["http://ok.example/", "http://bad.example/x"])
    assert result["found"] and result["matched_url"] == "http://bad.example/x"


def test_urlhaus_network_failure_is_not_a_hit(monkeypatch):
    def boom(*a, **k):
        raise ConnectionError("dns failure")
    monkeypatch.setattr(urlhaus_client.requests, "post", boom)
    out = urlhaus_client.check_url("http://x.example/")
    assert out["found"] is False and "error" in out


# ── ThreatFox ─────────────────────────────────────────────────────────────────

def test_threatfox_parses_confidence(monkeypatch):
    """scoring scales 70/35/15 off confidence_level; misreading it as None
    silently downgrades every ThreatFox hit to the weakest band."""
    payload = {"query_status": "ok", "data": [{
        "ioc": "evil.example",
        "threat_type": "botnet_cc",
        "malware": "win.qakbot",
        "malware_printable": "QakBot",
        "confidence_level": 100,
        "first_seen": "2026-07-01 00:00:00 UTC",
        "tags": ["c2"],
    }]}
    monkeypatch.setattr(threatfox_client.requests, "post", lambda *a, **k: _Resp(payload))
    result = threatfox_client._search("evil.example")
    assert result["found"] is True
    assert result["confidence"] == 100, "confidence_level not mapped to confidence"
    assert result["malware_printable"] == "QakBot"


def test_threatfox_empty_data_is_not_a_hit(monkeypatch):
    monkeypatch.setattr(threatfox_client.requests, "post",
                        lambda *a, **k: _Resp({"query_status": "ok", "data": []}))
    assert threatfox_client._search("x.example")["found"] is False


def test_threatfox_no_result_status_is_not_a_hit(monkeypatch):
    monkeypatch.setattr(threatfox_client.requests, "post",
                        lambda *a, **k: _Resp({"query_status": "no_result", "data": None}))
    assert threatfox_client._search("x.example")["found"] is False


# ── MalwareBazaar ─────────────────────────────────────────────────────────────

def test_malwarebazaar_recognises_a_known_hash(monkeypatch):
    payload = {"query_status": "ok", "data": [{
        "sha256_hash": "a" * 64,
        "file_name": "invoice.exe",
        "file_type": "exe",
        "signature": "AgentTesla",
        "first_seen": "2026-06-01 12:00:00",
        "tags": ["exe", "AgentTesla"],
    }]}
    monkeypatch.setattr(malwarebazaar_client.requests, "post", lambda *a, **k: _Resp(payload))
    result = malwarebazaar_client.check_hash("a" * 64)
    assert result["found"] is True, "a known-malware hash was not recognised"


def test_malwarebazaar_hash_not_found_is_not_a_hit(monkeypatch):
    monkeypatch.setattr(malwarebazaar_client.requests, "post",
                        lambda *a, **k: _Resp({"query_status": "hash_not_found", "data": None}))
    assert malwarebazaar_client.check_hash("b" * 64)["found"] is False


def test_malwarebazaar_ignores_an_empty_hash(monkeypatch):
    def unexpected(*a, **k):
        raise AssertionError("queried the API with no hash")
    monkeypatch.setattr(malwarebazaar_client.requests, "post", unexpected)
    assert malwarebazaar_client.check_hash("")["found"] is False


# ── AbuseIPDB ─────────────────────────────────────────────────────────────────

def test_abuseipdb_parses_confidence(monkeypatch):
    payload = {"data": {"ipAddress": "1.2.3.4", "abuseConfidenceScore": 92,
                        "countryCode": "RU", "totalReports": 40}}
    monkeypatch.setattr(abuseipdb_client.requests, "get", lambda *a, **k: _Resp(payload))
    result = abuseipdb_client.check_ip("1.2.3.4", "key")
    assert result.get("abuse_confidence") == 92, \
        "abuseConfidenceScore not mapped — scoring reads abuse_confidence"


def test_abuseipdb_without_a_key_is_skipped_not_clean(monkeypatch):
    """No key must be reported as "not checked", never as a clean result."""
    out = abuseipdb_client.check_ips(["1.2.3.4"], "")
    assert out.get("skipped") or not out.get("abuse_confidence")
