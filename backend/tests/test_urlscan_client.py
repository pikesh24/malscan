"""
URLScan.io response parsing.

`_check_urlscan` awards +40 when `is_malicious` is set and +15 on a non-zero
verdict score, and for a submitted URL that counts as artifact evidence — so it
can carry a verdict. It also supplies the screenshot and the outgoing-domain
list the report renders.

Like the other enrichers it is stubbed out for the whole test suite, so nothing
had ever run the real parser. The failure mode is quiet: a mis-read verdict
contributes nothing, raises no error, and leaves a scan looking like URLScan had
no opinion.

Payloads below follow the documented v1 result shape.
"""

import time

import pytest

from analysis_engine import urlscan_client


class _Resp:
    def __init__(self, payload, status=200):
        self._payload, self.status_code = payload, status

    def json(self):
        return self._payload


def _result(malicious=True, score=80):
    return {
        "task": {"url": "http://evil.example/login", "uuid": "abc-123"},
        "page": {
            "title": "Sign in", "ip": "203.0.113.5",
            "country": "RU", "server": "nginx",
        },
        "verdicts": {"overall": {"malicious": malicious, "score": score}},
        "lists": {"domains": ["evil.example", "cdn.evil.example", "tracker.example"]},
    }


@pytest.fixture(autouse=True)
def _no_sleeping(monkeypatch):
    """scan_url sleeps 6s then polls every 4s; tests must not actually wait."""
    monkeypatch.setattr(time, "sleep", lambda *_: None)


# ── Parsing ───────────────────────────────────────────────────────────────────

def test_malicious_verdict_is_parsed(monkeypatch):
    monkeypatch.setattr(urlscan_client, "_find_recent_scan", lambda *a, **k: None)
    monkeypatch.setattr(urlscan_client.requests, "post",
                        lambda *a, **k: _Resp({"api": "https://urlscan.io/api/v1/result/abc-123/",
                                               "uuid": "abc-123"}))
    monkeypatch.setattr(urlscan_client.requests, "get", lambda *a, **k: _Resp(_result()))

    out = urlscan_client.scan_url("http://evil.example/login", "key")
    assert out["is_malicious"] is True, "verdicts.overall.malicious not mapped"
    assert out["verdict_score"] == 80
    assert out["page_country"] == "RU"
    assert "abc-123" in out["screenshot_url"]
    assert out["outgoing_domains"][0] == "evil.example"


def test_clean_verdict_is_not_read_as_malicious(monkeypatch):
    monkeypatch.setattr(urlscan_client, "_find_recent_scan", lambda *a, **k: None)
    monkeypatch.setattr(urlscan_client.requests, "post",
                        lambda *a, **k: _Resp({"api": "x", "uuid": "u"}))
    monkeypatch.setattr(urlscan_client.requests, "get",
                        lambda *a, **k: _Resp(_result(malicious=False, score=0)))

    out = urlscan_client.scan_url("http://ok.example/", "key")
    assert out["is_malicious"] is False
    assert out["verdict_score"] == 0


def test_missing_verdict_block_defaults_to_not_malicious(monkeypatch):
    """A result without verdicts must not raise, and must not invent a hit."""
    monkeypatch.setattr(urlscan_client, "_find_recent_scan", lambda *a, **k: None)
    monkeypatch.setattr(urlscan_client.requests, "post",
                        lambda *a, **k: _Resp({"api": "x", "uuid": "u"}))
    monkeypatch.setattr(urlscan_client.requests, "get",
                        lambda *a, **k: _Resp({"task": {}, "page": {}}))

    out = urlscan_client.scan_url("http://x.example/", "key")
    assert out["is_malicious"] is False
    assert out["verdict_score"] == 0


def test_outgoing_domains_are_capped(monkeypatch):
    """The report renders these; an unbounded list from a link-farm page would
    be pasted into the document wholesale."""
    payload = _result()
    payload["lists"]["domains"] = [f"d{i}.example" for i in range(50)]
    monkeypatch.setattr(urlscan_client, "_find_recent_scan", lambda *a, **k: None)
    monkeypatch.setattr(urlscan_client.requests, "post",
                        lambda *a, **k: _Resp({"api": "x", "uuid": "u"}))
    monkeypatch.setattr(urlscan_client.requests, "get", lambda *a, **k: _Resp(payload))

    assert len(urlscan_client.scan_url("http://x.example/", "key")["outgoing_domains"]) <= 10


# ── Failure paths must never look like a clean result ────────────────────────

def test_no_api_key_is_an_error(monkeypatch):
    out = urlscan_client.scan_url("http://x.example/", "")
    assert "error" in out
    assert "is_malicious" not in out, "a keyless call produced a verdict"


def test_rate_limit_is_reported(monkeypatch):
    monkeypatch.setattr(urlscan_client, "_find_recent_scan", lambda *a, **k: None)
    monkeypatch.setattr(urlscan_client.requests, "post", lambda *a, **k: _Resp({}, status=429))
    out = urlscan_client.scan_url("http://x.example/", "key")
    assert "error" in out and "rate limit" in out["error"].lower()


def test_blocked_major_domain_is_explained(monkeypatch):
    """URLScan refuses to scan popular sites; that is not a detection and the
    report should say why rather than showing an empty panel."""
    monkeypatch.setattr(urlscan_client, "_find_recent_scan", lambda *a, **k: None)
    monkeypatch.setattr(urlscan_client.requests, "post",
                        lambda *a, **k: _Resp({"message": "Scanning this domain is prevented"},
                                              status=400))
    out = urlscan_client.scan_url("https://google.com/", "key")
    assert "error" in out and "does not allow" in out["error"].lower()
    assert "is_malicious" not in out


def test_timeout_is_an_error_not_a_verdict(monkeypatch):
    import requests as _rq
    monkeypatch.setattr(urlscan_client, "_find_recent_scan", lambda *a, **k: None)

    def boom(*a, **k):
        raise _rq.exceptions.Timeout()
    monkeypatch.setattr(urlscan_client.requests, "post", boom)

    out = urlscan_client.scan_url("http://x.example/", "key")
    assert "error" in out and "is_malicious" not in out


def test_never_completing_scan_reports_pending(monkeypatch):
    """Polling exhaustion must be distinguishable from "scanned, found nothing"."""
    monkeypatch.setattr(urlscan_client, "_find_recent_scan", lambda *a, **k: None)
    monkeypatch.setattr(urlscan_client.requests, "post",
                        lambda *a, **k: _Resp({"api": "x", "uuid": "u"}))
    monkeypatch.setattr(urlscan_client.requests, "get", lambda *a, **k: _Resp({}, status=404))

    out = urlscan_client.scan_url("http://x.example/", "key")
    assert out.get("status") == "pending"
    assert "is_malicious" not in out


# ── The search fast path ──────────────────────────────────────────────────────

def test_recent_public_scan_is_reused(monkeypatch):
    """Saves quota — but it must actually parse, not just avoid the submit."""
    from datetime import datetime, timezone

    now = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    search = {"results": [{"task": {"time": now},
                           "result": "https://urlscan.io/api/v1/result/xyz/",
                           "_id": "xyz"}]}

    def get(url, **k):
        return _Resp(search) if "search" in url else _Resp(_result())

    monkeypatch.setattr(urlscan_client.requests, "get", get)

    def unexpected(*a, **k):
        raise AssertionError("submitted a fresh scan despite a recent one existing")
    monkeypatch.setattr(urlscan_client.requests, "post", unexpected)

    out = urlscan_client.scan_url("http://evil.example/login", "key")
    assert out["is_malicious"] is True
    assert "xyz" in out["screenshot_url"]


def test_stale_scan_is_not_reused(monkeypatch):
    """A verdict older than the freshness window must not stand in for a scan —
    a URL that was clean a year ago tells you nothing about it today."""
    from datetime import datetime, timedelta, timezone

    old = (datetime.now(timezone.utc)
           - timedelta(days=urlscan_client.RECENT_SCAN_MAX_AGE_DAYS + 5)
           ).isoformat().replace("+00:00", "Z")
    search = {"results": [{"task": {"time": old},
                           "result": "https://urlscan.io/api/v1/result/old/", "_id": "old"}]}

    monkeypatch.setattr(urlscan_client.requests, "get",
                        lambda url, **k: _Resp(search) if "search" in url else _Resp(_result()))
    submitted = {"called": False}

    def post(*a, **k):
        submitted["called"] = True
        return _Resp({"api": "x", "uuid": "fresh"})
    monkeypatch.setattr(urlscan_client.requests, "post", post)

    urlscan_client.scan_url("http://evil.example/login", "key")
    assert submitted["called"], "a stale scan was reused instead of rescanning"


def test_search_failure_falls_back_to_a_fresh_scan(monkeypatch):
    """The fast path is an optimisation; if it breaks, scanning must continue."""
    def boom(*a, **k):
        raise ConnectionError("search down")
    monkeypatch.setattr(urlscan_client.requests, "get", boom)
    monkeypatch.setattr(urlscan_client.requests, "post",
                        lambda *a, **k: _Resp({"api": "x", "uuid": "u"}))

    out = urlscan_client.scan_url("http://x.example/", "key")
    # get() is also used for polling, so this ends pending rather than parsed —
    # the point is that it did not raise and did submit.
    assert "error" in out or out.get("status") == "pending"
