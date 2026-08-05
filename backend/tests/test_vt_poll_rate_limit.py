"""
A throttled VirusTotal poll is not "still analysing".

Both poll loops treated every non-200 as "not ready yet", so an HTTP 429
consumed one of the attempts. Nine polls at five-second intervals is twelve
requests a minute against a four-per-minute ceiling, which guarantees throttling
— so a scan could burn its whole budget being rate limited while VirusTotal had
a finished verdict waiting, then report `queued`. That marks the scan partial
and downgrades a good result to Inconclusive.

The rate-limit retry helper existed but was only ever applied to the two initial
lookups, never to the polls.
"""

import pytest

from analysis_engine import vt_client


class _Resp:
    def __init__(self, payload=None, status=200):
        self._payload, self.status_code = payload or {}, status

    def json(self):
        return self._payload


def _completed(stats=None):
    return _Resp({"data": {"attributes": {
        "status": "completed",
        "stats": stats or {"malicious": 7, "suspicious": 0, "harmless": 50, "undetected": 12},
        "results": {"VendorA": {"category": "malicious", "result": "Trojan"}},
    }}})


_RUNNING = _Resp({"data": {"attributes": {"status": "queued"}}})
_THROTTLED = _Resp({}, status=429)


@pytest.fixture(autouse=True)
def _no_sleeping(monkeypatch):
    monkeypatch.setattr(vt_client.time, "sleep", lambda *_: None)


def _sequence(monkeypatch, responses):
    """Serves the given responses in order, then repeats the last one."""
    calls = {"n": 0}

    def get(*a, **k):
        i = min(calls["n"], len(responses) - 1)
        calls["n"] += 1
        return responses[i]

    monkeypatch.setattr(vt_client.requests, "get", get)
    return calls


# ── The core defect ──────────────────────────────────────────────────────────

def test_throttling_does_not_consume_a_polling_attempt(monkeypatch):
    """Two 429s, then the verdict — with a budget of a SINGLE attempt.

    It can only reach the verdict if throttled responses are not counted. This
    failed against the first version of the fix, which used `for _ in
    range(attempts)`: a `continue` still spends the iteration, so the code
    consumed the budget it was written to protect while its own comment claimed
    the opposite.
    """
    calls = _sequence(monkeypatch, [_THROTTLED, _THROTTLED, _completed()])

    attrs, status = vt_client._poll_analysis("id", {}, attempts=1, interval=1)

    assert status == "completed", "throttled polls were counted as progress"
    assert attrs["stats"]["malicious"] == 7
    assert calls["n"] == 3


def test_persistent_throttling_is_reported_as_rate_limited_not_pending(monkeypatch):
    """The operator needs to know the quota was the bottleneck, not the
    analysis — they are different problems with different fixes."""
    _sequence(monkeypatch, [_THROTTLED])

    attrs, status = vt_client._poll_analysis("id", {}, attempts=9, interval=1)

    assert status == "rate_limited"
    assert attrs is None


def test_a_genuinely_slow_analysis_is_still_pending(monkeypatch):
    """Not every incomplete poll is a rate limit — a 200 that says 'queued'
    means VirusTotal really is still working."""
    _sequence(monkeypatch, [_RUNNING])

    attrs, status = vt_client._poll_analysis("id", {}, attempts=3, interval=1)

    assert status == "pending"
    assert attrs is None


def test_throttling_is_bounded_so_a_scan_cannot_hang(monkeypatch):
    """Not counting 429s must not become an unbounded retry loop."""
    calls = _sequence(monkeypatch, [_THROTTLED])

    vt_client._poll_analysis("id", {}, attempts=9, interval=1)

    assert calls["n"] <= vt_client.VT_MAX_THROTTLED_POLLS + 1, (
        f"made {calls['n']} throttled polls — the cap is not holding"
    )


def test_a_network_error_mid_poll_does_not_abort_the_scan(monkeypatch):
    import requests as _rq

    responses = [_rq.exceptions.ConnectionError("boom"), _completed()]
    calls = {"n": 0}

    def get(*a, **k):
        item = responses[min(calls["n"], len(responses) - 1)]
        calls["n"] += 1
        if isinstance(item, Exception):
            raise item
        return item

    monkeypatch.setattr(vt_client.requests, "get", get)

    _, status = vt_client._poll_analysis("id", {}, attempts=5, interval=1)
    assert status == "completed"


# ── The callers surface it correctly ─────────────────────────────────────────

def test_file_upload_reports_rate_limiting_distinctly(monkeypatch):
    monkeypatch.setattr(vt_client.requests, "post",
                        lambda *a, **k: _Resp({"data": {"id": "abc"}}))
    monkeypatch.setattr(vt_client, "_poll_analysis", lambda *a, **k: (None, "rate_limited"))
    monkeypatch.setattr(vt_client.os.path, "getsize", lambda p: 1024)
    monkeypatch.setattr(vt_client, "open", lambda *a, **k: __import__("io").BytesIO(b"x"),
                        raising=False)

    out = vt_client.upload_file(__file__, "key")

    assert out["vt_status"] == "rate_limited"
    assert "stats" not in out, "a throttled scan must not produce a verdict"


def test_rate_limited_counts_as_incomplete_intel(monkeypatch):
    """If the pipeline did not treat it as incomplete, a throttled scan would be
    scored as a clean 0 — the exact failure the partial mechanism exists for."""
    from app import main

    incomplete = main.process_scan_job.__globals__.get("_intel_incomplete")
    if incomplete is None:
        pytest.skip("_intel_incomplete is a closure; covered end to end elsewhere")
    assert incomplete({"vt_status": "rate_limited"}) is True
