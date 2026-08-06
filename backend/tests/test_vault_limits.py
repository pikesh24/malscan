"""
Stored artifacts must be bounded by something other than luck.

`cleanup_vault` was called once, at module import — not on a schedule, not on a
startup event. A process that stays up for ninety days accumulated ninety days
of files, because nothing ran it again. And retention alone bounds nothing over
a short window: at the submission limit a client can write gigabytes in minutes,
none of it old enough to delete for weeks.

Full remediation is object storage with a quota. This is the free version: sweep
on a timer, and refuse new submissions once the vault is over budget — a 507
that names the reason, rather than filling the disk and failing in ways nobody
can read.
"""
import io
import os

import pytest

from app import main as app_main


def test_over_budget_submissions_are_refused(client, monkeypatch):
    monkeypatch.setattr(app_main, "VAULT_MAX_BYTES", 1)          # everything is over budget
    monkeypatch.setattr(app_main, "_vault_bytes", lambda: 10_000)

    res = client.post("/upload", files={"file": ("x.txt", io.BytesIO(b"data"), "text/plain")})

    assert res.status_code == 507, res.text
    assert "storage" in res.json()["detail"].lower()


def test_under_budget_submissions_go_through(client, monkeypatch):
    monkeypatch.setattr(app_main, "_vault_bytes", lambda: 0)

    res = client.post("/upload", files={"file": ("y.txt", io.BytesIO(b"data"), "text/plain")})

    assert res.status_code == 200, res.text


def test_the_sweep_runs_again_after_the_interval(client, monkeypatch):
    """The bug was that it only ever ran once, at import."""
    calls = []
    monkeypatch.setattr(app_main, "cleanup_vault", lambda d, days_old: calls.append(days_old))
    monkeypatch.setattr(app_main, "_vault_bytes", lambda: 0)
    # "Long ago" has to be relative to the clock actually in use. This was 0.0,
    # which reads as long ago on a workstation that has been up for days and as
    # *just now* on a CI runner booted seconds earlier — time.monotonic() counts
    # from boot, so 0.0 is only distant if the machine has been running a while.
    # The suite passed on Windows and failed on Linux for exactly that reason.
    monkeypatch.setattr(app_main, "_last_vault_sweep",
                        app_main.time.monotonic() - app_main.VAULT_SWEEP_INTERVAL_S - 1)

    client.post("/upload", files={"file": ("z.txt", io.BytesIO(b"data"), "text/plain")})

    assert calls, "a submission after the sweep interval did not trigger cleanup"


def test_the_sweep_does_not_run_on_every_request(client, monkeypatch):
    """Walking the vault per submission would be its own denial of service."""
    calls = []
    monkeypatch.setattr(app_main, "cleanup_vault", lambda d, days_old: calls.append(days_old))
    monkeypatch.setattr(app_main, "_vault_bytes", lambda: 0)
    monkeypatch.setattr(app_main, "_last_vault_sweep", app_main.time.monotonic())

    for i in range(3):
        client.post("/upload", files={"file": (f"a{i}.txt", io.BytesIO(f"d{i}".encode()), "text/plain")})

    assert not calls, f"cleanup ran {len(calls)} times within the interval"


def test_the_rate_limiter_does_not_grow_without_bound(monkeypatch):
    """Each distinct source IP allocated a deque that was never reclaimed."""
    monkeypatch.setattr(app_main, "_SUBMISSION_LOG_MAX_IPS", 10)
    app_main._submission_log.clear()

    class _Req:
        def __init__(self, host):
            self.client = type("C", (), {"host": host})()

    # Aged-out entries from many distinct addresses.
    for i in range(50):
        app_main._enforce_rate_limit(_Req(f"10.0.0.{i}"))
    for entries in app_main._submission_log.values():
        entries.clear()
    app_main._enforce_rate_limit(_Req("10.0.1.1"))

    assert len(app_main._submission_log) <= 11, (
        f"limiter retained {len(app_main._submission_log)} empty per-IP entries"
    )
    app_main._submission_log.clear()
