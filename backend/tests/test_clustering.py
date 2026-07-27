"""
Cross-scan infrastructure clustering — the "related scans" graph.

Two pieces: an inverted index in app/indicator_index.py that records which jobs
contain which indicators, and a pure algorithm in attribution_module/clustering.py
that turns a lookup into shared-infrastructure findings.

The failure here is not a wrong verdict but a wrong *story*. The comment on
lookup_prior_jobs describes a bug where a rescanned file clustered with copies of
itself and rendered as a campaign — "shares 4 indicators with 4 other jobs", all
of them the same artifact. That exclusion keys on file_hash rather than job_id,
which is subtle enough to be worth pinning, especially now that a 60-second
debounce (rather than a 24-hour cache) makes rescans ordinary.
"""

import pytest

from app.indicator_index import (
    backfill_indicator_index,
    index_job_indicators,
    lookup_prior_jobs,
)
from app.models import ScanJob
from attribution_module.clustering import cluster_iocs


def _results(ips=(), domains=(), asn=None, registrar=None):
    return {
        "indicators": {"ips": list(ips), "domains": list(domains), "urls": []},
        "osint_summary": {"asn": asn, "registrar": registrar},
    }


@pytest.fixture
def db():
    from app.database import SessionLocal
    session = SessionLocal()
    try:
        yield session
    finally:
        session.close()


def _add_job(db, job_id, file_hash, results):
    db.add(ScanJob(job_id=job_id, file_hash=file_hash, status="Completed", results=results))
    db.commit()
    index_job_indicators(db, job_id, results)


# ── The algorithm ─────────────────────────────────────────────────────────────

def test_shared_ip_produces_a_cluster_and_a_signal():
    prior = {"ip": {"1.2.3.4": ["job-old"]}, "domain": {}, "asn": {}, "registrar": {}}
    out = cluster_iocs("job-new", _results(ips=["1.2.3.4"]), prior)

    assert out["shared_ips"]["1.2.3.4"] == ["job-old", "job-new"]
    assert out["cluster_count"] == 1
    assert any("same IP" in s for s in out["risk_signals"])


def test_an_indicator_no_prior_job_has_is_not_a_cluster():
    prior = {"ip": {}, "domain": {}, "asn": {}, "registrar": {}}
    out = cluster_iocs("job-new", _results(ips=["9.9.9.9"], domains=["x.example"]), prior)
    assert out["cluster_count"] == 0
    assert out["risk_signals"] == []


def test_asn_and_registrar_cluster_without_claiming_a_count():
    """Every scan has an ASN and a registrar, so those signals are worded as
    context rather than as "seen in N jobs"."""
    prior = {"ip": {}, "domain": {},
             "asn": {"AS9009": ["job-a", "job-b"]},
             "registrar": {"NameCheap": ["job-a"]}}
    out = cluster_iocs("job-new", _results(asn="AS9009", registrar="NameCheap"), prior)

    assert out["shared_asns"]["AS9009"] == ["job-a", "job-b", "job-new"]
    assert out["cluster_count"] == 2
    assert any("ASN: 'AS9009'" in s for s in out["risk_signals"])


def test_duplicate_prior_job_ids_are_collapsed():
    prior = {"ip": {"1.2.3.4": ["job-a", "job-a", "job-b"]}, "domain": {}, "asn": {}, "registrar": {}}
    out = cluster_iocs("job-new", _results(ips=["1.2.3.4"]), prior)
    assert out["shared_ips"]["1.2.3.4"] == ["job-a", "job-b", "job-new"]


def test_missing_lookup_kinds_do_not_raise():
    """clustering must tolerate a partial lookup rather than take a scan down."""
    out = cluster_iocs("job-new", _results(ips=["1.2.3.4"], asn="AS1"), {})
    assert out["cluster_count"] == 0


# ── The index ─────────────────────────────────────────────────────────────────

def test_indicators_are_found_across_different_artifacts(db):
    _add_job(db, "job-1", "hash-aaa", _results(ips=["203.0.113.9"], domains=["shared.example"]))
    found = lookup_prior_jobs(db, "job-2", _results(ips=["203.0.113.9"]))
    assert found["ip"]["203.0.113.9"] == ["job-1"]


def test_a_rescan_of_the_same_file_is_not_a_campaign(db):
    """The documented bug: the same artifact scanned twice produced a second job
    with identical indicators, and matching on job_id alone made the file cluster
    with itself — reported to the user as shared infrastructure.

    Exclusion is on file_hash, and with a 60-second debounce rather than a 24-hour
    cache, rescans are ordinary rather than rare.
    """
    results = _results(ips=["198.51.100.7"], domains=["repeat.example"])
    _add_job(db, "job-first", "hash-same", results)

    db.add(ScanJob(job_id="job-second", file_hash="hash-same",
                   status="Completed", results=results))
    db.commit()

    found = lookup_prior_jobs(db, "job-second", results)
    assert found["ip"] == {}, "a file clustered with an earlier scan of itself"
    assert found["domain"] == {}

    out = cluster_iocs("job-second", results, found)
    assert out["cluster_count"] == 0, "rescanning one file rendered as a campaign"


def test_a_different_file_sharing_infrastructure_still_clusters(db):
    """The fix must not suppress genuine shared infrastructure."""
    results_a = _results(ips=["198.51.100.20"])
    _add_job(db, "job-a", "hash-a", results_a)

    results_b = _results(ips=["198.51.100.20"])
    db.add(ScanJob(job_id="job-b", file_hash="hash-b", status="Completed", results=results_b))
    db.commit()

    found = lookup_prior_jobs(db, "job-b", results_b)
    assert found["ip"]["198.51.100.20"] == ["job-a"]


def test_indexing_is_idempotent_for_repeated_values(db):
    """The same value listed twice in one job must not be indexed twice."""
    results = _results(ips=["203.0.113.55", "203.0.113.55"], domains=["dup.example"])
    _add_job(db, "job-dup", "hash-dup", results)

    db.add(ScanJob(job_id="job-other", file_hash="hash-other", status="Completed", results=results))
    db.commit()
    found = lookup_prior_jobs(db, "job-other", results)
    assert found["ip"]["203.0.113.55"] == ["job-dup"]


def test_backfill_is_a_noop_once_the_index_is_populated(db):
    """It runs at import time on every start, so re-entering it must not double
    up rows — a duplicated index would inflate every cluster count."""
    from app.models import IndicatorIndex

    _add_job(db, "job-bf", "hash-bf", _results(ips=["203.0.113.77"]))
    before = db.query(IndicatorIndex).count()

    backfill_indicator_index(db)

    assert db.query(IndicatorIndex).count() == before, "backfill duplicated index rows"
    found = lookup_prior_jobs(db, "job-bf-other", _results(ips=["203.0.113.77"]))
    assert found["ip"]["203.0.113.77"] == ["job-bf"]
