"""
backend/app/indicator_index.py

Inverted-index helpers backing cross-job clustering. Instead of loading every
prior job's full results JSON on each scan (O(n) memory + compute), each job's
indicators are recorded once in the `indicator_index` table, and a new scan only
looks up the rows matching its own indicators (O(k·log n)).

DB access lives here (where the models are importable) so that
`attribution_module/clustering.py` stays a pure, DB-free algorithm.
"""

from .models import IndicatorIndex, ScanJob

# kinds tracked in the index — mirror what clustering compares on
_KINDS = ("ip", "domain", "asn", "registrar")


def _values_for(score_data: dict) -> dict:
    """Extract the indexable values of each kind from a job's score_data."""
    indicators = score_data.get("indicators", {}) or {}
    osint = score_data.get("osint_summary", {}) or {}
    asn = osint.get("asn")
    registrar = osint.get("registrar")
    return {
        "ip":        list(indicators.get("ips") or []),
        "domain":    list(indicators.get("domains") or []),
        "asn":       [asn] if asn else [],
        "registrar": [registrar] if registrar else [],
    }


def index_job_indicators(db, job_id: str, score_data: dict) -> None:
    """Record this job's indicators in the index for future scans to match against."""
    rows, seen = [], set()
    for kind, values in _values_for(score_data).items():
        for value in values:
            if value and (kind, value) not in seen:
                seen.add((kind, value))
                rows.append(IndicatorIndex(value=value, kind=kind, job_id=job_id))
    if rows:
        db.add_all(rows)
        db.commit()


def lookup_prior_jobs(db, current_job_id: str, score_data: dict) -> dict:
    """
    Return {kind: {value: [other_job_ids]}} for the current job's values —
    only indicators that already appear in OTHER ARTIFACTS. Targeted indexed
    query, not a full-history scan.

    "Other" is keyed on file_hash, not job_id: the same artifact rescanned
    produces a new job carrying identical indicators, so matching on job_id alone
    would make a file cluster with copies of itself and render as a campaign
    ("shares 4 indicators with 4 other jobs" — all of them itself). That was
    masked while a 24h result cache short-circuited duplicate scans before they
    were ever indexed; with only a 60s debounce, rescans are normal and this
    exclusion is what keeps clustering meaningful.
    """
    out = {k: {} for k in _KINDS}
    current_hash = (
        db.query(ScanJob.file_hash)
          .filter(ScanJob.job_id == current_job_id)
          .scalar()
    )
    for kind, values in _values_for(score_data).items():
        if not values:
            continue
        query = (
            db.query(IndicatorIndex.value, IndicatorIndex.job_id)
              .filter(
                  IndicatorIndex.kind == kind,
                  IndicatorIndex.value.in_(values),
                  IndicatorIndex.job_id != current_job_id,
              )
        )
        if current_hash:
            query = (
                query.join(ScanJob, ScanJob.job_id == IndicatorIndex.job_id)
                     .filter(ScanJob.file_hash != current_hash)
            )
        rows = query.all()
        matches: dict = {}
        for value, jid in rows:
            bucket = matches.setdefault(value, [])
            if jid not in bucket:
                bucket.append(jid)
        out[kind] = matches
    return out


def backfill_indicator_index(db) -> None:
    """
    One-time population from existing completed jobs so pre-existing installs keep
    clustering correctly. Idempotent: no-op once the index has any rows (and on a
    fresh/test DB there are no prior jobs, so it does nothing).
    """
    if db.query(IndicatorIndex.id).first() is not None:
        return
    for job in db.query(ScanJob).filter(ScanJob.status == "Completed").all():
        if isinstance(job.results, dict):
            index_job_indicators(db, job.job_id, job.results)
