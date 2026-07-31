"""
A file that could not be read must never be reported Clear.

The artifact is read once and the bytes are reused across every analyser. When
that read failed, `raw_bytes` became None and the failure was swallowed: IOC
extraction, PE parsing, YARA and both document analysers all quietly received
nothing, produced nothing, and the scan reported Clear on a file it had never
opened.

The commonest cause is real-time antivirus on the scanning host confiscating the
sample between upload and analysis — which correlates with the file actually
being malicious, making it the worst possible moment to return a clean verdict.
This is not hypothetical: it happened in this project's own test suite, where a
fixture containing a live download cradle was quarantined mid-scan and the test
failed on a permission error.
"""

import pytest

from attribution_module.scoring import calculate_score


def _analysis(**overrides):
    """The shape calculate_score expects, with everything empty — i.e. exactly
    what the pipeline produces when nothing could be read."""
    base = {
        "file_hash": "0" * 64,
        "submitted_url": None,
        "static": {
            "suspicious_sections": [], "pe_sections": [], "is_pe": False,
            "imphash": None, "file_entropy": 0.0, "magic_type": "Unknown",
            "type_mismatch": False, "suspicious_strings": [],
        },
        "osint": {},
        "url": {},
        "iocs": {"ips": [], "domains": [], "urls": []},
        "apk": {},
        "document": {},
    }
    base.update(overrides)
    return base


def test_an_unreadable_artifact_is_not_clear():
    result = calculate_score(_analysis(artifact_unreadable="PermissionError"))

    assert result["verdict"] == "Inconclusive", (
        f"a file that was never read was reported {result['verdict']}"
    )


def test_the_reason_explains_the_quarantine_case():
    """A bland I/O error would leave the user thinking the tool is broken. The
    likely cause is evidence about the file, so the report says so."""
    result = calculate_score(_analysis(artifact_unreadable="PermissionError"))
    reason = result.get("inconclusive_reason") or ""

    assert "could not be read" in reason
    assert "antivirus" in reason.lower()
    assert "PermissionError" in reason


def test_a_readable_but_empty_analysis_is_still_clear():
    """The guard must key on the read having FAILED, not on the analysis being
    empty — plenty of harmless files produce nothing at all."""
    result = calculate_score(_analysis())

    assert result["verdict"] == "Clear"
    assert result.get("inconclusive_reason") is None


def test_a_detection_is_not_downgraded_to_inconclusive():
    """Same rule as everywhere else: Inconclusive only ever replaces a would-be
    Clear, so a real finding is never buried behind 'could not check'."""
    from attribution_module import scoring

    known = "a" * 64
    original = dict(scoring.KNOWN_MALICIOUS_HASHES)
    scoring.KNOWN_MALICIOUS_HASHES[known] = {
        "score": 100, "family": "Test", "attribution": "Unattributed",
        "reason": "test",
    }
    try:
        result = calculate_score(_analysis(file_hash=known, artifact_unreadable="PermissionError"))
        assert result["verdict"] == "Malicious"
    finally:
        scoring.KNOWN_MALICIOUS_HASHES.clear()
        scoring.KNOWN_MALICIOUS_HASHES.update(original)


@pytest.mark.parametrize("error", ["PermissionError", "OSError", "FileNotFoundError"])
def test_any_read_failure_counts(error):
    assert calculate_score(_analysis(artifact_unreadable=error))["verdict"] == "Inconclusive"
