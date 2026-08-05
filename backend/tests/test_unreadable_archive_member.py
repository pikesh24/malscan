"""
A quarantined archive member must not leave the archive looking Clear.

Companion to test_unreadable_artifact.py, which covers the same failure for the
top-level file. This case was left behind, and it is the more common one: real
antivirus grabs extracted members constantly, because extraction is the moment a
payload first exists on disk as itself.

Found by scanning a ZIP containing a shortcut with an encoded PowerShell command.
Bitdefender took the member between extraction and analysis, so the shortcut was
never parsed, nothing scored, and the verdict was **Clear with no reasons at
all** — on an archive whose one interesting file had just been confiscated as
malware. `archive_unreadable` recorded it and the report showed a caveat panel,
but the verdict itself did not move.

An antivirus product removing a file is evidence about that file. It is the
strongest possible reason not to say Clear.
"""

import io
import zipfile

import pytest


def _zip(members: dict) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        for name, body in members.items():
            z.writestr(name, body)
    return buf.getvalue()


def _scan(client, payload: bytes, name: str) -> dict:
    res = client.post("/upload",
                      files={"file": (name, io.BytesIO(payload), "application/zip")})
    assert res.status_code == 200, res.text
    status = client.get(f"/status/{res.json()['job_id']}").json()
    assert status["status"] == "Completed"
    return status["results"]


def test_the_member_walk_records_an_unreadable_file(tmp_path):
    """Exercises the real branch without needing antivirus to cooperate.

    A directory where a file is expected makes `open()` raise IsADirectoryError —
    an OSError, the same class quarantine produces — so the walk takes the
    identical path it takes when a sample is confiscated.
    """
    from app.main import _analyze_archive_member, _new_archive_scan

    acc = _new_archive_scan()
    unreadable = tmp_path / "payload.bin"
    unreadable.mkdir()

    _analyze_archive_member(str(unreadable), "payload.bin", acc, depth=1)

    assert acc["unreadable"] == ["payload.bin"], (
        "a member that could not be read was skipped without being recorded"
    )
    entry = next(c for c in acc["contents"] if c["name"] == "payload.bin")
    assert entry.get("unreadable"), "the contents listing does not mark it unreadable"


def test_scoring_treats_unreadable_members_as_unexaminable():
    """The unit-level contract, independent of whether AV is present."""
    from attribution_module.scoring import calculate_score

    base = {
        "file_hash": "0" * 64, "submitted_url": None,
        "static": {"suspicious_sections": [], "pe_sections": [], "is_pe": False,
                   "imphash": None, "file_entropy": 0.0, "magic_type": "Unknown",
                   "type_mismatch": False, "suspicious_strings": []},
        "osint": {}, "url": {}, "iocs": {"ips": [], "domains": [], "urls": []},
        "apk": {}, "document": {},
    }

    clean = calculate_score(dict(base))
    assert clean["verdict"] == "Clear", "the control case is not Clear; test is invalid"

    quarantined = calculate_score({**base, "unreadable_members": ["Invoice.lnk"]})
    assert quarantined["verdict"] == "Inconclusive", (
        "an archive whose member was confiscated still reported Clear"
    )
    reason = quarantined.get("inconclusive_reason") or ""
    assert "could not be read" in reason
    assert "antivirus" in reason.lower()
    assert "Invoice.lnk" in reason, "the report does not name the member"


def test_a_real_detection_is_not_downgraded():
    """Inconclusive only ever replaces a would-be Clear."""
    from attribution_module import scoring

    known = "b" * 64
    original = dict(scoring.KNOWN_MALICIOUS_HASHES)
    scoring.KNOWN_MALICIOUS_HASHES[known] = {
        "score": 100, "family": "T", "attribution": "Unattributed", "reason": "t"}
    try:
        result = scoring.calculate_score({
            "file_hash": known, "submitted_url": None,
            "static": {"suspicious_sections": [], "pe_sections": [], "is_pe": False,
                       "imphash": None, "file_entropy": 0.0, "magic_type": "Unknown",
                       "type_mismatch": False, "suspicious_strings": []},
            "osint": {}, "url": {}, "iocs": {"ips": [], "domains": [], "urls": []},
            "apk": {}, "document": {}, "unreadable_members": ["x.bin"],
        })
        assert result["verdict"] == "Malicious"
    finally:
        scoring.KNOWN_MALICIOUS_HASHES.clear()
        scoring.KNOWN_MALICIOUS_HASHES.update(original)


def test_an_ordinary_archive_still_concludes(client):
    results = _scan(client, _zip({"a.txt": b"hello", "b.txt": b"world"}), "ordinary.zip")

    assert results["verdict"] == "Clear"
    assert not results.get("archive_unreadable")


@pytest.mark.parametrize("count", [1, 3, 10])
def test_the_reason_scales_without_dumping_every_name(count):
    from attribution_module.scoring import calculate_score

    members = [f"file{i}.bin" for i in range(count)]
    result = calculate_score({
        "file_hash": "0" * 64, "submitted_url": None,
        "static": {"suspicious_sections": [], "pe_sections": [], "is_pe": False,
                   "imphash": None, "file_entropy": 0.0, "magic_type": "Unknown",
                   "type_mismatch": False, "suspicious_strings": []},
        "osint": {}, "url": {}, "iocs": {"ips": [], "domains": [], "urls": []},
        "apk": {}, "document": {}, "unreadable_members": members,
    })
    reason = result["inconclusive_reason"]
    assert str(count) in reason
    assert len(reason) < 400, "the reason dumps the whole member list"
