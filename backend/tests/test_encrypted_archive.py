"""
Password-protected archives must say so, not read as clean.

A password-protected archive extracts nothing, so every inner detector the
"scan the files inside archives" work added is bypassed at once: no member hash
for MalwareBazaar or VirusTotal, no YARA, no PE parsing, no document analysis.
The scan then finds nothing and reports Clear — on a file no one looked inside.
Encrypting the payload and sending the password separately is a standard way of
getting a sample past scanners that work this way, so "could not examine" and
"nothing concerning" must never render the same.

No score is attached deliberately: people password-protect archives for
ordinary reasons too. The requirement is that the report SAYS it could not look.
"""

import zipfile

import pytest

from app.main import (
    _is_encrypted_member_error,
    _new_archive_scan,
    _scan_archive_tree,
)

# A PE header and a URL, so the control archive has something for the inner
# detectors to find. Deliberately not EICAR — a real test-virus string on disk
# trips local antivirus and makes the suite fail for unrelated reasons.
PAYLOAD = b"MZ\x90\x00" + b"\x00" * 64 + b"http://payload.example/c2\x00" + b"A" * 128


def _write_zip(path, encrypted, names=("invoice.exe",)):
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as zf:
        for name in names:
            zf.writestr(name, PAYLOAD)
    if not encrypted:
        return path
    # ZipInfo.flag_bits cannot be used: writestr recomputes the field while
    # writing and silently discards it. Patching both header copies is what
    # actually produces a member zipfile treats as password-protected — it
    # checks this bit before attempting decryption, which is the same branch a
    # genuinely encrypted archive takes.
    data = bytearray(path.read_bytes())
    for sig, flag_off in ((b"PK\x03\x04", 6), (b"PK\x01\x02", 8)):
        pos = 0
        while (pos := data.find(sig, pos)) != -1:
            data[pos + flag_off] |= 0x1
            pos += 4
    path.write_bytes(bytes(data))
    return path


@pytest.fixture
def blocklisted(monkeypatch):
    """Registers a benign payload in the known-hash blocklist for one test.

    Mirrors the fixture in test_archive_detection.py. EICAR would be the natural
    choice and deliberately is not: real-time antivirus quarantines it between
    extraction and analysis, failing the test for unrelated reasons.
    """
    import hashlib

    from attribution_module import scoring

    def _register(payload: bytes):
        sha = hashlib.sha256(payload).hexdigest()
        monkeypatch.setitem(scoring.KNOWN_MALICIOUS_HASHES, sha, {
            "score": 100,
            "family": "Test-Blocklist-Sample",
            "attribution": "Unattributed",
            "reason": "Known malicious test sample detected by SHA-256 hash.",
        })
        return payload, sha

    return _register


@pytest.fixture
def encrypted_zip(tmp_path):
    return _write_zip(tmp_path / "protected.zip", encrypted=True)


@pytest.fixture
def plain_zip(tmp_path):
    return _write_zip(tmp_path / "plain.zip", encrypted=False)


def test_the_fixture_really_is_password_protected(encrypted_zip):
    """Guards the test itself: a first version of this set the flag via ZipInfo,
    which writestr discarded, so it asserted against an unencrypted file."""
    with zipfile.ZipFile(encrypted_zip) as zf:
        with pytest.raises(RuntimeError, match="password"):
            zf.read("invoice.exe")


def test_encrypted_members_are_recorded(encrypted_zip):
    acc = _new_archive_scan()
    _scan_archive_tree(str(encrypted_zip), acc)

    assert acc["encrypted"] == ["invoice.exe"]
    assert acc["files_seen"] == 0, "nothing can be extracted from an encrypted archive"
    assert acc["hash_candidates"] == [], "no inner hash can reach MalwareBazaar/VirusTotal"


def test_a_normal_archive_is_not_flagged_as_encrypted(plain_zip):
    acc = _new_archive_scan()
    _scan_archive_tree(str(plain_zip), acc)

    assert acc["encrypted"] == []
    assert acc["files_seen"] == 1
    assert len(acc["hash_candidates"]) == 1


def test_partially_encrypted_archive_still_scans_what_it_can(tmp_path):
    """Only some members encrypted: the readable ones must still be analysed,
    and the unreadable ones still reported."""
    path = _write_zip(tmp_path / "mixed.zip", encrypted=False,
                      names=("readable.bin", "locked.exe"))
    data = bytearray(path.read_bytes())
    # Flag only the second local header and its central-directory entry.
    for sig, flag_off in ((b"PK\x03\x04", 6), (b"PK\x01\x02", 8)):
        hits, pos = [], 0
        while (pos := data.find(sig, pos)) != -1:
            hits.append(pos)
            pos += 4
        if len(hits) > 1:
            data[hits[1] + flag_off] |= 0x1
    path.write_bytes(bytes(data))

    acc = _new_archive_scan()
    _scan_archive_tree(str(path), acc)

    assert acc["encrypted"] == ["locked.exe"]
    assert acc["files_seen"] == 1, "the readable member must still be extracted"


# ── Error classification ─────────────────────────────────────────────────────

def test_encryption_errors_are_told_apart_from_ordinary_failures():
    assert _is_encrypted_member_error(
        RuntimeError("File 'x' is encrypted, password required for extraction"))
    assert _is_encrypted_member_error(type("PasswordRequired", (Exception,), {})())
    assert _is_encrypted_member_error(type("RarWrongPassword", (Exception,), {})())
    # A genuinely different failure must not be mislabelled as encryption.
    assert not _is_encrypted_member_error(RuntimeError("Bad CRC-32"))
    assert not _is_encrypted_member_error(NotImplementedError("compression type 99"))


# ── The reporting path, end to end ───────────────────────────────────────────

def _scan(client, payload: bytes, filename: str) -> dict:
    import io

    res = client.post("/upload",
                      files={"file": (filename, io.BytesIO(payload), "application/octet-stream")})
    assert res.status_code == 200, res.text
    status = client.get(f"/status/{res.json()['job_id']}").json()
    assert status["status"] == "Completed"
    return status["results"]


def test_report_states_that_the_archive_could_not_be_examined(client, encrypted_zip):
    """The point of the whole change: the caveat has to reach the report.

    Regression guard too — archive_truncated/archive_unreadable were copied into
    the report only inside `if archive_contents:`, and an archive nothing
    extracted from has no contents. The caveat was therefore dropped in the one
    case that needed it most, which a password-protected archive always is.
    """
    results = _scan(client, encrypted_zip.read_bytes(), "protected.zip")

    assert results.get("archive_encrypted") == ["invoice.exe"], (
        "the report does not say the archive was password-protected"
    )


def test_encrypted_archive_is_never_reported_clear(client, encrypted_zip):
    """"Nothing found" here means "nothing was looked at". Reporting that as
    Clear is how a password-protected sample gets a clean bill of health — the
    same reasoning that downgrades a scan whose intel did not return."""
    results = _scan(client, encrypted_zip.read_bytes(), "protected.zip")

    assert results["verdict"] == "Inconclusive", (
        f"password-protected archive reported as {results['verdict']}"
    )
    assert "password-protected" in (results.get("inconclusive_reason") or ""), (
        "the verdict does not explain why it could not conclude"
    )


def test_the_stated_reason_matches_the_actual_cause(client, encrypted_zip):
    """The presentation layer hard-coded the VirusTotal explanation for every
    Inconclusive verdict, so an unexaminable archive would have claimed a
    VirusTotal outage that never happened."""
    results = _scan(client, encrypted_zip.read_bytes(), "protected.zip")

    assert "VirusTotal" not in (results.get("inconclusive_reason") or "")


def test_an_ordinary_archive_carries_no_caveat(client, plain_zip):
    results = _scan(client, plain_zip.read_bytes(), "plain.zip")

    assert not results.get("archive_encrypted")
    assert results["verdict"] != "Inconclusive", "a readable archive must still conclude"
    assert results.get("archive_contents"), "a readable archive should still list its members"


def test_a_real_detection_is_not_buried_as_inconclusive(client, tmp_path, blocklisted):
    """Inconclusive only ever replaces a would-be Clear. An archive holding a
    known-bad member alongside an encrypted one must stay Malicious — masking a
    true positive behind "could not check" is the worse failure."""
    known, _ = blocklisted(b"known-bad-sample-for-encrypted-archive-test")
    path = tmp_path / "mixed_known.zip"
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("sample.bin", known)
        zf.writestr("locked.exe", PAYLOAD)
    data = bytearray(path.read_bytes())
    for sig, flag_off in ((b"PK\x03\x04", 6), (b"PK\x01\x02", 8)):
        hits, pos = [], 0
        while (pos := data.find(sig, pos)) != -1:
            hits.append(pos)
            pos += 4
        if len(hits) > 1:
            data[hits[1] + flag_off] |= 0x1
    path.write_bytes(bytes(data))

    results = _scan(client, path.read_bytes(), "mixed_known.zip")

    assert results["verdict"] == "Malicious", (
        f"a known-bad member was downgraded to {results['verdict']}"
    )
    assert results.get("archive_encrypted") == ["locked.exe"], (
        "the encrypted member should still be reported alongside the detection"
    )
