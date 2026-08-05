"""
Containers we can name but cannot open must not report Clear.

`_open_extractable_archive` handles ZIP and RAR. Everything else in the magic
table — 7-Zip, CAB, InstallShield CAB, GZIP, BZIP2, XZ — was identified by name
and never opened, so the report announced "7-Zip Archive" while no byte inside
had been read, and the verdict came back Clear. Same false-clean the
password-protected case produced, minus even a caveat.

ISO and TAR could not be identified at all: their signatures sit at offsets
0x8001 and 257, and the magic scan only ever read the first 16 bytes. An ISO is
the standard way to deliver a payload without mark-of-the-web, so "Unknown" was
a poor answer.

The wording is checked as carefully as the verdict. Telling someone their 7-Zip
archive is password-protected would be confidently, specifically wrong — the
failure mode that made the hard-coded VirusTotal sentence a bug.
"""

import io
import zipfile

import pytest

from analysis_engine.static_analyzer import detect_file_type
from app.main import _unextractable_container

# Minimal headers. Content beyond the signature is irrelevant: nothing can parse
# these formats here, which is the entire point.
SEVENZIP = b"\x37\x7A\xBC\xAF\x27\x1C" + b"\x00" * 256
CAB = b"MSCF" + b"\x00" * 256
GZIP = b"\x1F\x8B\x08" + b"\x00" * 256
BZIP2 = b"BZh9" + b"\x00" * 256
XZ = b"\xFD7zXZ\x00" + b"\x00" * 256
ISO = b"\x00" * 32769 + b"CD001" + b"\x00" * 256
TAR = b"\x00" * 257 + b"ustar\x0000" + b"\x00" * 256


def _scan(client, payload: bytes, filename: str) -> dict:
    res = client.post("/upload",
                      files={"file": (filename, io.BytesIO(payload), "application/octet-stream")})
    assert res.status_code == 200, res.text
    status = client.get(f"/status/{res.json()['job_id']}").json()
    assert status["status"] == "Completed"
    return status["results"]


# ── Identification ───────────────────────────────────────────────────────────

# ids= is not cosmetic here: without it pytest builds the test id from the
# payload bytes, and a 32 KB ISO header becomes a 32 KB id that overflows the
# Windows environment-variable limit before a single assertion runs.
@pytest.mark.parametrize("payload,expected", [
    (SEVENZIP, "7-Zip Archive"),
    (CAB, "Microsoft Cabinet (CAB) File"),
    (GZIP, "GZIP Compressed"),
    (BZIP2, "BZIP2 Compressed"),
    (XZ, "XZ Compressed"),
], ids=["7zip", "cab", "gzip", "bzip2", "xz"])
def test_prefix_signature_formats_are_identified(tmp_path, payload, expected):
    path = tmp_path / "sample.bin"
    path.write_bytes(payload)
    assert detect_file_type(str(path))["magic_type"] == expected


@pytest.mark.parametrize("payload,expected", [
    (ISO, "ISO 9660 Disc Image"),
    (TAR, "TAR Archive"),
], ids=["iso9660", "tar"])
def test_offset_signature_formats_are_identified(tmp_path, payload, expected):
    """Signatures past the first 16 bytes were previously invisible."""
    path = tmp_path / "sample.bin"
    path.write_bytes(payload)
    assert detect_file_type(str(path))["magic_type"] == expected


def test_offset_scan_does_not_override_a_match_at_offset_zero(tmp_path):
    """A ZIP that happens to contain the bytes 'CD001' is still a ZIP."""
    path = tmp_path / "sample.zip"
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("f.bin", b"\x00" * 32769 + b"CD001")
    path.write_bytes(buf.getvalue())
    assert "ZIP" in detect_file_type(str(path))["magic_type"]


# ── Classification ───────────────────────────────────────────────────────────

def test_extractable_formats_are_not_flagged_unsupported():
    for supported in ("ZIP Archive / Office Open XML / APK / JAR",
                      "Windows Executable (PE/EXE/DLL)",
                      "PDF Document",
                      "Unknown"):
        assert _unextractable_container(supported) is None


def test_unopenable_formats_are_named():
    assert _unextractable_container("7-Zip Archive") == "7-Zip"
    assert _unextractable_container("ISO 9660 Disc Image") == "ISO disc image"


def test_rar_depends_on_whether_a_backend_exists(monkeypatch):
    """RAR is supported — but only with unrar/bsdtar/7z present. Without one the
    scan examined nothing, and no report ever said so."""
    from app import main

    monkeypatch.setattr(main, "RAR_ENABLED", True)
    assert main._unextractable_container("RAR Archive") is None

    monkeypatch.setattr(main, "RAR_ENABLED", False)
    assert "RAR" in (main._unextractable_container("RAR Archive") or "")


# ── End to end ───────────────────────────────────────────────────────────────

def test_a_7zip_archive_is_not_reported_clear(client):
    results = _scan(client, SEVENZIP, "payload.7z")

    assert results["verdict"] == "Inconclusive", (
        f"an unopenable 7-Zip archive was reported {results['verdict']}"
    )
    assert results.get("archive_unsupported") == "7-Zip"


def test_an_iso_is_not_reported_clear(client):
    results = _scan(client, ISO, "invoice.iso")
    assert results["verdict"] == "Inconclusive"
    assert results.get("archive_unsupported") == "ISO disc image"


def test_the_reason_names_the_format_and_does_not_claim_encryption(client):
    """The specific failure this guards: reusing the password-protected wording
    would tell the user their 7-Zip archive has a password it does not have."""
    results = _scan(client, SEVENZIP, "payload.7z")
    reason = results.get("inconclusive_reason") or ""

    assert "7-Zip" in reason
    assert "password" not in reason.lower()
    assert "VirusTotal" not in reason


def test_an_ordinary_zip_still_concludes(client):
    """The overcorrection guard: a format we CAN open must not be swept up."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("notes.txt", b"ordinary content")
    results = _scan(client, buf.getvalue(), "ordinary.zip")

    assert results.get("archive_unsupported") is None
    assert results["verdict"] != "Inconclusive"


def test_a_plain_document_still_concludes(client):
    results = _scan(client, b"just some text, not a container at all", "notes.txt")

    assert results.get("archive_unsupported") is None
    assert results["verdict"] != "Inconclusive"
