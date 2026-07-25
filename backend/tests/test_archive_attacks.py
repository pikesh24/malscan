"""
Hostile archives aimed at MALSCAN itself rather than at the user.

The scanner opens and extracts whatever it is given, so the archive path is
attack surface: a member name can try to escape the extraction directory, and a
member header can lie about how large the contents are. `generate_test_files.py`
built samples like these but no test ever ran them, so the guards in
process_scan_job had never been exercised against an actual hostile archive.

These go through the real API, because the guards live inline in the scan job —
a unit test of the helpers would not touch them.
"""

import io
import os
import struct
import zipfile

import pytest

from app import main as app_main


def _upload(client, payload: bytes, filename: str):
    return client.post(
        "/upload",
        files={"file": (filename, io.BytesIO(payload), "application/octet-stream")},
    )


def _scan(client, payload: bytes, filename: str):
    res = _upload(client, payload, filename)
    assert res.status_code == 200, res.text
    return client.get(f"/status/{res.json()['job_id']}").json()


# ── Zip Slip ──────────────────────────────────────────────────────────────────

def test_zip_slip_does_not_escape_the_extraction_directory(client, tmp_path):
    """A member named ../../… must not be written outside the temp dir."""
    canary = tmp_path / "canary.txt"
    escape = "../../" * 6 + str(canary.name)

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("harmless.txt", b"ordinary content")
        z.writestr(escape, b"PWNED")

    status = _scan(client, buf.getvalue(), "slip.zip")
    assert status["status"] == "Completed"
    assert not canary.exists(), "zip slip wrote outside the extraction directory"


def test_absolute_path_member_is_blocked(client, tmp_path):
    """An absolute member path must be rejected, not joined."""
    target = tmp_path / "abs_canary.txt"
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr(str(target).replace("\\", "/").lstrip("/"), b"PWNED")
        z.writestr("ok.txt", b"fine")

    _scan(client, buf.getvalue(), "abs.zip")
    assert not target.exists() or target.read_bytes() != b"PWNED"


def test_sibling_prefix_directory_is_not_treated_as_inside(client):
    """commonpath, not startswith: "/x/dir_evil" must not pass as "/x/dir"."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("../malscan_arc_evil/payload.txt", b"PWNED")
        z.writestr("real.txt", b"fine")
    assert _scan(client, buf.getvalue(), "sibling.zip")["status"] == "Completed"


# ── Archive bombs ─────────────────────────────────────────────────────────────

# The two guards below are budget checks, so proving them at the real limits
# means genuinely producing 200 MB and 500 files — 93 of the original 96 seconds
# for this file, in a suite that otherwise runs in nine. The limits are module
# globals read at call time, so lowering them exercises the identical branch for
# a fraction of the cost. MALSCAN_SLOW_ARCHIVE_TESTS=1 additionally runs the
# full-scale version, which is the only way to observe real memory behaviour.

def test_many_file_bomb_is_capped(client, monkeypatch):
    """More members than the cap must be truncated, not all extracted."""
    monkeypatch.setattr(app_main, "MAX_ZIP_FILE_COUNT", 10)

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        for i in range(60):
            z.writestr(f"f{i}.txt", b"x")

    status = _scan(client, buf.getvalue(), "many.zip")
    assert status["status"] == "Completed"
    listed = status["results"].get("archive_contents") or []
    assert len(listed) <= 10, f"cap ignored: {len(listed)} members extracted"


def test_decompressed_size_budget_stops_extraction(client, monkeypatch):
    """Extraction must stop once the decompressed budget is spent."""
    monkeypatch.setattr(app_main, "MAX_DECOMPRESSED_BYTES", 256 * 1024)

    payload = b"\x00" * (128 * 1024)
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED, compresslevel=9) as z:
        for i in range(20):
            z.writestr(f"bomb{i}.bin", payload)

    status = _scan(client, buf.getvalue(), "bomb.zip")
    assert status["status"] == "Completed"
    listed = status["results"].get("archive_contents") or []
    assert len(listed) < 20, "budget did not stop extraction"


@pytest.mark.skipif(
    os.environ.get("MALSCAN_SLOW_ARCHIVE_TESTS") != "1",
    reason="full-scale bomb — set MALSCAN_SLOW_ARCHIVE_TESTS=1 to run (~60s)",
)
def test_highly_compressed_member_does_not_exhaust_memory(client):
    """Real-scale bomb: ~360 MB of expansion inside a few hundred KB.

    The budget sums `file_size` from member headers, which the attacker writes,
    so this checks the scan survives a member whose true expansion dwarfs the
    archive — a property the down-scaled test above cannot show.
    """
    payload = b"\x00" * (60 * 1024 * 1024)
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED, compresslevel=9) as z:
        for i in range(6):
            z.writestr(f"bomb{i}.bin", payload)

    assert len(buf.getvalue()) < app_main.MAX_UPLOAD_BYTES
    status = _scan(client, buf.getvalue(), "bomb.zip")
    assert status["status"] == "Completed", "scanner did not survive a compression bomb"


def test_lying_size_header_is_not_trusted(client):
    """A member declaring 1 byte while containing far more.

    The decompressed-size budget sums declared sizes, so a lying header would
    slip past it. Written by hand because zipfile will not produce a mismatched
    header.
    """
    real = b"A" * (8 * 1024 * 1024)
    import zlib

    comp = zlib.compressobj(9, zlib.DEFLATED, -15)
    blob = comp.compress(real) + comp.flush()
    name = b"liar.bin"
    crc = zlib.crc32(real) & 0xFFFFFFFF

    # local header, declaring uncompressed size = 1
    local = (struct.pack("<IHHHHHIIIHH", 0x04034B50, 20, 0, 8, 0, 0, crc, len(blob), 1, len(name), 0)
             + name + blob)
    central = (struct.pack("<IHHHHHHIIIHHHHHII", 0x02014B50, 20, 20, 0, 8, 0, 0, crc,
                           len(blob), 1, len(name), 0, 0, 0, 0, 0, 0) + name)
    end = struct.pack("<IHHHHIIH", 0x06054B50, 0, 0, 1, 1, len(central), len(local), 0)

    status = _scan(client, local + central + end, "liar.zip")
    assert status["status"] == "Completed", "a lying size header crashed the scan"


def test_nested_archives_terminate(client):
    """Archive inside archive inside archive must not recurse without end."""
    inner = io.BytesIO()
    with zipfile.ZipFile(inner, "w") as z:
        z.writestr("payload.txt", b"contacts http://nested-inner.example/c2")
    blob = inner.getvalue()

    for depth in range(6):
        outer = io.BytesIO()
        with zipfile.ZipFile(outer, "w") as z:
            z.writestr(f"level{depth}.zip", blob)
        blob = outer.getvalue()

    status = _scan(client, blob, "nested.zip")
    assert status["status"] == "Completed", "nested archives did not terminate"


# ── The archive path still works ──────────────────────────────────────────────

def test_ordinary_archive_still_has_its_contents_scanned(client):
    """The other half: hardening must not stop real extraction."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("readme.txt", b"nothing here")
        z.writestr("inner/payload.txt", b"beacons to http://arc-inner.example/c2 and 45.33.32.156")

    results = _scan(client, buf.getvalue(), "ordinary.zip")["results"]
    assert "45.33.32.156" in results["indicators"]["ips"], \
        "IOCs from inside the archive were not extracted"
    names = " ".join(e.get("name", "") for e in (results.get("archive_contents") or []))
    assert "payload.txt" in names
