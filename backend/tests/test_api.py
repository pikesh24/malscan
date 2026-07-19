"""API integration tests — full upload→scan→report flow via TestClient.

External enrichers are stubbed in conftest.py, so the pipeline runs the real
static analysis, scoring, clustering and report generation, fully offline.
TestClient executes FastAPI background tasks synchronously, so by the time
POST /upload returns, the scan job has already finished.
"""

import io
import os
import struct
import zlib

import pytest

from app import main as app_main

# EICAR antivirus test string, assembled at runtime so this source file is not
# itself flagged by AV scanners. The string is harmless by design, but every
# AV product (correctly) detects it — set MALSCAN_NO_EICAR=1 to skip that test
# if your AV quarantines it mid-run.
EICAR = (b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$" + b"EICAR-STANDARD-ANTIVIRUS" + b"-TEST-FILE!$H+H*")


def _upload(client, content: bytes, filename: str):
    return client.post("/upload", files={"file": (filename, io.BytesIO(content), "application/octet-stream")})


# ── Upload flow ───────────────────────────────────────────────────────────────

def test_upload_and_complete_flow(client):
    res = _upload(client, b"hello, this file mentions http://some-site.example/thing and 9.9.9.9", "note.txt")
    assert res.status_code == 200
    job_id = res.json()["job_id"]

    status = client.get(f"/status/{job_id}").json()
    assert status["status"] == "Completed"
    results = status["results"]
    assert results["verdict"] in ("Clear", "Suspicious", "Malicious")
    assert "9.9.9.9" in results["indicators"]["ips"]
    assert isinstance(results["score"], int)


@pytest.mark.skipif(os.environ.get("MALSCAN_NO_EICAR") == "1", reason="AV interferes with EICAR on this machine")
def test_eicar_upload_is_malicious(client):
    res = _upload(client, EICAR, "eicar.com.txt")
    job_id = res.json()["job_id"]
    results = client.get(f"/status/{job_id}").json()["results"]
    assert results["score"] == 100
    assert results["verdict"] == "Malicious"
    assert results["family"] == "EICAR-Test-File"


def test_oversized_upload_rejected(client):
    big = b"0" * (app_main.MAX_UPLOAD_BYTES + 1)
    res = _upload(client, big, "big.bin")
    assert res.status_code == 413


def test_hostile_filename_is_handled(client):
    res = _upload(client, b"plain content", "../../evil<script>alert(1)</script>.txt")
    assert res.status_code == 200
    job_id = res.json()["job_id"]
    assert client.get(f"/status/{job_id}").json()["status"] == "Completed"


# ── URL submission ────────────────────────────────────────────────────────────

def test_submit_url_flow(client):
    res = client.post("/submit-url", json={"url": "http://test-target.example/update.exe"})
    assert res.status_code == 200
    job_id = res.json()["job_id"]
    results = client.get(f"/status/{job_id}").json()["results"]
    # plain HTTP (+20) and direct .exe download (+20) → at least Suspicious
    assert results["score"] >= 35
    assert results["verdict"] in ("Suspicious", "Malicious")


def test_submit_bare_domain_accepted(client):
    res = client.post("/submit-url", json={"url": "example.com"})
    assert res.status_code == 200


def test_submit_url_rejects_bad_schemes(client):
    for bad in ("javascript:alert(1)", "file:///etc/passwd", "not a url at all!", ""):
        res = client.post("/submit-url", json={"url": bad})
        assert res.status_code == 400, f"expected 400 for {bad!r}"


def test_submit_url_rejects_overlong(client):
    res = client.post("/submit-url", json={"url": "http://x.example/" + "a" * app_main.MAX_URL_LENGTH})
    assert res.status_code == 400


# ── Status & reports ──────────────────────────────────────────────────────────

def test_unknown_job_404(client):
    assert client.get("/status/no-such-job").status_code == 404
    assert client.get("/report/no-such-job").status_code == 404


def test_report_endpoints_and_csp(client):
    job_id = _upload(client, b"report me http://r.example/x", "r.txt").json()["job_id"]

    html_res = client.get(f"/report/{job_id}")
    assert html_res.status_code == 200
    assert "Content-Security-Policy" in html_res.headers
    assert html_res.headers["X-Content-Type-Options"] == "nosniff"
    assert "MalScan" in html_res.text

    json_res = client.get(f"/report/{job_id}/json")
    assert json_res.status_code == 200
    assert "score" in json_res.json()


# ── Rate limiting ─────────────────────────────────────────────────────────────

def test_rate_limit_triggers_429(client, monkeypatch):
    monkeypatch.setattr(app_main, "RATE_LIMIT_MAX", 3)
    for _ in range(3):
        assert client.post("/submit-url", json={"url": "http://rl.example/"}).status_code == 200
    res = client.post("/submit-url", json={"url": "http://rl.example/"})
    assert res.status_code == 429


# ── Result cache: same file → same verdict ────────────────────────────────────

def test_same_file_reuses_cached_result(client):
    """Identical bytes re-uploaded within the TTL return the earlier verdict
    verbatim (the 'same file → same result' guarantee), refreshing only metadata."""
    content = b"cache me: http://cache-test.example/x mentions 45.33.32.156"
    res1 = _upload(client, content, "first.txt").json()
    result1 = client.get(f"/status/{res1['job_id']}").json()["results"]
    assert not result1.get("cache_reuse")   # first scan runs the full pipeline

    res2 = _upload(client, content, "second.txt").json()   # identical bytes, new name
    result2 = client.get(f"/status/{res2['job_id']}").json()["results"]

    assert result2.get("cache_reuse") is True
    assert res2["job_id"] != res1["job_id"]
    # Analytical result is identical…
    assert result2["score"] == result1["score"]
    assert result2["verdict"] == result1["verdict"]
    assert result2["indicators"] == result1["indicators"]
    # …but file metadata reflects THIS request.
    assert result2["original_filename"] == "second.txt"
    # The cache path skips report generation, so the report endpoint must
    # regenerate it on demand for the reused job.
    assert client.get(f"/report/{res2['job_id']}").status_code == 200


def test_partial_result_is_not_cached(client, monkeypatch):
    """A scan whose VirusTotal lookup did not complete is tagged partial and must
    NOT be reused from cache — a timeout must never freeze as a clean verdict."""
    monkeypatch.setenv("VT_API_KEY", "test-key")   # make the vt_file lookup run
    monkeypatch.setattr(app_main, "get_file_report",
                        lambda *a, **k: {"error": "VT request timed out.", "vt_status": "error"})

    content = b"partial-intel probe with 45.33.32.156"
    res1 = _upload(client, content, "p1.bin").json()
    result1 = client.get(f"/status/{res1['job_id']}").json()["results"]
    assert result1["partial"] is True
    assert not result1.get("cache_reuse")

    res2 = _upload(client, content, "p2.bin").json()
    result2 = client.get(f"/status/{res2['job_id']}").json()["results"]
    # Not served from cache — re-scanned (still partial), never frozen.
    assert not result2.get("cache_reuse")
    assert result2["partial"] is True


# ── RAR archive extraction ────────────────────────────────────────────────────

def _build_rar(filename: str, data: bytes) -> bytes:
    """Assemble a genuine RAR4 'stored' archive (correct CRCs) so the extraction
    path is exercised for real — no external `rar` tool needed to create it."""
    def block(head_type, flags, tail, add=b""):
        # HEAD_SIZE counts the whole header INCLUDING the 2-byte HEAD_CRC.
        head_size = 2 + 1 + 2 + 2 + len(tail)
        body = struct.pack("<B", head_type) + struct.pack("<H", flags) + struct.pack("<H", head_size) + tail
        return struct.pack("<H", zlib.crc32(body) & 0xFFFF) + body + add

    marker = b"Rar!\x1a\x07\x00"
    main = block(0x73, 0x0000, struct.pack("<H", 0) + struct.pack("<I", 0))
    name = filename.encode("ascii")
    tail = (
        struct.pack("<I", len(data)) + struct.pack("<I", len(data))  # PACK / UNP size
        + struct.pack("<B", 0)                                        # HOST_OS
        + struct.pack("<I", zlib.crc32(data) & 0xFFFFFFFF)           # FILE_CRC
        + struct.pack("<I", 0) + struct.pack("<B", 20)               # FTIME, UNP_VER
        + struct.pack("<B", 0x30)                                     # METHOD = stored
        + struct.pack("<H", len(name)) + struct.pack("<I", 0x20) + name
    )
    fhead = block(0x74, 0x8000, tail, add=data)                       # 0x8000 = data follows
    end = block(0x7B, 0x0000, b"")
    return marker + main + fhead + end


@pytest.mark.skipif(not app_main.RAR_ENABLED, reason="no RAR extraction backend (unrar/bsdtar/7z) installed")
def test_rar_inner_files_are_extracted_and_scanned(client):
    inner = b"rar inner payload beacons http://rar-inner.example/c2 and 45.33.32.156"
    rar = _build_rar("payload.txt", inner)
    res = client.post("/upload", files={"file": ("bundle.rar", io.BytesIO(rar), "application/x-rar-compressed")})
    assert res.status_code == 200
    results = client.get(f"/status/{res.json()['job_id']}").json()["results"]
    # IOCs from INSIDE the RAR surfaced in the report.
    assert "45.33.32.156" in results["indicators"]["ips"]
    assert any("rar-inner.example" in u for u in results["indicators"]["urls"])
