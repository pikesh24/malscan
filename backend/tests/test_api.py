"""API integration tests — full upload→scan→report flow via TestClient.

External enrichers are stubbed in conftest.py, so the pipeline runs the real
static analysis, scoring, clustering and report generation, fully offline.
TestClient executes FastAPI background tasks synchronously, so by the time
POST /upload returns, the scan job has already finished.
"""

import importlib.util
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


# ── Duplicate-submission debounce (NOT a result cache) ────────────────────────

def test_duplicate_submission_within_window_is_debounced(client):
    """The same bytes resubmitted within the debounce window (double-click, app
    retry) reuse the just-computed result instead of burning a second scan's
    worth of external API quota. Metadata still reflects THIS request."""
    content = b"debounce me: http://debounce-test.example/x mentions 45.33.32.156"
    res1 = _upload(client, content, "first.txt").json()
    result1 = client.get(f"/status/{res1['job_id']}").json()["results"]
    assert not result1.get("debounced")   # first scan runs the full pipeline

    res2 = _upload(client, content, "second.txt").json()   # identical bytes, new name
    result2 = client.get(f"/status/{res2['job_id']}").json()["results"]

    assert result2.get("debounced") is True
    assert res2["job_id"] != res1["job_id"]
    assert result2["score"] == result1["score"]
    assert result2["verdict"] == result1["verdict"]
    # …but file metadata reflects THIS request.
    assert result2["original_filename"] == "second.txt"
    # The debounce path skips report generation, so the report endpoint must
    # regenerate it on demand for the reused job.
    assert client.get(f"/report/{res2['job_id']}").status_code == 200


def test_rescan_past_window_runs_a_fresh_scan(client, monkeypatch):
    """Past the debounce window a resubmit is a REAL rescan, not a replay.

    This is the guarantee that replaced the old 24h result cache: a wrong verdict
    (or one made stale by threat intel moving) can never be frozen — the next
    scan recomputes it from scratch."""
    monkeypatch.setattr(app_main, "RESULT_DEBOUNCE_SECONDS", 0)

    content = b"rescan me: http://rescan-test.example/y mentions 45.33.32.156"
    res1 = _upload(client, content, "a.txt").json()
    client.get(f"/status/{res1['job_id']}")

    res2 = _upload(client, content, "b.txt").json()
    result2 = client.get(f"/status/{res2['job_id']}").json()["results"]

    assert not result2.get("debounced")   # full pipeline ran again
    assert result2["verdict"] in ("Clear", "Suspicious", "Malicious", "Inconclusive")


def test_partial_result_is_never_reused(client, monkeypatch):
    """A scan whose VirusTotal lookup did not complete is tagged partial and must
    never be handed back to a later submission — even inside the debounce window.
    A degraded scan must not stand in for a finished one."""
    monkeypatch.setenv("VT_API_KEY", "test-key")   # make the vt_file lookup run
    monkeypatch.setattr(app_main, "get_file_report",
                        lambda *a, **k: {"error": "VT request timed out.", "vt_status": "error"})

    content = b"partial-intel probe with 45.33.32.156"
    res1 = _upload(client, content, "p1.bin").json()
    result1 = client.get(f"/status/{res1['job_id']}").json()["results"]
    assert result1["partial"] is True
    assert not result1.get("debounced")

    res2 = _upload(client, content, "p2.bin").json()
    result2 = client.get(f"/status/{res2['job_id']}").json()["results"]
    assert not result2.get("debounced")
    assert result2["partial"] is True


def test_partial_scan_with_no_findings_is_inconclusive_not_clear(client, monkeypatch):
    """The core safety property: when VirusTotal (the verdict-critical source)
    does not complete and nothing else was found, 'no findings' must NOT be
    reported as Clear — we cannot tell 'nothing is wrong' from 'we couldn't
    check'. Otherwise a rate-limited scan of real malware looks safe."""
    monkeypatch.setenv("VT_API_KEY", "test-key")
    monkeypatch.setattr(app_main, "get_file_report",
                        lambda *a, **k: {"error": "VT rate limit exceeded.", "vt_status": "error"})

    res = _upload(client, b"a wholly unremarkable file with no indicators", "benign.txt").json()
    results = client.get(f"/status/{res['job_id']}").json()["results"]

    assert results["partial"] is True
    assert results["verdict"] == "Inconclusive"
    assert results["verdict"] != "Clear"


def test_partial_scan_does_not_downgrade_a_real_detection(client, monkeypatch):
    """Inconclusive is deliberately narrow: it only replaces a would-be 'Clear'.
    A genuine detection must keep its verdict even when intel was incomplete —
    relabelling a true positive as 'Inconclusive' would bury it."""
    monkeypatch.setenv("VT_API_KEY", "test-key")
    monkeypatch.setattr(app_main, "get_file_report",
                        lambda *a, **k: {"error": "VT rate limit exceeded.", "vt_status": "error"})
    # EICAR is scanned by an earlier test in this session; without this the
    # upload would be debounced to that earlier (non-partial) result.
    monkeypatch.setattr(app_main, "RESULT_DEBOUNCE_SECONDS", 0)

    res = _upload(client, EICAR, "eicar.com").json()
    results = client.get(f"/status/{res['job_id']}").json()["results"]

    assert results["partial"] is True
    assert results["verdict"] in ("Malicious", "Suspicious")


def test_rescan_does_not_cluster_with_itself(client, monkeypatch):
    """Without a long-lived cache every rescan creates a new job carrying the same
    indicators. Clustering must exclude the artifact's OWN prior scans (keyed on
    file_hash) or a file appears to share infrastructure with copies of itself and
    reads as a campaign."""
    monkeypatch.setattr(app_main, "RESULT_DEBOUNCE_SECONDS", 0)

    # Indicators unique to this test — any cluster match can then ONLY be a
    # self-match. (Shared IPs like 45.33.32.156 legitimately cluster across the
    # other tests' distinct artifacts, which is the behaviour we want to keep.)
    content = b"self-cluster probe mentions 203.0.113.77 and http://selfclust-unique.example/z"
    first = _upload(client, content, "one.txt").json()
    client.get(f"/status/{first['job_id']}")

    second = _upload(client, content, "two.txt").json()
    results = client.get(f"/status/{second['job_id']}").json()["results"]

    clusters = results.get("clusters") or {}
    assert clusters.get("cluster_count", 0) == 0
    for key in ("shared_ips", "shared_domains", "shared_asns", "shared_registrars"):
        assert not (clusters.get(key) or {}), f"{key} matched the artifact's own prior scan"


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


# ── Layer 2: the pipeline actually wires the scoring changes together ──────────
# The corpus in tests/corpus/ calls calculate_score() directly, which means it
# cannot see main.py at all. These tests cover the seam: a refactor of how
# main.py builds analysis_data could silently undo a scoring fix while every
# corpus case stayed green.


def test_flag_weights_survive_the_pipeline(client):
    """Per-flag URL weights must reach the scorer through main.py.

    analyze_url() returns 'suspicious_flags' plus a parallel 'flag_weights', and
    _check_url_flags falls back to a flat +20 per flag when weights are absent.
    That fallback is deliberate (older callers) but it means a main.py change
    that dropped flag_weights would revert every URL flag to +20 — reintroducing
    the false positives phase A removed — without failing a single corpus case.

    A bank subdomain over http is the sharpest probe: one flag worth +5 now,
    two flags worth 40 (= Suspicious) under the old flat scoring.
    """
    res = client.post("/submit-url", json={"url": "http://netbanking.hdfcbank.com/"})
    results = client.get(f"/status/{res.json()['job_id']}").json()["results"]

    assert results["verdict"] == "Clear", (
        f"real bank subdomain scored {results['score']} via the pipeline: {results['reasons']}"
    )
    url_points = [e["points"] for e in results["score_breakdown"] if e["label"] == "URL Anomalies"]
    assert url_points != [40], "URL flags scored 20 each — flag_weights did not reach the scorer"


def test_pipeline_does_not_call_real_bank_subdomain_a_typosquat(client):
    """The report text is the product; a Clear verdict with a phishing warning
    attached still tells the user their bank is fake."""
    res = client.post("/submit-url", json={"url": "https://eportal.incometax.gov.in/"})
    results = client.get(f"/status/{res.json()['job_id']}").json()["results"]
    assert not any("impersonate" in r.lower() for r in results["reasons"]), results["reasons"]


def test_artifact_evidence_rule_applies_through_the_pipeline(client):
    """Infrastructure-only suspicion must not reach Malicious end-to-end."""
    res = _upload(client, b"contacts 45.33.32.156 and http://some-host.example/beacon", "notes.txt")
    results = client.get(f"/status/{res.json()['job_id']}").json()["results"]
    if results["verdict"] == "Malicious":
        identity = {"Known Malicious Hash Match", "MalwareBazaar Hash Match", "YARA Rule Matches",
                    "VirusTotal Consensus", "File Structure Analysis", "Document Threat Analysis",
                    "PE Section Entropy", "APK Permissions"}
        fired = {e["label"] for e in results["score_breakdown"] if e["points"] > 0}
        assert fired & identity, (
            f"Malicious with no artifact evidence — only {sorted(fired)}"
        )


def test_safe_domain_indicators_are_stripped_from_a_file(client):
    """Boilerplate namespace URLs every document embeds must not become IOCs.

    _strip_safe_indicators runs inside the job, so no corpus case exercises it.
    """
    body = (b"<xml xmlns='http://www.w3.org/2001/XMLSchema'>"
            b"see http://schemas.microsoft.com/office/2004/12/omml and "
            b"http://real-target.example/payload</xml>")
    res = _upload(client, body, "doc.xml")
    results = client.get(f"/status/{res.json()['job_id']}").json()["results"]

    urls = " ".join(results["indicators"]["urls"])
    assert "w3.org" not in urls and "schemas.microsoft.com" not in urls
    assert "real-target.example" in urls, "stripping removed a genuine indicator too"


def test_submitted_safe_domain_is_kept_as_an_indicator(client):
    """A deliberately submitted URL stays in the report even when allow-listed —
    the report still needs to geolocate it, graph it and screenshot it."""
    res = client.post("/submit-url", json={"url": "https://github.com/"})
    results = client.get(f"/status/{res.json()['job_id']}").json()["results"]
    assert results["verdict"] in ("Clear", "Inconclusive")
    assert any("github.com" in d for d in results["indicators"]["domains"]), \
        "submitted domain was stripped from its own report"


# ── Ordinary signed software must not look malicious ──────────────────────────
# All three of these came from one real report: Claude_Setup.exe, a legitimately
# signed installer that 62 VirusTotal engines agreed was clean, scored 73/100 and
# was presented as a "High Confidence Threat".

def test_code_signing_urls_are_not_treated_as_indicators(client):
    """Authenticode embeds the signer's CRL/OCSP/CA endpoints in EVERY signed
    binary. They record who signed the file, not what it communicates with — but
    they were extracted as network indicators, so signing a release properly
    raised its IOC volume and therefore its score. The trailing bytes are real:
    DER structure bleeds into the extracted string."""
    body = (b"http://crl3.digicert.com/DigiCertTrustedRootG4.crl0 "
            b"http://ocsp.digicert.com0 "
            b"http://cacerts.digicert.com/DigiCertTrustedRootG4.crt0C "
            b"http://real-payload.example/stage2.bin")
    job_id = _upload(client, body, "signed.bin").json()["job_id"]
    urls = " ".join(client.get(f"/status/{job_id}").json()["results"]["indicators"]["urls"])

    assert "digicert" not in urls, f"certificate-chain URLs became indicators: {urls}"
    assert "real-payload.example" in urls, "stripping cert URLs also removed a genuine indicator"


def test_failed_lookup_on_an_embedded_url_does_not_make_the_scan_partial(client, monkeypatch):
    """VirusTotal is verdict-critical for the ARTIFACT, not for every string in it.

    A binary's string table yields hosts that never resolve (adjacent symbols run
    together, certificate blobs leave trailing bytes), so the lookup on an
    embedded URL fails routinely on perfectly ordinary software. Treating that as
    an incomplete scan marked the result provisional AND vetoed the benign-
    consensus dampening — so a clean verdict on the file was discarded because a
    junk string extracted from it did not resolve.
    """
    monkeypatch.setenv("VT_API_KEY", "test-key")
    monkeypatch.setattr(app_main, "get_url_report",
                        lambda *a, **k: {"error": "VT request timed out.", "vt_status": "error"})
    monkeypatch.setattr(app_main, "get_file_report",
                        lambda *a, **k: {"stats": {"malicious": 0, "suspicious": 0,
                                                   "harmless": 8, "undetected": 60},
                                         "vt_status": "found"})

    res = _upload(client, b"ordinary program referencing http://embedded-junk.example/x", "app.bin")
    results = client.get(f"/status/{res.json()['job_id']}").json()["results"]

    assert results.get("partial") is not True, \
        "a failed lookup on an EMBEDDED url marked the artifact's own scan partial"


# ── Rescanning the same executable ────────────────────────────────────────────

def _interpreter_is_pe() -> bool:
    try:
        with open(os.sys.executable, "rb") as f:
            return f.read(2) == b"MZ"
    except OSError:
        return False


@pytest.mark.skipif(not _interpreter_is_pe(), reason="no PE binary available on this platform")
def test_the_same_executable_can_be_scanned_twice(client, monkeypatch):
    """End-to-end guarantee that a PE can be resubmitted and rescanned.

    Analysing a PE used to leave it memory-mapped by the scanning process, so a
    second submission could not rewrite the vault copy: HTTP 500 from /upload,
    raised before any job row existed. Found in the wild on Claude_Setup.exe.

    Note this test does NOT reliably reproduce that bug — under TestClient the
    background task runs inline and the mapping is released before the second
    upload, so it passed even against the broken code. The actual regression
    guard is test_analyzing_a_pe_leaves_the_file_writable, which was confirmed
    to fail without the fix. This one stands guard over the product-level
    promise instead: rescanning is deliberate design (there is no result cache),
    so the debounce is disabled to force a genuine second pass.
    """
    monkeypatch.setattr(app_main, "RESULT_DEBOUNCE_SECONDS", 0)
    with open(os.sys.executable, "rb") as f:
        pe_bytes = f.read()

    first = _upload(client, pe_bytes, "setup.exe")
    assert first.status_code == 200, first.text[:300]

    second = _upload(client, pe_bytes, "setup.exe")
    assert second.status_code == 200, f"re-scanning the same PE failed: {second.text[:300]}"
    assert client.get(f"/status/{second.json()['job_id']}").json()["status"] == "Completed"


# ── PDF export ────────────────────────────────────────────────────────────────

@pytest.mark.skipif(importlib.util.find_spec("playwright") is None,
                    reason="playwright package not installed")
def test_unreachable_rented_browser_is_not_reported_as_a_missing_install(client, monkeypatch):
    """A configured-but-unreachable browser must not be reported as "not installed".

    The deployed backend has no Chromium of its own — it rents one over CDP
    (BROWSERLESS_WS_URL). An expired token or a down service then fails at
    exactly the same call a missing local install does, and folding both into
    the 501 "run playwright install chromium" message would send whoever debugs
    it off fixing a box that is deliberately never meant to host a browser.
    """
    monkeypatch.setattr(app_main, "BROWSER_WS_ENDPOINT", "ws://127.0.0.1:1/devtools/browser/unreachable")
    monkeypatch.setattr(app_main, "BROWSER_CONNECT_TIMEOUT_MS", 3000)

    job_id = _upload(client, b"pdf export probe", "export-me.txt").json()["job_id"]
    res = client.get(f"/report/{job_id}/pdf")

    assert res.status_code == 502, f"expected a gateway error, got {res.status_code}"
    assert "remote browser" in res.json()["detail"]
