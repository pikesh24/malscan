"""
Browser extension manifests.

An extension holding `<all_urls>` plus `cookies` can read every live session
token the user has — which bypasses multi-factor authentication entirely,
because a stolen live session never sees a login prompt. That combination is
the browser equivalent of the Android overlay-plus-accessibility pair.

A .crx is a ZIP, so the archive walk already extracted and hashed its members
and found nothing: the manifest is small JSON and the payload is ordinary
JavaScript. The permission model — the part that says what it can actually do —
was never read, exactly as the APK manifest was not read before that path was
fixed.

The false-positive tests carry the weight here. Real extensions ask for broad
permissions all the time: ad blockers legitimately need to see every request,
and password managers legitimately need every site.
"""

import io
import json
import zipfile


from analysis_engine.extension_analyzer import analyze_extension


def _crx(manifest: dict, *, crx_header=False, extra=None) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("manifest.json", json.dumps(manifest))
        z.writestr("background.js", "console.log('hi');")
        for name, body in (extra or {}).items():
            z.writestr(name, body)
    payload = buf.getvalue()
    if crx_header:
        payload = b"Cr24" + b"\x03\x00\x00\x00" + b"\x00" * 16 + payload
    return payload


def _write(tmp_path, payload: bytes, name="ext.crx"):
    path = tmp_path / name
    path.write_bytes(payload)
    return str(path)


STEALER = {
    "manifest_version": 3,
    "name": "Handy Coupon Finder",
    "version": "2.1",
    "permissions": ["cookies", "tabs", "webRequest", "scripting", "history"],
    "host_permissions": ["<all_urls>"],
}

ORDINARY = {
    "manifest_version": 3,
    "name": "Dark Mode for One Site",
    "version": "1.0",
    "permissions": ["storage"],
    "host_permissions": ["https://example.com/*"],
}


# ── Recognition ──────────────────────────────────────────────────────────────

def test_a_crx_is_recognised(tmp_path):
    info = analyze_extension(_write(tmp_path, _crx(STEALER)))
    assert info["is_extension"] is True
    assert info["name"] == "Handy Coupon Finder"
    assert info["manifest_version"] == 3


def test_a_crx3_header_does_not_prevent_reading_the_manifest(tmp_path):
    """CRX3 puts a signed header in front of the ZIP."""
    info = analyze_extension(_write(tmp_path, _crx(STEALER, crx_header=True)))
    assert info["is_extension"] is True


def test_an_ordinary_zip_is_not_an_extension(tmp_path):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("notes.txt", "hello")
    info = analyze_extension(_write(tmp_path, buf.getvalue(), "docs.zip"))
    assert info["is_extension"] is False


def test_a_json_file_that_is_not_a_manifest_is_not_an_extension(tmp_path):
    """manifest.json exists but has no manifest_version — e.g. a web app manifest."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("manifest.json", json.dumps({"name": "My PWA", "start_url": "/"}))
    assert analyze_extension(_write(tmp_path, buf.getvalue()))["is_extension"] is False


def test_a_non_zip_is_handled(tmp_path):
    assert analyze_extension(_write(tmp_path, b"MZ\x00\x00", "x.exe"))["is_extension"] is False


# ── Permissions ──────────────────────────────────────────────────────────────

def test_session_stealing_combination_is_reported(tmp_path):
    info = analyze_extension(_write(tmp_path, _crx(STEALER)))

    assert info["all_sites_access"] is True
    assert "cookies" in info["notable_permissions"]
    assert "perm_cookies" in info["codes"]
    assert "all_sites" in info["codes"]


def test_the_description_explains_the_consequence(tmp_path):
    """A permission list is only useful if the reader knows what it means."""
    info = analyze_extension(_write(tmp_path, _crx(STEALER)))
    cookie_finding = next(f for f in info["findings"] if "cookies" in f)
    assert "session" in cookie_finding.lower()


def test_manifest_v2_host_patterns_in_permissions_are_found(tmp_path):
    """MV2 mixes host patterns into the permissions array."""
    info = analyze_extension(_write(tmp_path, _crx({
        "manifest_version": 2,
        "name": "Legacy",
        "version": "1.0",
        "permissions": ["<all_urls>", "cookies"],
    })))
    assert info["all_sites_access"] is True


def test_content_script_matches_count_as_host_access(tmp_path):
    info = analyze_extension(_write(tmp_path, _crx({
        "manifest_version": 3,
        "name": "Injector",
        "version": "1.0",
        "content_scripts": [{"matches": ["<all_urls>"], "js": ["c.js"]}],
    })))
    assert info["all_sites_access"] is True


def test_native_messaging_is_reported(tmp_path):
    info = analyze_extension(_write(tmp_path, _crx({
        "manifest_version": 3, "name": "Bridge", "version": "1.0",
        "permissions": ["nativeMessaging"],
    })))
    assert "perm_nativeMessaging" in info["codes"]


def test_remote_code_loading_is_reported(tmp_path):
    """If the manifest points at a remote script, what runs is not what was
    reviewed — the extension can change after installation."""
    info = analyze_extension(_write(tmp_path, _crx({
        "manifest_version": 2, "name": "Loader", "version": "1.0",
        "permissions": ["storage"],
        "content_security_policy": "script-src 'self' https://cdn.example.com; object-src 'self'",
    })))
    assert info["remote_code"] is True
    assert "remote_code" in info["codes"]


def test_unsafe_csp_is_reported(tmp_path):
    info = analyze_extension(_write(tmp_path, _crx({
        "manifest_version": 2, "name": "Evaler", "version": "1.0",
        "content_security_policy": "script-src 'self' 'unsafe-eval'; object-src 'self'",
    })))
    assert "unsafe_csp" in info["codes"]


# ── False positives ──────────────────────────────────────────────────────────

def test_a_narrow_extension_reports_nothing(tmp_path):
    info = analyze_extension(_write(tmp_path, _crx(ORDINARY)))

    assert info["is_extension"] is True
    assert info["findings"] == [], f"an ordinary extension was flagged: {info['findings']}"


def test_storage_only_extensions_are_not_notable(tmp_path):
    info = analyze_extension(_write(tmp_path, _crx({
        "manifest_version": 3, "name": "Notes", "version": "1.0",
        "permissions": ["storage", "alarms", "contextMenus"],
    })))
    assert info["codes"] == []


# ── End to end: the finding has to reach a verdict ───────────────────────────

def _scan(client, payload: bytes, filename: str) -> dict:
    res = client.post("/upload",
                      files={"file": (filename, io.BytesIO(payload), "application/octet-stream")})
    assert res.status_code == 200, res.text
    status = client.get(f"/status/{res.json()['job_id']}").json()
    assert status["status"] == "Completed"
    return status["results"]


def _ext_points(results: dict) -> int:
    for entry in results.get("score_breakdown") or []:
        if entry["label"] == "Extension Permissions":
            return entry["points"]
    return 0


def test_a_session_stealing_extension_scores(client):
    results = _scan(client, _crx(STEALER), "coupon-finder.crx")

    assert _ext_points(results) > 0, "a cookies-on-every-site extension scored nothing"
    reasons = " ".join(results.get("reasons") or [])
    assert "session" in reasons.lower()


def test_a_narrow_extension_does_not_score(client):
    results = _scan(client, _crx(ORDINARY), "darkmode.crx")
    assert _ext_points(results) == 0


def test_an_extension_inside_a_zip_is_analysed(client):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("bundled.crx", _crx(STEALER))
    results = _scan(client, buf.getvalue(), "delivery.zip")

    assert _ext_points(results) > 0, "an extension inside a ZIP lost its manifest analysis"


def test_an_office_document_is_not_treated_as_an_extension(client):
    """OOXML files are ZIPs too — the check must not misfire on them."""
    docx = io.BytesIO()
    with zipfile.ZipFile(docx, "w") as z:
        z.writestr("[Content_Types].xml", b"<?xml version='1.0'?><Types/>")
        z.writestr("word/document.xml", b"<?xml version='1.0'?><document/>")
    results = _scan(client, docx.getvalue(), "report.docx")

    assert _ext_points(results) == 0


# ── Robustness ───────────────────────────────────────────────────────────────

def test_a_corrupt_manifest_does_not_raise(tmp_path):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("manifest.json", "{not valid json at all")
    assert analyze_extension(_write(tmp_path, buf.getvalue()))["is_extension"] is False


def test_a_manifest_claiming_a_huge_size_is_refused(tmp_path):
    """The declared size is attacker-controlled; refuse before reading."""
    from analysis_engine import extension_analyzer

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("manifest.json", json.dumps({"manifest_version": 3, "pad": "A" * 200_000}))
    path = _write(tmp_path, buf.getvalue())

    original = extension_analyzer.MAX_MANIFEST_BYTES
    try:
        extension_analyzer.MAX_MANIFEST_BYTES = 1000
        assert analyze_extension(path)["is_extension"] is False
    finally:
        extension_analyzer.MAX_MANIFEST_BYTES = original
