"""
APK analysis must follow the content, not the filename.

Permission scoring is the strongest Android signal in the product — the
overlay-plus-accessibility conjunction is the defining pattern of modern banking
trojans, which are the fastest-growing mobile threat category. Two ways to lose
all of it were:

  * renaming `evil.apk` to `evil.zip`, because the top-level analyser was gated
    on the submitted filename ending `.apk`; and
  * wrapping the APK in a ZIP, because the per-member walk never ran the APK
    analyser at all — the members were extracted and hashed, and every
    Android-specific signal was discarded.

Both are trivial for an attacker and neither costs them anything.
"""

import io
import zipfile

import pytest

ANDROID_NS = "http://schemas.android.com/apk/res/android"

# The exact pair scoring calls "the exact pattern used by banking trojans".
BANKER_MANIFEST = f"""<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="{ANDROID_NS}" package="com.fake.bank">
  <uses-permission android:name="android.permission.SYSTEM_ALERT_WINDOW"/>
  <uses-permission android:name="android.permission.BIND_ACCESSIBILITY_SERVICE"/>
  <uses-permission android:name="android.permission.RECEIVE_SMS"/>
  <application android:label="Definitely Your Bank"/>
</manifest>
""".encode()

BENIGN_MANIFEST = f"""<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="{ANDROID_NS}" package="com.ordinary.notes">
  <uses-permission android:name="android.permission.INTERNET"/>
  <application android:label="Notes"/>
</manifest>
""".encode()


def _apk_bytes(manifest=BANKER_MANIFEST) -> bytes:
    """A minimal APK: a ZIP carrying AndroidManifest.xml and a DEX."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("AndroidManifest.xml", manifest)
        z.writestr("classes.dex", b"dex\n035\x00" + b"\x00" * 64)
    return buf.getvalue()


def _zip_containing(name: str, payload: bytes) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr(name, payload)
    return buf.getvalue()


def _scan(client, payload: bytes, filename: str) -> dict:
    res = client.post("/upload",
                      files={"file": (filename, io.BytesIO(payload), "application/octet-stream")})
    assert res.status_code == 200, res.text
    status = client.get(f"/status/{res.json()['job_id']}").json()
    assert status["status"] == "Completed"
    return status["results"]


def _apk_points(results: dict) -> int:
    for entry in results.get("score_breakdown") or []:
        if entry["label"] == "APK Permissions":
            return entry["points"]
    return 0


# ── The fixture must be a real APK, or every assertion below is vacuous ──────

def test_the_fixture_is_recognised_as_an_apk(client):
    results = _scan(client, _apk_bytes(), "banker.apk")
    assert results.get("apk_info", {}).get("is_apk") is True
    assert _apk_points(results) > 0, "the control case scores nothing — fixture is wrong"


# ── Renaming must not defeat analysis ────────────────────────────────────────

def test_apk_renamed_to_zip_is_still_analysed(client):
    """The analyser answers 'is this an APK' itself; the filename never should."""
    renamed = _scan(client, _apk_bytes(), "totally-not-an-apk.zip")

    assert renamed.get("apk_info", {}).get("is_apk") is True, "renaming defeated APK analysis"
    assert _apk_points(renamed) > 0


def test_apk_renamed_scores_the_same_as_the_original(client):
    original = _scan(client, _apk_bytes(), "banker.apk")
    renamed = _scan(client, _apk_bytes(), "invoice.zip")

    assert _apk_points(renamed) == _apk_points(original), (
        "the same bytes scored differently depending on the filename"
    )


# ── Wrapping must not defeat analysis ────────────────────────────────────────

def test_apk_inside_a_zip_is_analysed(client):
    wrapped = _scan(client, _zip_containing("payload.apk", _apk_bytes()), "delivery.zip")

    assert wrapped.get("apk_info", {}).get("is_apk") is True, (
        "an APK inside a ZIP lost all Android analysis"
    )
    assert _apk_points(wrapped) > 0


def test_a_wrapped_apk_names_the_member_it_came_from(client):
    wrapped = _scan(client, _zip_containing("payload.apk", _apk_bytes()), "delivery.zip")

    assert wrapped.get("apk_info", {}).get("matched_file") == "payload.apk", (
        "the report cannot say which member the manifest came from"
    )


def test_wrapping_does_not_change_the_permission_score(client):
    direct = _scan(client, _apk_bytes(), "banker.apk")
    wrapped = _scan(client, _zip_containing("payload.apk", _apk_bytes()), "delivery.zip")

    assert _apk_points(wrapped) == _apk_points(direct), (
        "wrapping an APK in a ZIP changed its permission score"
    )


# ── Guard against the obvious overcorrection ─────────────────────────────────

def test_an_ordinary_zip_is_not_treated_as_an_apk(client):
    plain = _zip_containing("readme.txt", b"nothing to see here")
    results = _scan(client, plain, "documents.zip")

    assert not results.get("apk_info", {}).get("is_apk")
    assert _apk_points(results) == 0


def test_an_office_document_is_not_treated_as_an_apk(client):
    """OOXML files are ZIPs too — asking every ZIP must not misfire on them."""
    docx = io.BytesIO()
    with zipfile.ZipFile(docx, "w") as z:
        z.writestr("[Content_Types].xml", b"<?xml version='1.0'?><Types/>")
        z.writestr("word/document.xml", b"<?xml version='1.0'?><document/>")
    results = _scan(client, docx.getvalue(), "report.docx")

    assert not results.get("apk_info", {}).get("is_apk")


def test_a_benign_apk_does_not_score_on_permissions(client):
    """INTERNET alone is nearly every app on the store."""
    results = _scan(client, _apk_bytes(BENIGN_MANIFEST), "notes.apk")

    assert results["apk_info"]["is_apk"] is True
    assert _apk_points(results) == 0, "an ordinary app scored on permissions"


def test_a_direct_apk_is_not_overridden_by_a_nested_one(client):
    """An APK carrying another APK: the submitted artifact's own manifest is the
    one the verdict is about."""
    outer = io.BytesIO()
    with zipfile.ZipFile(outer, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("AndroidManifest.xml", BENIGN_MANIFEST)
        z.writestr("classes.dex", b"dex\n035\x00")
        z.writestr("assets/second.apk", _apk_bytes())
    results = _scan(client, outer.getvalue(), "outer.apk")

    assert results["apk_info"]["package"] == "com.ordinary.notes", (
        "a nested APK's manifest replaced the submitted APK's own"
    )


# ── NFC relay (2026 contactless-theft pattern) ───────────────────────────────

NFC_RELAY_MANIFEST = f"""<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="{ANDROID_NS}" package="com.fake.pay">
  <uses-permission android:name="android.permission.NFC"/>
  <uses-permission android:name="android.permission.BIND_ACCESSIBILITY_SERVICE"/>
  <application android:label="Contactless Helper"/>
</manifest>
""".encode()

NFC_ONLY_MANIFEST = f"""<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="{ANDROID_NS}" package="com.transit.card">
  <uses-permission android:name="android.permission.NFC"/>
  <uses-permission android:name="android.permission.INTERNET"/>
  <application android:label="Transit Card"/>
</manifest>
""".encode()


def test_nfc_alone_does_not_score(client):
    """Payment, transit and access-badge apps all use NFC legitimately — on its
    own it must carry no weight at all."""
    results = _scan(client, _apk_bytes(NFC_ONLY_MANIFEST), "transit.apk")

    assert results["apk_info"]["is_apk"] is True
    assert _apk_points(results) == 0, "an ordinary NFC app was scored"


def test_nfc_is_reported_even_though_it_does_not_score(client):
    """It was previously invisible; an analyst should still see it."""
    results = _scan(client, _apk_bytes(NFC_ONLY_MANIFEST), "transit.apk")
    assert "android.permission.NFC" in results["apk_info"]["dangerous_permissions"]


def test_nfc_with_accessibility_is_the_relay_pattern(client):
    results = _scan(client, _apk_bytes(NFC_RELAY_MANIFEST), "helper.apk")

    assert _apk_points(results) > 0
    assert any("contactless-relay" in r for r in results.get("reasons") or []), (
        "the NFC relay combination was not called out"
    )
