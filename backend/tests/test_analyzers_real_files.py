"""
The analysers, run against real files rather than hand-written dicts.

tests/corpus/ feeds calculate_score() dictionaries describing what an analyser
"would have produced". That tests the scorer's reaction to inputs invented by
whoever wrote the fixture — it cannot tell you the analyser actually produces
them. Two things hid in that gap:

  - apk_analyzer only read *plain-text* AndroidManifest.xml. Every APK built by
    the Android toolchain ships binary AXML, so permission extraction returned
    an empty list for every real APK, and a sideloaded banking trojan looked
    like an app requesting no permissions at all.
  - the whole YARA rule file failed to compile, which no test noticed because no
    test had ever executed a rule.

So: build files with the real structure, run the real analysers, and assert the
fields the corpus fixtures rely on actually appear.
"""

import io
import os
import tempfile
import zipfile

import pytest

from analysis_engine.apk_analyzer import analyze_apk
from analysis_engine.document_analyzer import analyze_document

DANGEROUS = [
    "android.permission.READ_SMS",
    "android.permission.SEND_SMS",
    "android.permission.RECEIVE_SMS",
    "android.permission.BIND_DEVICE_ADMIN",
    "android.permission.CAMERA",
]


@pytest.fixture
def tmpfile():
    made = []

    def _write(payload: bytes, suffix: str) -> str:
        fd, path = tempfile.mkstemp(suffix=suffix)
        with os.fdopen(fd, "wb") as fh:
            fh.write(payload)
        made.append(path)
        return path

    yield _write
    for p in made:
        try:
            os.unlink(p)
        except OSError:
            pass


def _apk(manifest: bytes) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("AndroidManifest.xml", manifest)
        z.writestr("classes.dex", b"dex\n035\x00" + b"\x00" * 64)
    return buf.getvalue()


def _axml(perms, encoding="utf-16-le"):
    """A binary AXML manifest: 0x00080003 magic plus a string pool.

    Not a real AXML encoder — just the part that matters here, which is that the
    permission names live in the pool as readable text and the header is not XML.
    """
    if encoding == "utf-16-le":
        pool = b"".join(len(p).to_bytes(2, "little") + p.encode("utf-16-le") + b"\x00\x00" for p in perms)
    else:
        pool = b"".join(p.encode() + b"\x00" for p in perms)
    return b"\x03\x00\x08\x00" + len(pool).to_bytes(4, "little") + pool


# ── APK ───────────────────────────────────────────────────────────────────────

def test_permissions_are_read_from_a_binary_axml_manifest(tmpfile):
    """The regression that mattered: real APKs are all binary AXML."""
    result = analyze_apk(tmpfile(_apk(_axml(DANGEROUS)), ".apk"))
    assert result["is_apk"]
    assert set(result["dangerous_permissions"]) == set(DANGEROUS), \
        "binary AXML manifest yielded no permissions — the case every real APK hits"


def test_permissions_are_read_from_utf8_axml(tmpfile):
    """Newer builds encode the string pool as UTF-8 rather than UTF-16."""
    result = analyze_apk(tmpfile(_apk(_axml(DANGEROUS, "utf-8")), ".apk"))
    assert set(result["dangerous_permissions"]) == set(DANGEROUS)


def test_plain_text_manifest_still_works(tmpfile):
    """The original path must survive the fallback being added."""
    manifest = (
        b'<manifest package="com.example.app" '
        b'xmlns:android="http://schemas.android.com/apk/res/android">'
        + b"".join(f'<uses-permission android:name="{p}"/>'.encode() for p in DANGEROUS)
        + b"</manifest>"
    )
    result = analyze_apk(tmpfile(_apk(manifest), ".apk"))
    assert set(result["dangerous_permissions"]) == set(DANGEROUS)
    assert result["package"] == "com.example.app", "plain-text parse lost the package name"


def test_apk_with_no_permissions_reports_none(tmpfile):
    """The string-pool scan must not invent permissions that are not there."""
    result = analyze_apk(tmpfile(_apk(_axml([])), ".apk"))
    assert result["dangerous_permissions"] == []


def test_non_apk_zip_is_not_an_apk(tmpfile):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("hello.txt", b"just a zip")
    assert not analyze_apk(tmpfile(buf.getvalue(), ".zip"))["is_apk"]


# ── Documents ─────────────────────────────────────────────────────────────────
# The corpus asserts on doc_type / has_javascript / has_js_auto_combo /
# has_launch_action / has_macros. These check the analyser really emits them.

def test_driveby_pdf_fields_match_what_the_corpus_asserts(tmpfile):
    pdf = (
        b"%PDF-1.7\n"
        b"1 0 obj<</Type/Catalog/OpenAction<</S/JavaScript/JS(app.alert\\(1\\);)>>>>endobj\n"
        b"2 0 obj<</S/Launch/F(cmd.exe)>>endobj\n"
        b"trailer<</Root 1 0 R>>\n%%EOF"
    )
    doc = analyze_document(tmpfile(pdf, ".pdf"), "invoice.pdf")
    assert doc["doc_type"] == "pdf"
    assert doc["has_javascript"]
    assert doc["has_launch_action"]
    assert doc["has_js_auto_combo"], \
        "JavaScript wired to OpenAction not detected — the field the corpus scores 45 on"


def test_ordinary_form_pdf_is_not_a_driveby(tmpfile):
    """Form JS and a page-navigation action, not wired together."""
    pdf = (
        b"%PDF-1.7\n"
        b"1 0 obj<</Type/Catalog/OpenAction<</S/GoTo/D[2 0 R]>>>>endobj\n"
        b"2 0 obj<</Type/Page/AA<</Fo<</S/JavaScript/JS(validate\\(\\);)>>>>>>endobj\n"
        b"trailer<</Root 1 0 R>>\n%%EOF"
    )
    doc = analyze_document(tmpfile(pdf, ".pdf"), "taxform.pdf")
    assert doc["doc_type"] == "pdf"
    assert not doc["has_js_auto_combo"], \
        "ordinary form PDF classified as a drive-by — scores 45 instead of 15"
    assert not doc.get("has_launch_action")


def test_macro_document_is_detected(tmpfile):
    """OOXML is a ZIP; a macro lives at word/vbaProject.bin."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("[Content_Types].xml", b"<Types/>")
        z.writestr("word/document.xml", b"<w:document/>")
        z.writestr("word/vbaProject.bin", b"\xd0\xcf\x11\xe0" + b"Attribute VB_Name\x00Shell(")
    doc = analyze_document(tmpfile(buf.getvalue(), ".docm"), "resume.docm")
    assert doc["doc_type"] == "ooxml"
    assert doc["has_macros"], "vbaProject.bin present but has_macros not set"


def test_macro_free_docx_is_clean(tmpfile):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("[Content_Types].xml", b"<Types/>")
        z.writestr("word/document.xml", b"<w:document>ordinary text</w:document>")
    doc = analyze_document(tmpfile(buf.getvalue(), ".docx"), "notes.docx")
    assert doc["doc_type"] == "ooxml"
    assert not doc["has_macros"]


def test_page_open_javascript_is_still_a_driveby(tmpfile):
    """/AA with the page-open key (/O) does auto-execute — this must stay caught
    after narrowing /AA to exclude form-field actions."""
    pdf = (
        b"%PDF-1.7\n"
        b"1 0 obj<</Type/Page/AA<</O<</S/JavaScript/JS(payload\(\);)>>>>>>endobj\n"
        b"trailer<</Root 1 0 R>>\n%%EOF"
    )
    doc = analyze_document(tmpfile(pdf, ".pdf"), "x.pdf")
    assert doc["has_js_auto_combo"], "page-open JavaScript no longer detected"


@pytest.mark.parametrize("action", [b"/Fo", b"/Bl", b"/K", b"/V", b"/C", b"/F"])
def test_form_field_javascript_is_not_a_driveby(tmpfile, action):
    """Every field-level action runs on user interaction, not on open."""
    pdf = (
        b"%PDF-1.7\n1 0 obj<</Type/Annot/AA<<" + action +
        b"<</S/JavaScript/JS(validate\(\);)>>>>>>endobj\ntrailer<</Root 1 0 R>>\n%%EOF"
    )
    doc = analyze_document(tmpfile(pdf, ".pdf"), "form.pdf")
    assert not doc["has_js_auto_combo"], f"form action {action.decode()} treated as drive-by"
