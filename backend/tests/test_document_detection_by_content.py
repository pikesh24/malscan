"""
Office document analysis must follow the content, not the filename.

Found by re-auditing for the bug pattern behind the APK gate: dispatch decided
by extension. OOXML analysis ran only for `.docx/.xlsx/.pptx/.docm/.xlsm/.pptm`
or for a file with NO extension at all, so a macro-bearing document renamed to
`.zip` — or `.dat`, or anything else — skipped VBA detection and came back
`doc_type=unknown`. Renaming a file is free, and macro documents are one of the
most common delivery mechanisms there is.

Widening the gate needed the identification tightened first. `is_ooxml` was set
by the presence of any member ending `.xml`, `.rels` or `.bin`, which is true of
an APK (AndroidManifest.xml) and of a browser extension — so handing every ZIP
to the OOXML analyser would have started reporting Android packages as Office
documents. Both halves are pinned below.
"""

import io
import json
import zipfile

import pytest

from analysis_engine.document_analyzer import analyze_document


def _macro_document() -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("[Content_Types].xml", '<?xml version="1.0"?><Types/>')
        z.writestr("word/document.xml", '<?xml version="1.0"?><document/>')
        z.writestr("word/vbaProject.bin", b"\xd0\xcf\x11\xe0Auto_Open" + b"\x00" * 200)
    return buf.getvalue()


def _apk() -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("AndroidManifest.xml", "<manifest/>")
        z.writestr("classes.dex", b"dex\n035\x00")
    return buf.getvalue()


def _extension() -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("manifest.json", json.dumps({"manifest_version": 3, "name": "x"}))
        z.writestr("background.js", "console.log(1)")
    return buf.getvalue()


def _plain_zip() -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("notes.txt", "hello")
    return buf.getvalue()


def _write(tmp_path, payload, name="sample.bin"):
    path = tmp_path / name
    path.write_bytes(payload)
    return str(path)


# ── Renaming must not defeat macro detection ─────────────────────────────────

@pytest.mark.parametrize("filename", ["invoice.docm", "invoice.zip", "invoice.dat",
                                      "invoice", "invoice.txt", "invoice.jpg"])
def test_macros_are_found_whatever_the_file_is_called(tmp_path, filename):
    result = analyze_document(_write(tmp_path, _macro_document()), filename)

    assert result["doc_type"] == "ooxml", f"renamed to {filename}, analysis was skipped"
    assert result["has_macros"] is True


def test_the_control_case_really_does_contain_macros(tmp_path):
    """Guards the fixture: if this ever stops finding macros, every case above
    is passing for the wrong reason."""
    result = analyze_document(_write(tmp_path, _macro_document()), "invoice.docm")
    assert result["has_macros"] is True
    assert any("vbaProject" in f for f in result.get("suspicious_flags") or [])


# ── Other ZIP-shaped formats must not become "Office documents" ──────────────

@pytest.mark.parametrize("payload,label", [
    (_apk(), "APK"),
    (_extension(), "browser extension"),
    (_plain_zip(), "plain ZIP"),
], ids=["apk", "crx", "plain-zip"])
def test_other_zip_formats_are_not_reported_as_office_documents(tmp_path, payload, label):
    """The reason the gate could not simply be widened: an APK carries
    AndroidManifest.xml, and the old is_ooxml test was 'any .xml member'."""
    result = analyze_document(_write(tmp_path, payload), "sample.zip")

    assert result["doc_type"] != "ooxml", f"a {label} was analysed as an Office document"


def test_a_real_document_without_macros_is_still_recognised(tmp_path):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("[Content_Types].xml", '<?xml version="1.0"?><Types/>')
        z.writestr("word/document.xml", '<?xml version="1.0"?><document>text</document>')
    result = analyze_document(_write(tmp_path, buf.getvalue()), "report.docx")

    assert result["doc_type"] == "ooxml"
    assert result["has_macros"] is False


def test_legacy_ole_is_still_found_by_magic_bytes(tmp_path):
    """The OLE path already had a magic-byte fallback; make sure widening the
    OOXML gate did not shadow it."""
    ole = b"\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1" + b"\x00" * 2048
    result = analyze_document(_write(tmp_path, ole), "invoice.bin")
    assert result["doc_type"] == "ole"


def test_a_pdf_is_still_a_pdf(tmp_path):
    result = analyze_document(_write(tmp_path, b"%PDF-1.7\n" + b"\x00" * 500), "x.bin")
    assert result["doc_type"] == "pdf"
