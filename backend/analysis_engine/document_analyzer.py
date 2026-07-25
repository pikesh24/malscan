"""
analysis_engine/document_analyzer.py

Deep content analysis for document formats commonly received via WhatsApp:
  - PDF  (.pdf)           — embedded JavaScript, auto-actions, Launch, embedded files
  - OOXML (.docx/.xlsx/.pptx) — VBA macro presence, suspicious XML patterns
  - Legacy OLE (.doc/.xls/.ppt) — OLE VBA stream, macro signatures

No external dependencies — uses only stdlib (zipfile, re, struct).
"""

import os
import re
import zipfile
import logging

logger = logging.getLogger(__name__)

# Decompression budget for OOXML member scanning — a ≤50 MB Office file can claim
# to inflate to gigabytes (zip bomb); never read more than this in total.
MAX_OOXML_DECOMPRESSED_BYTES = 200 * 1024 * 1024

# ── PDF suspicious markers ────────────────────────────────────────────────────

PDF_DANGER_PATTERNS = [
    (rb"/JavaScript",       "Embedded JavaScript (can execute code on open)"),
    (rb"/JS\s",             "Embedded JavaScript (abbreviated form)"),
    (rb"/JS\(",             "Embedded JavaScript (abbreviated form)"),
    (rb"/OpenAction",       "Auto-execute action on document open"),
    (rb"/AA\s",             "Additional auto-action trigger"),
    (rb"/Launch",           "Launch action (can execute external programs)"),
    (rb"/EmbeddedFile",     "Embedded file inside PDF"),
    (rb"/EmbeddedFiles",    "Embedded file collection"),
    (rb"/RichMedia",        "Rich media embedding (potential exploit vector)"),
    (rb"/XFA",              "XFA form (exploited in targeted attacks)"),
    (rb"eval\s*\(",         "eval() call in PDF content"),
    (rb"unescape\s*\(",     "unescape() call — common in obfuscated JS"),
    (rb"String\.fromCharCode", "String.fromCharCode — common obfuscation"),
]

# ── OOXML (DOCX/XLSX/PPTX) suspicious patterns ───────────────────────────────

MACRO_INDICATOR_FILES = {
    "word/vbaProject.bin",
    "xl/vbaProject.bin",
    "ppt/vbaProject.bin",
    "xl/xlm/macrosheets/",
}

OOXML_SUSPICIOUS_XML = [
    (b"AutoOpen",       "AutoOpen macro — runs automatically on document open"),
    (b"AutoClose",      "AutoClose macro"),
    (b"Document_Open",  "Document_Open event handler"),
    (b"Workbook_Open",  "Workbook_Open event handler — auto-runs on spreadsheet open"),
    (b"Shell(",         "Shell() call inside Office document — can execute OS commands"),
    (b"CreateObject",   "CreateObject — used to spawn processes in VBA malware"),
    (b"WScript",        "Windows Script Host reference"),
    (b"PowerShell",     "PowerShell execution from document macro"),
    (b"cmd.exe",        "cmd.exe reference in document content"),
    (b"http://",        "HTTP URL embedded in document XML"),
    (b"https://",       "HTTPS URL embedded in document XML"),
    (b"DDEAUTO",        "DDE auto-execute field (no-macro malware vector)"),
    (b"DDE ",           "DDE field — can execute commands without macros"),
]

# ── Legacy OLE (.doc/.xls/.ppt) markers ──────────────────────────────────────

OLE_SIGNATURE = b"\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1"   # Compound Document File
VBA_SIGNATURES = [
    b"VBA",
    b"Attribute VB_Name",
    b"Sub AutoOpen",
    b"Sub Auto_Open",
    b"Sub Document_Open",
    b"Shell(",
    b"CreateObject",
    b"DDEAUTO",
]

# ── Suspicious macro keyword patterns (for scoring) ──────────────────────────

MACRO_SUSPICIOUS_KEYWORDS = [
    "shell", "createobject", "wscript", "powershell", "cmd.exe",
    "environ", "killprocess", "autoopen", "document_open", "workbook_open",
    "ddeauto", "xmlhttp", "winhttp", "download", "urldownloadtofile",
]


def _extract_pdf_urls(content: bytes) -> list:
    urls = set()
    for m in re.findall(rb"https?://[^\x00-\x1f\x7f-\xff\s<>\")\]]{4,}", content):
        try:
            urls.add(m.decode("latin-1", errors="ignore"))
        except Exception:
            pass
    return list(urls)[:30]


def analyze_pdf(file_path: str) -> dict:
    result = {
        "is_pdf": False,
        "has_javascript": False,
        "has_auto_action": False,
        "has_launch_action": False,
        "has_embedded_files": False,
        "has_js_auto_combo": False,
        "suspicious_flags": [],
        "extracted_urls": [],
        "page_count": None,
    }

    try:
        with open(file_path, "rb") as f:
            header = f.read(5)
            if not header.startswith(b"%PDF"):
                return result
            f.seek(0)
            content = f.read()

        result["is_pdf"] = True

        # Page count heuristic
        page_matches = re.findall(rb"/Type\s*/Page[^s]", content)
        if page_matches:
            result["page_count"] = len(page_matches)

        for pattern, description in PDF_DANGER_PATTERNS:
            if re.search(pattern, content, re.IGNORECASE):
                result["suspicious_flags"].append(description)
                if b"JavaScript" in pattern or b"JS" in pattern:
                    result["has_javascript"] = True
                if b"OpenAction" in pattern or b"AA" in pattern:
                    result["has_auto_action"] = True
                if b"Launch" in pattern:
                    result["has_launch_action"] = True
                if b"EmbeddedFile" in pattern:
                    result["has_embedded_files"] = True

        # JavaScript bound DIRECTLY to an open/auto trigger (e.g.
        # "/OpenAction << /S /JavaScript ... >>") — the classic drive-by PDF
        # pattern. Mere co-existence of /JS and /OpenAction in the same file is
        # NOT flagged here; that combination is normal for interactive forms.
        # /AA is "additional actions", and the sub-key decides everything. On a
        # form field (/Fo focus, /K keystroke, /V validate, /C calculate, /F
        # format) the JavaScript runs only when a user interacts with the field —
        # that is what every interactive form does. Only a page-open action (/O)
        # fires by itself.
        #
        # Matching /AA followed by any JavaScript treated ordinary form fields as
        # drive-by documents, scoring them 45 instead of 15. /OpenAction is
        # unambiguous: it is the document-open handler, so JS in it does execute
        # on open.
        _js_auto = (
            rb"/OpenAction\b[^>]{0,400}?/(JS|JavaScript)\b",
            rb"/AA\b[^>]{0,200}?/O\b[^>]{0,200}?/(JS|JavaScript)\b",
        )
        if any(re.search(p, content, re.IGNORECASE | re.DOTALL) for p in _js_auto):
            result["has_js_auto_combo"] = True
            result["suspicious_flags"].append(
                "JavaScript wired to execute automatically on document open"
            )

        result["extracted_urls"] = _extract_pdf_urls(content)

    except Exception as e:
        logger.warning(f"PDF analysis error for {file_path}: {e}")
        result["error"] = str(e)

    return result


def analyze_office_ooxml(file_path: str) -> dict:
    """Analyse DOCX / XLSX / PPTX (all ZIP-based Office Open XML formats)."""
    result = {
        "is_ooxml": False,
        "has_macros": False,
        "suspicious_flags": [],
        "suspicious_macro_keywords": [],
        "extracted_urls": [],
    }

    try:
        if not zipfile.is_zipfile(file_path):
            return result

        with zipfile.ZipFile(file_path, "r") as zf:
            names_lower = {n.lower() for n in zf.namelist()}

            # Check for VBA project
            for macro_file in MACRO_INDICATOR_FILES:
                if macro_file.lower() in names_lower or any(macro_file.lower() in n for n in names_lower):
                    result["is_ooxml"] = True
                    result["has_macros"] = True
                    result["suspicious_flags"].append(
                        "Office document contains VBA macros (vbaProject.bin present)"
                    )
                    break

            # Scan all XML content for suspicious patterns
            urls = set()
            found_keywords = set()
            budget = MAX_OOXML_DECOMPRESSED_BYTES
            for member_name in zf.namelist():
                lower = member_name.lower()
                if not (lower.endswith(".xml") or lower.endswith(".rels") or lower.endswith(".bin")):
                    continue
                if lower.endswith(".png") or lower.endswith(".jpg"):
                    continue
                result["is_ooxml"] = True
                try:
                    # Zip-bomb guard: never read more than the remaining budget.
                    declared = zf.getinfo(member_name).file_size
                    if declared > budget:
                        logger.warning(f"OOXML member {member_name} ({declared} bytes) exceeds remaining decompression budget — skipping")
                        continue
                    budget -= declared
                    data = zf.read(member_name)
                    for pattern, description in OOXML_SUSPICIOUS_XML:
                        if pattern in data:
                            if description not in result["suspicious_flags"]:
                                result["suspicious_flags"].append(description)

                    # URL extraction from XML
                    for m in re.findall(rb"https?://[^\x00-\x1f\x7f<>\"'\s]{4,}", data):
                        try:
                            urls.add(m.decode("latin-1", errors="ignore"))
                        except Exception:
                            pass

                    # Keyword matching for macro content
                    data_lower = data.lower()
                    for kw in MACRO_SUSPICIOUS_KEYWORDS:
                        if kw.encode() in data_lower:
                            found_keywords.add(kw)
                except Exception:
                    continue

            result["extracted_urls"] = list(urls)[:20]
            result["suspicious_macro_keywords"] = list(found_keywords)

    except Exception as e:
        logger.warning(f"OOXML analysis error for {file_path}: {e}")
        result["error"] = str(e)

    return result


def analyze_ole_document(file_path: str) -> dict:
    """Analyse legacy .doc/.xls/.ppt (OLE Compound Document format)."""
    result = {
        "is_ole": False,
        "has_macros": False,
        "suspicious_flags": [],
        "suspicious_macro_keywords": [],
    }

    try:
        with open(file_path, "rb") as f:
            header = f.read(8)
            if header != OLE_SIGNATURE:
                return result
            f.seek(0)
            content = f.read()

        result["is_ole"] = True

        found_keywords = set()
        for sig in VBA_SIGNATURES:
            if sig in content:
                result["has_macros"] = True
                kw = sig.decode("latin-1", errors="ignore").strip()
                if kw not in ("VBA",) and kw not in result["suspicious_flags"]:
                    result["suspicious_flags"].append(f"VBA pattern found: {kw}")
                found_keywords.add(kw.lower())

        if result["has_macros"]:
            result["suspicious_flags"].insert(
                0, "Legacy Office document contains VBA macros"
            )

        result["suspicious_macro_keywords"] = list(found_keywords)

    except Exception as e:
        logger.warning(f"OLE analysis error for {file_path}: {e}")
        result["error"] = str(e)

    return result


def analyze_document(file_path: str, filename: str = "") -> dict:
    """
    Main entry point. Detects file type and runs the appropriate analyser.
    Returns unified result dict with 'doc_type' key.
    """
    ext = os.path.splitext(filename.lower())[1] if filename else ""

    # Try PDF first (by magic bytes)
    try:
        with open(file_path, "rb") as f:
            magic = f.read(5)
        if magic.startswith(b"%PDF") or ext == ".pdf":
            result = analyze_pdf(file_path)
            result["doc_type"] = "pdf"
            return result
    except Exception:
        pass

    # Try OOXML (DOCX/XLSX/PPTX)
    if ext in (".docx", ".xlsx", ".pptx", ".docm", ".xlsm", ".pptm") or (
        not ext and zipfile.is_zipfile(file_path)
    ):
        result = analyze_office_ooxml(file_path)
        if result.get("is_ooxml"):
            result["doc_type"] = "ooxml"
            return result

    # Try legacy OLE
    if ext in (".doc", ".xls", ".ppt", ".docm", ".xlsm"):
        result = analyze_ole_document(file_path)
        if result.get("is_ole"):
            result["doc_type"] = "ole"
            return result

    # Unknown document type — try OLE by magic bytes as last resort
    try:
        with open(file_path, "rb") as f:
            magic = f.read(8)
        if magic == OLE_SIGNATURE:
            result = analyze_ole_document(file_path)
            result["doc_type"] = "ole"
            return result
    except Exception:
        pass

    return {"doc_type": "unknown"}
