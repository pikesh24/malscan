"""
analysis_engine/html_analyzer.py
HTML attachment analysis — smuggling and clipboard-injection lures.

Why this exists
---------------
An HTML attachment looks inert. Nothing executes on the mail server, there is no
macro, and the file often contains no URL at all — which is exactly the point.
In HTML smuggling (MITRE T1027.006) the payload travels as text inside the page:
JavaScript decodes it and uses the Blob API with URL.createObjectURL to assemble
a real file in the browser's memory, then triggers a download. Nothing is ever
fetched from the network, so a gateway that inspects downloads sees nothing and
a reputation service has no URL to rate.

Malscan previously read such a file as "some text" — entropy low, no IOCs, no
YARA hit, verdict Clear.

The strongest signal here is not a keyword
------------------------------------------
Keyword matching on Blob/createObjectURL finds the common case and misses
anything obfuscated, which is most of it: payloads get split across variables,
XOR'd, reversed, or wrapped in several encoding layers.

So the primary check decodes the embedded data and looks at what it actually is.
A page carrying a base64 blob that decodes to `MZ` is smuggling a Windows
executable, whatever the surrounding JavaScript looks like, and no amount of
obfuscation of the *loader* changes what the *payload* decodes to. Keyword
patterns stay as corroboration.
"""

import base64
import binascii
import logging
import re

logger = logging.getLogger(__name__)

# HTML files are large; regex over an unbounded attachment is a denial of
# service in itself. Smuggled payloads sit near the top in practice, and this is
# generous enough for a several-megabyte embedded executable.
MAX_HTML_BYTES = 8 * 1024 * 1024

# Below this, a base64 run is an icon or a font, not a payload. Ordinary inline
# images clear a few hundred characters; smuggled executables are far larger.
MIN_PAYLOAD_B64 = 2000

# Enough decoded bytes to identify a file type.
_MAGIC_PROBE_BYTES = 32

# What a decoded blob turning out to be tells us. Ordered longest-first so ZIP
# does not shadow the Office/APK cases that share its signature.
_DECODED_MAGIC = [
    (b"MZ",                     "a Windows executable (PE)"),
    (b"\x7fELF",                "a Linux executable (ELF)"),
    (b"PK\x03\x04",            "a ZIP archive (or Office/JAR/APK)"),
    (b"Rar!",                   "a RAR archive"),
    (b"\x37\x7A\xBC\xAF\x27\x1C", "a 7-Zip archive"),
    (b"%PDF",                   "a PDF document"),
    (b"\xD0\xCF\x11\xE0",      "a legacy Office document"),
    (b"\x4C\x00\x00\x00\x01\x14\x02", "a Windows shortcut (LNK)"),
    (b"\x1F\x8B",              "a GZIP archive"),
]

_HTML_MARKERS = (b"<html", b"<!doctype html", b"<script", b"<body", b"<head", b"<iframe")

# (code, pattern, description). Patterns are BYTES: an HTML attachment has no
# guaranteed encoding and may be UTF-16 or simply malformed, so the file is
# never decoded to str — a decode error must not be the thing that stops a
# smuggled payload being found.
_PATTERNS = [
    ("blob_construction",
     re.compile(rb"new\s+Blob\s*\(", re.I),
     "Builds a file in memory with the Blob API"),
    ("object_url",
     re.compile(rb"URL\.createObjectURL|webkitURL\.createObjectURL", re.I),
     "Turns in-memory data into a downloadable link (createObjectURL)"),
    ("ms_save_blob",
     re.compile(rb"msSaveOrOpenBlob|msSaveBlob", re.I),
     "Uses the legacy Internet Explorer blob-save API"),
    ("forced_download",
     re.compile(rb"\.download\s*=|<a[^>]+\bdownload\b", re.I),
     "Sets a download filename programmatically"),
    ("synthetic_click",
     re.compile(rb"\.click\s*\(\s*\)", re.I),
     "Clicks a link from script rather than waiting for the user"),
    ("base64_decode",
     re.compile(rb"\batob\s*\(|fromCharCode|frombase64string", re.I),
     "Decodes embedded data at run time"),
    ("obfuscation",
     re.compile(rb"\beval\s*\(|unescape\s*\(|decodeURIComponent\s*\(\s*escape", re.I),
     "Run-time code assembly (eval/unescape)"),
    ("meta_refresh_data_uri",
     re.compile(rb"http-equiv=[\"']?refresh[^>]+data:", re.I),
     "Meta refresh pointing at an inline data: payload"),
    ("data_uri_octet_stream",
     re.compile(rb"data:application/(octet-stream|x-msdownload|zip|x-7z|vnd\.microsoft\.portable-executable)", re.I),
     "Inline data: URI declaring an executable or archive"),
    # ClickFix / fake-CAPTCHA lures: the page writes a command to the clipboard
    # and instructs the user to run it. There is no download at all, so this is
    # the only artifact that ever exists.
    ("clipboard_write",
     re.compile(rb"navigator\.clipboard\.writeText|execCommand\s*\(\s*[\"']copy", re.I),
     "Writes to the clipboard from script"),
    ("run_dialog_lure",
     re.compile(rb"win(dows)?\s*\+\s*r\b|\bwin\s*key\s*\+\s*r\b|press\s+ctrl\s*\+\s*v", re.I),
     "Instructs the user to open the Run dialog and paste"),
    ("shell_command_text",
     re.compile(rb"powershell(\.exe)?\s+-|cmd(\.exe)?\s+/c|mshta\s+http|curl\s+http.{0,80}\|\s*iex", re.I),
     "Contains a shell command line in the page text"),
]

# Long runs of base64. Excludes anything immediately preceded by an image data
# URI, which is the one legitimate reason for a large blob in a page.
_B64_RUN = re.compile(rb"[A-Za-z0-9+/=]{%d,}" % MIN_PAYLOAD_B64)
_IMAGE_DATA_URI = re.compile(rb"data:image/[a-z+]{2,12};base64,\s*$", re.I)

# Payloads are also smuggled as arrays of integers, which sidesteps every
# base64 check.
_INT_ARRAY = re.compile(rb"\[\s*(?:\d{1,3}\s*,\s*){400,}\d{1,3}\s*\]")


def looks_like_html(data: bytes, filename: str = "") -> bool:
    if filename.lower().endswith((".html", ".htm", ".xhtml", ".hta", ".svg")):
        return True
    head = data[:4096].lower()
    return any(marker in head for marker in _HTML_MARKERS)


def _identify_decoded(blob: bytes) -> str | None:
    """Decodes the start of a base64 run and reports what it turned out to be."""
    sample = blob[: ((_MAGIC_PROBE_BYTES * 4 // 3) + 8)]
    sample = sample[: len(sample) - (len(sample) % 4)]
    if len(sample) < 8:
        return None
    try:
        decoded = base64.b64decode(sample, validate=False)
    except (binascii.Error, ValueError):
        return None
    for magic, description in _DECODED_MAGIC:
        if decoded.startswith(magic):
            return description
    return None


def analyze_html(file_path: str, data: bytes = None, filename: str = "") -> dict:
    """
    Reports whether an HTML file is smuggling a payload or running a
    clipboard-injection lure. Returns is_html False for anything else.
    """
    result = {
        "is_html": False,
        "findings": [],
        "codes": [],
        "smuggled_payload": None,
        "largest_base64_run": 0,
    }

    try:
        if data is None:
            with open(file_path, "rb") as fh:
                data = fh.read(MAX_HTML_BYTES)
    except OSError as e:
        logger.warning(f"HTML read failed for {file_path}: {e}")
        return result

    if not data or not looks_like_html(data, filename):
        return result
    result["is_html"] = True
    data = data[:MAX_HTML_BYTES]

    findings, codes = [], []

    def record(code, description):
        if code not in codes:
            codes.append(code)
            findings.append(description)

    # 1. What does the embedded data actually decode to? This is the evidence;
    #    everything below is corroboration.
    for match in _B64_RUN.finditer(data):
        run = match.group()
        result["largest_base64_run"] = max(result["largest_base64_run"], len(run))
        preceding = data[max(0, match.start() - 64):match.start()]
        if _IMAGE_DATA_URI.search(preceding):
            continue          # an inline image, which is ordinary
        identified = _identify_decoded(run)
        if identified:
            result["smuggled_payload"] = identified
            record("smuggled_payload",
                   f"Page carries {len(run):,} characters of base64 that decode to {identified}")
            break
        record("large_encoded_blob",
               f"Page carries a {len(run):,}-character encoded blob that is not an image")

    if _INT_ARRAY.search(data):
        record("int_array_payload",
               "Payload embedded as a long integer array — a common way to avoid base64 checks")

    # 2. Corroborating behaviour.
    text = data
    for code, pattern, description in _PATTERNS:
        if pattern.search(text):
            record(code, description)

    result["findings"], result["codes"] = findings, codes
    return result
