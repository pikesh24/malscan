"""
analysis_engine/script_analyzer.py
Script dropper analysis — JS, VBS, WSF, HTA, BAT.

Why this exists
---------------
Scripts were covered only by raw string matching and YARA, which finds the plain
ones and misses everything obfuscated — and obfuscation is the norm here, since
a script is text and rewriting text is free. A .js dropper that builds
`WScript.Shell` one character at a time matches no rule at all.

PowerShell already has YARA rules. Windows Script Host — .js, .vbs, .wsf, .hta —
had nothing, despite being a standard attachment payload for decades and a
common second stage inside archives and ISOs.

The discriminator that actually works
-------------------------------------
Obfuscation on its own is a bad signal: every minified JavaScript library on the
web looks obfuscated by any structural measure — long lines, high entropy,
single-character identifiers, endless concatenation. Weighting obfuscation
heavily would flag jQuery.

What is nearly unambiguous is the API surface. `WScript.Shell`, `ADODB.Stream`
and `ActiveXObject` do not exist in a browser. A .js file reaching for them is
not a web script that happens to be minified — it is a Windows Script Host
program, and the only reason to deliver one by email is to run it. So the APIs
carry the weight and obfuscation is a multiplier on top, not a finding by
itself.
"""

import logging
import math
import re

logger = logging.getLogger(__name__)

MAX_SCRIPT_BYTES = 4 * 1024 * 1024

SCRIPT_EXTENSIONS = {
    ".js": "JavaScript", ".jse": "Encoded JavaScript", ".mjs": "JavaScript",
    ".vbs": "VBScript", ".vbe": "Encoded VBScript", ".wsf": "Windows Script File",
    ".wsh": "Windows Script Host", ".hta": "HTML Application",
    ".ps1": "PowerShell", ".psm1": "PowerShell", ".bat": "Batch", ".cmd": "Batch",
    ".sh": "Shell", ".py": "Python", ".jar": "Java",
}

# Content markers, so a renamed script is still recognised.
_CONTENT_MARKERS = [
    (re.compile(rb"<job\b|<script\s+language=", re.I), "Windows Script File"),
    (re.compile(rb"\bDim\b.{0,40}\bSet\b|\bWScript\b|\bCreateObject\s*\(", re.I), "VBScript"),
    (re.compile(rb"\bfunction\s*\(|\bvar\s+\w+\s*=|=>\s*\{", re.I), "JavaScript"),
    (re.compile(rb"^\s*#!.*\b(bash|sh|python|perl)\b", re.I | re.M), "Shell"),
    (re.compile(rb"^\s*@echo\s+off|^\s*set\s+\w+=", re.I | re.M), "Batch"),
]

# (code, pattern, description, weightable)
#
# The first group is the Windows Script Host / ActiveX surface. None of it
# exists in a browser, so its presence in a delivered .js or .vbs is close to
# conclusive about what the file is for.
_BEHAVIOUR_PATTERNS = [
    ("wsh_shell",
     re.compile(rb"WScript\.Shell|Shell\.Application|WScript\.CreateObject", re.I),
     "Creates a Windows Script Host shell object — can run programs"),
    ("activex",
     re.compile(rb"\bActiveXObject\s*\(|\bCreateObject\s*\(", re.I),
     "Instantiates a COM/ActiveX object"),
    ("adodb_stream",
     re.compile(rb"ADODB\.Stream", re.I),
     "Uses ADODB.Stream — writes downloaded bytes to disk"),
    ("http_request",
     re.compile(rb"MSXML2\.XMLHTTP|WinHttp\.WinHttpRequest|ServerXMLHTTP|XMLHTTP", re.I),
     "Makes an HTTP request from script"),
    # VBScript calls subs without parentheses (`sh.Run "a.exe", 0, False`), so
    # requiring `(` missed the single most common form this appears in.
    ("shell_run",
     re.compile(rb"\.(Run|Exec|ShellExecute)\s*[\(\"']", re.I),
     "Executes a command"),
    ("filesystem_object",
     re.compile(rb"Scripting\.FileSystemObject", re.I),
     "Reads or writes files directly"),
    ("powershell_launch",
     re.compile(rb"powershell(\.exe)?[\s\"']+-|-enc(odedcommand)?\s+[A-Za-z0-9+/=]{40,}", re.I),
     "Launches PowerShell, or carries an encoded PowerShell command"),
    ("registry_persistence",
     re.compile(rb"RegWrite|CurrentVersion\\\\?Run|HKCU\\\\?Software\\\\?Microsoft", re.I),
     "Writes a registry key used for persistence"),
    ("scheduled_task",
     re.compile(rb"schtasks\s+/create|Register-ScheduledTask", re.I),
     "Creates a scheduled task for persistence"),
    ("eval_exec",
     re.compile(rb"\beval\s*\(|\bExecuteGlobal\b|\bExecute\s*\(|\bFunction\s*\(\s*[\"']", re.I),
     "Builds and runs code at run time"),
    ("amsi_bypass",
     re.compile(rb"AmsiScanBuffer|amsiInitFailed|System\.Management\.Automation\.AmsiUtils", re.I),
     "Attempts to disable the Antimalware Scan Interface"),
    ("hidden_window",
     re.compile(rb"\.Run\s*\([^)]{0,120},\s*0\s*,|WindowStyle\s*=\s*0|-w(indowstyle)?\s+hidden", re.I),
     "Runs a command with no visible window"),
    ("bitsadmin",
     re.compile(rb"bitsadmin|certutil\s+-urlcache|Start-BitsTransfer", re.I),
     "Downloads via a living-off-the-land utility"),
]

# Structural obfuscation. Reported, but weighted low on its own — every minified
# library on the web trips these.
_OBFUSCATION_PATTERNS = [
    ("char_code_assembly",
     re.compile(rb"fromCharCode|\bChrW?\s*\(\s*\d+\s*\)(\s*&\s*ChrW?\s*\(\s*\d+\s*\)){4,}", re.I),
     "Builds strings from character codes"),
    ("hex_escapes",
     re.compile(rb"(\\x[0-9a-fA-F]{2}){20,}"),
     "Long run of hex-escaped characters"),
    ("string_splicing",
     re.compile(rb"([\"'][^\"'\n]{0,3}[\"']\s*[+&]\s*){8,}"),
     "String assembled from many small fragments"),
    ("reverse_trick",
     re.compile(rb"\.split\s*\(\s*[\"']{2}\s*\)\s*\.reverse|StrReverse\s*\(", re.I),
     "Reverses a string to hide its contents"),
    ("base64_blob",
     re.compile(rb"[A-Za-z0-9+/=]{600,}"),
     "Large base64 blob embedded in the script"),
]

_URL_PATTERN = re.compile(rb"https?://[^\s\"'<>)]{4,}", re.I)


def _shannon_entropy(sample: bytes) -> float:
    if not sample:
        return 0.0
    counts = [0] * 256
    for byte in sample:
        counts[byte] += 1
    total = len(sample)
    return -sum((c / total) * math.log2(c / total) for c in counts if c)


def identify(data: bytes, filename: str = "") -> str | None:
    ext = ""
    if "." in filename:
        ext = filename[filename.rfind("."):].lower()
    if ext in SCRIPT_EXTENSIONS:
        return SCRIPT_EXTENSIONS[ext]

    # Renamed or extensionless: fall back to content, but only for text.
    head = data[:8192]
    if b"\x00" in head[:512]:
        return None                       # binary, not a script
    for pattern, label in _CONTENT_MARKERS:
        if pattern.search(head):
            return label
    return None


def analyze_script(file_path: str, data: bytes = None, filename: str = "") -> dict:
    """
    Reports whether a file is a script dropper and what it would do.

    Returns is_script False for anything that is not a script.
    """
    result = {
        "is_script": False,
        "script_type": None,
        "findings": [],
        "codes": [],
        "urls": [],
        "entropy": 0.0,
    }

    try:
        if data is None:
            with open(file_path, "rb") as fh:
                data = fh.read(MAX_SCRIPT_BYTES)
    except OSError as e:
        logger.warning(f"Script read failed for {file_path}: {e}")
        return result

    if not data:
        return result
    data = data[:MAX_SCRIPT_BYTES]

    script_type = identify(data, filename)
    if not script_type:
        return result

    result["is_script"] = True
    result["script_type"] = script_type
    result["entropy"] = round(_shannon_entropy(data[:65536]), 2)

    findings, codes = [], []

    def record(code, description):
        if code not in codes:
            codes.append(code)
            findings.append(description)

    for code, pattern, description in _BEHAVIOUR_PATTERNS:
        if pattern.search(data):
            record(code, description)

    for code, pattern, description in _OBFUSCATION_PATTERNS:
        if pattern.search(data):
            record(code, description)

    result["urls"] = sorted({
        m.decode("utf-8", errors="replace") for m in _URL_PATTERN.findall(data)
    })[:10]

    result["findings"], result["codes"] = findings, codes
    return result
