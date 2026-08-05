"""
analysis_engine/lnk_analyzer.py
Windows shortcut (.LNK) analysis.

Why this exists
---------------
A .lnk is not a document, it is a stored command line. That makes it a favourite
delivery and persistence artifact: it arrives looking like a PDF or an invoice,
and running it executes whatever the shortcut says. It is a primary ClickFix
persistence mechanism (dropped into the Startup folder) and a standard payload
inside ISO and ZIP deliveries, precisely because the container hides it from the
mark-of-the-web warning that would otherwise appear.

Before this, a .lnk reached Malscan and nothing looked at it. Entropy and string
scanning ran over the raw bytes, which is close to useless here: the interesting
part is UTF-16 and short, so a shortcut running an encoded PowerShell payload
looked like an unremarkable small binary.

What it reads
-------------
The Shell Link Binary File Format (MS-SHLLINK): a fixed 76-byte header, then
optional structures whose presence is announced by LinkFlags, then a run of
length-prefixed strings. The command line lives in one of those strings, so it
can be read exactly rather than guessed at — no heuristics, no regex over
binary.

Every offset here is attacker-controlled, so every read is bounds-checked and
the parser returns what it managed rather than raising.
"""

import logging

import re
import struct

logger = logging.getLogger(__name__)

# HeaderSize (0x4C) followed by the Shell Link CLSID. Both fixed by the spec, so
# together they are a reliable signature — the extension is not.
LNK_HEADER_SIZE = 0x0000004C
LNK_CLSID = b"\x01\x14\x02\x00\x00\x00\x00\x00\xC0\x00\x00\x00\x00\x00\x00\x46"

# LinkFlags bits used here (MS-SHLLINK 2.1).
_HAS_TARGET_IDLIST = 0x00000001
_HAS_LINK_INFO     = 0x00000002
_HAS_NAME          = 0x00000004
_HAS_RELATIVE_PATH = 0x00000008
_HAS_WORKING_DIR   = 0x00000010
_HAS_ARGUMENTS     = 0x00000020
_HAS_ICON_LOCATION = 0x00000040
_IS_UNICODE        = 0x00000080

# ShowCommand values; anything else (notably 7 = minimised-no-activate) means the
# window is being kept off the screen.
_SW_SHOWNORMAL = 1
_SW_SHOWMAXIMIZED = 3
_SW_SHOWMINNOACTIVE = 7

# Interpreters a shortcut has no ordinary reason to launch. A genuine shortcut
# points at an application; these point at something that will run whatever the
# arguments say.
_INTERPRETERS = (
    "powershell", "pwsh", "cmd.exe", "wscript", "cscript", "mshta",
    "rundll32", "regsvr32", "msiexec", "installutil", "curl", "certutil",
    "bitsadmin", "wmic", "forfiles", "conhost", "explorer.exe",
)

# Argument patterns worth naming individually, with why they matter.
# (code, pattern, description). The code is what scoring keys on — matching on
# display text would break the moment the wording is improved.
_ARGUMENT_PATTERNS = [
    ("encoded_command",
     re.compile(r"-e(nc|ncoded|ncodedcommand)?\s+[A-Za-z0-9+/=]{40,}", re.I),
     "PowerShell encoded command — the payload is base64 inside the shortcut"),
    ("base64_decode",
     re.compile(r"frombase64string", re.I),
     "Base64 decoding in the command line"),
    ("hidden_execution",
     re.compile(r"-w(indowstyle)?\s+hidden|-nop\b|-noprofile|-noni|-noninteractive", re.I),
     "PowerShell run hidden or without profile — hides the window from the user"),
    ("download_cradle",
     re.compile(r"downloadstring|downloadfile|invoke-webrequest|\biwr\b|\bcurl\b|bitsadmin", re.I),
     "Downloads content at run time — a dropper stage"),
    ("invoke_expression",
     re.compile(r"iex\b|invoke-expression", re.I),
     "Invoke-Expression — executes downloaded text as code"),
    ("certutil_abuse",
     re.compile(r"certutil.{0,40}-(decode|urlcache)", re.I),
     "certutil used to decode or fetch a payload"),
    ("mshta_remote",
     re.compile(r"mshta\s+(https?|javascript:)", re.I),
     "MSHTA executing remote or inline script"),
    ("rundll32_script",
     re.compile(r"rundll32.{0,60}(javascript:|\.dll\s*,)", re.I),
     "rundll32 executing script or an exported function"),
    ("contains_url",
     re.compile(r"https?://", re.I),
     "Command line contains a URL"),
    ("unc_path",
     re.compile(r"\\\\[A-Za-z0-9._-]+\\", re.I),
     "Command line references a UNC network path"),
    ("user_writable_dir",
     re.compile(r"(appdata|programdata|\\temp\\|%temp%|public\\)", re.I),
     "Runs something from a user-writable directory"),
]

# A real shortcut's arguments are short. Padding with whitespace to push the
# command out of the Windows properties dialog is an old but still-used trick.
_LONG_ARGUMENTS = 400
_SUSPICIOUS_WHITESPACE_RUN = re.compile(r"\s{20,}")


def _read_u16(buf: bytes, off: int):
    if off + 2 > len(buf):
        return None
    return struct.unpack_from("<H", buf, off)[0]


def _read_u32(buf: bytes, off: int):
    if off + 4 > len(buf):
        return None
    return struct.unpack_from("<I", buf, off)[0]


def _read_string_data(buf: bytes, off: int, unicode_strings: bool):
    """One StringData entry: a character count, then that many characters.

    Returns (text, next_offset), or (None, off) if it does not fit — a truncated
    or lying length must end parsing, not raise.
    """
    count = _read_u16(buf, off)
    if count is None:
        return None, off
    off += 2
    width = 2 if unicode_strings else 1
    size = count * width
    if size < 0 or off + size > len(buf):
        return None, off
    raw = buf[off:off + size]
    try:
        text = raw.decode("utf-16-le" if unicode_strings else "latin-1", errors="replace")
    except Exception:
        text = ""
    return text, off + size


def _local_base_path(buf: bytes, off: int, info_size: int):
    """Best-effort target path out of the LinkInfo structure.

    Optional by design: the shortcut's arguments carry the payload, and LinkInfo
    is the most variable part of the format. A failure here must not cost the
    rest of the analysis.
    """
    try:
        header_size = _read_u32(buf, off + 4)
        flags = _read_u32(buf, off + 8)
        if header_size is None or flags is None or not flags & 0x1:
            return ""
        base_off = _read_u32(buf, off + 16)
        if not base_off or off + base_off >= len(buf):
            return ""
        end = buf.find(b"\x00", off + base_off, off + info_size)
        if end == -1:
            return ""
        return buf[off + base_off:end].decode("latin-1", errors="replace")
    except Exception:
        return ""


def is_lnk(data: bytes) -> bool:
    if len(data) < 20:
        return False
    return (
        struct.unpack_from("<I", data, 0)[0] == LNK_HEADER_SIZE
        and data[4:20] == LNK_CLSID
    )


def analyze_lnk(file_path: str, data: bytes = None) -> dict:
    """
    Parses a Windows shortcut and reports what it would run.

    Returns is_lnk False for anything else, so callers can hand it any file.
    """
    result = {
        "is_lnk": False,
        "target": "",
        "arguments": "",
        "working_dir": "",
        "icon_location": "",
        "relative_path": "",
        "hidden_window": False,
        "suspicious": [],
        "codes": [],
    }

    try:
        if data is None:
            with open(file_path, "rb") as fh:
                data = fh.read(1024 * 1024)
    except OSError as e:
        logger.warning(f"LNK read failed for {file_path}: {e}")
        return result

    if not data or not is_lnk(data):
        return result
    result["is_lnk"] = True

    flags = _read_u32(data, 20) or 0
    show_command = _read_u32(data, 60) or _SW_SHOWNORMAL
    unicode_strings = bool(flags & _IS_UNICODE)
    off = 76

    if flags & _HAS_TARGET_IDLIST:
        size = _read_u16(data, off)
        if size is None:
            return result
        off += 2 + size

    if flags & _HAS_LINK_INFO:
        info_size = _read_u32(data, off)
        if info_size is None or info_size <= 0:
            return result
        result["target"] = _local_base_path(data, off, info_size)
        off += info_size

    # StringData, in the fixed order the spec defines.
    for bit, key in (
        (_HAS_NAME, None),
        (_HAS_RELATIVE_PATH, "relative_path"),
        (_HAS_WORKING_DIR, "working_dir"),
        (_HAS_ARGUMENTS, "arguments"),
        (_HAS_ICON_LOCATION, "icon_location"),
    ):
        if not flags & bit:
            continue
        text, off = _read_string_data(data, off, unicode_strings)
        if text is None:
            break
        if key:
            result[key] = text

    result["hidden_window"] = show_command not in (_SW_SHOWNORMAL, _SW_SHOWMAXIMIZED)
    result["suspicious"], result["codes"] = _assess(result)
    return result


def _assess(info: dict):
    """What is worth telling the user about this shortcut.

    Returns (descriptions, codes). Descriptions are for the report; codes are
    what scoring weights, so the wording can be improved without silently
    changing anyone's score.
    """
    findings, codes = [], []

    def record(code, description):
        codes.append(code)
        findings.append(description)

    args = info.get("arguments") or ""
    target = (info.get("target") or "") + " " + (info.get("relative_path") or "")
    haystack = f"{target} {args}"

    hit = next((name for name in _INTERPRETERS if name in target.lower()), None)
    if hit:
        record("interpreter_target",
               f"Shortcut launches a command interpreter ({hit}) rather than an application")

    for code, pattern, description in _ARGUMENT_PATTERNS:
        if pattern.search(haystack):
            record(code, description)

    if len(args) > _LONG_ARGUMENTS:
        record("long_command_line",
               f"Unusually long command line ({len(args)} characters) — ordinary shortcuts are short")
    if _SUSPICIOUS_WHITESPACE_RUN.search(args):
        record("whitespace_padding",
               "Long run of whitespace in the command line — pads the real command out of view "
               "in the shortcut's properties dialog")
    if info.get("hidden_window") and (hit or args):
        record("hidden_window", "Shortcut is configured to run without showing a window")

    # An icon borrowed from a document viewer while the target is an interpreter
    # is the whole disguise, in one line.
    icon = (info.get("icon_location") or "").lower()
    if hit and any(word in icon for word in ("shell32", "imageres", "acrobat", "wordpad", "notepad", ".pdf", ".doc")):
        record("document_icon_disguise",
               "Shortcut wears a document icon while launching an interpreter")

    return findings, codes
