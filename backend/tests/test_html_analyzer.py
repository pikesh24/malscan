"""
HTML attachments: smuggling and clipboard-injection lures.

An HTML attachment looks inert — no macro, no executable, often no URL at all —
which is the point. In HTML smuggling the payload travels as text inside the
page and JavaScript assembles it into a real file in the browser using the Blob
API, so nothing is fetched from the network and there is no download for a
gateway to inspect. Malscan read these as "some text": low entropy, no IOCs, no
YARA hit, verdict Clear.

The tests are built around the distinction the analyser is designed on: keyword
matching finds the obvious cases and misses obfuscated ones, so the primary
signal is decoding the embedded blob and seeing what it actually is. A page
whose base64 decodes to MZ is smuggling an executable no matter how the loader
is written.
"""

import base64

import pytest

from analysis_engine.html_analyzer import analyze_html, looks_like_html

PE = b"MZ\x90\x00\x03" + b"\x00" * 4096
ZIP = b"PK\x03\x04" + b"\x00" * 4096


def _b64(payload: bytes) -> str:
    return base64.b64encode(payload).decode()


def smuggling_page(payload=PE, obfuscated=False) -> bytes:
    """A page that assembles a file in memory and downloads it."""
    blob = _b64(payload)
    if obfuscated:
        # The loader is deliberately unrecognisable; the payload is unchanged.
        script = (
            f"var _0x=['{blob}'];"
            "var q=(function(a){return a.split('').reverse().join('')});"
            "var z=window['At'+'ob'];"
        )
    else:
        script = (
            f"var data='{blob}';"
            "var bin=atob(data);var arr=new Uint8Array(bin.length);"
            "var blob=new Blob([arr],{type:'application/octet-stream'});"
            "var url=URL.createObjectURL(blob);"
            "var a=document.createElement('a');a.href=url;a.download='invoice.exe';a.click();"
        )
    return f"<html><body><script>{script}</script></body></html>".encode()


def clickfix_page() -> bytes:
    """A fake CAPTCHA that puts a command on the clipboard and tells the user to
    run it. There is no download, so the page is the only artifact there is.

    The clipboard command is deliberately inert. An earlier version used a real
    `iwr http://...|iex` download cradle and real-time antivirus quarantined the
    file between the upload and the scan reading it back, so the end-to-end test
    failed on a permission error rather than on behaviour. Same reason the
    archive tests avoid EICAR. The structure under test — clipboard write plus
    Run-dialog instructions plus a shell command line — is unchanged.
    """
    return (
        b"<html><body><h1>Verify you are human</h1>"
        b"<p>1. Press Windows + R &nbsp; 2. Press Ctrl + V &nbsp; 3. Press Enter</p>"
        b"<script>navigator.clipboard.writeText("
        b"\"powershell -w hidden -nop -c Write-Host verified\");"
        b"</script></body></html>"
    )


def ordinary_page() -> bytes:
    """A normal marketing email body, including an inline logo."""
    logo = _b64(b"\x89PNG\r\n\x1a\n" + b"\x00" * 3000)
    return (
        b"<html><head><title>Newsletter</title></head><body>"
        b"<h1>Our September update</h1><p>Hello, here is what is new.</p>"
        b'<img src="data:image/png;base64,' + logo.encode() + b'" alt="logo">'
        b'<a href="https://example.com/read-more">Read more</a>'
        b"<script>document.querySelector('h1').classList.add('loaded');</script>"
        b"</body></html>"
    )


# ── Recognition ──────────────────────────────────────────────────────────────

def test_html_is_recognised_by_content_and_by_extension():
    assert looks_like_html(b"<!DOCTYPE html><html></html>")
    assert looks_like_html(b"anything at all", "invoice.html")
    assert not looks_like_html(b"MZ\x90\x00 binary content", "payload.exe")


def test_non_html_returns_is_html_false():
    info = analyze_html("x.exe", data=b"MZ" + b"\x00" * 500)
    assert info["is_html"] is False
    assert info["findings"] == []


# ── The primary signal: what the blob decodes to ─────────────────────────────

def test_a_smuggled_executable_is_identified_by_its_decoded_magic():
    info = analyze_html("x.html", data=smuggling_page(PE))

    assert info["smuggled_payload"] is not None
    assert "executable" in info["smuggled_payload"]
    assert "smuggled_payload" in info["codes"]


def test_a_smuggled_archive_is_identified():
    info = analyze_html("x.html", data=smuggling_page(ZIP))
    assert "ZIP" in (info["smuggled_payload"] or "")


def test_obfuscating_the_loader_does_not_hide_the_payload():
    """The whole reason decoding beats keyword matching: split variables, XOR and
    reversed strings change the loader, never what the payload decodes to."""
    info = analyze_html("x.html", data=smuggling_page(PE, obfuscated=True))

    assert info["smuggled_payload"] is not None, (
        "an obfuscated loader hid a payload that still decodes to MZ"
    )


# ── Corroborating behaviour ──────────────────────────────────────────────────

def test_blob_assembly_and_forced_download_are_reported():
    codes = analyze_html("x.html", data=smuggling_page())["codes"]

    for expected in ("blob_construction", "object_url", "forced_download", "synthetic_click"):
        assert expected in codes, f"{expected} not detected"


def test_integer_array_payloads_are_caught():
    body = "[" + ",".join(["77"] * 500) + "]"
    info = analyze_html("x.html", data=f"<html><script>var p={body};</script></html>".encode())
    assert "int_array_payload" in info["codes"]


# ── ClickFix / clipboard injection ───────────────────────────────────────────

def test_clipboard_injection_lure_is_detected():
    info = analyze_html("x.html", data=clickfix_page())
    codes = info["codes"]

    assert "clipboard_write" in codes
    assert "run_dialog_lure" in codes
    assert "shell_command_text" in codes


# ── False positives ──────────────────────────────────────────────────────────

def test_an_ordinary_page_with_an_inline_image_is_clean():
    """The one legitimate reason for a large base64 run in a page."""
    info = analyze_html("x.html", data=ordinary_page())

    assert info["is_html"] is True
    assert info["findings"] == [], f"ordinary newsletter flagged: {info['findings']}"


def test_a_plain_text_page_is_clean():
    info = analyze_html("x.html", data=b"<html><body><p>Just a note.</p></body></html>")
    assert info["findings"] == []


def test_a_page_using_ordinary_javascript_is_clean():
    page = (
        b"<html><body><script>"
        b"document.addEventListener('DOMContentLoaded',function(){"
        b"var el=document.getElementById('x');if(el){el.textContent='ready';}});"
        b"</script></body></html>"
    )
    assert analyze_html("x.html", data=page)["findings"] == []


def test_a_small_base64_string_is_not_a_payload():
    """Short encoded values are routine — tracking pixels, tokens, sprites."""
    small = _b64(b"MZ" + b"\x00" * 40)
    page = f"<html><script>var t='{small}';</script></html>".encode()
    assert analyze_html("x.html", data=page)["smuggled_payload"] is None


# ── Robustness ───────────────────────────────────────────────────────────────

@pytest.mark.parametrize("data,label", [
    (b"", "empty"),
    (b"<html>" + b"A" * 5000 + b"</html>", "long non-base64 run"),
    (b"<html><script>var x='" + b"!" * 4000 + b"';</script></html>", "invalid base64 alphabet"),
], ids=["empty", "long-text", "invalid-b64"])
def test_malformed_input_is_survivable(data, label):
    info = analyze_html("x.html", data=data)
    assert isinstance(info, dict), label


# ── End to end: the finding has to reach a verdict ───────────────────────────

def _scan(client, payload: bytes, filename: str) -> dict:
    import io

    res = client.post("/upload",
                      files={"file": (filename, io.BytesIO(payload), "application/octet-stream")})
    assert res.status_code == 200, res.text
    status = client.get(f"/status/{res.json()['job_id']}").json()
    assert status["status"] == "Completed"
    return status["results"]


def _html_points(results: dict) -> int:
    for entry in results.get("score_breakdown") or []:
        if entry["label"] == "HTML Attachment":
            return entry["points"]
    return 0


def test_a_smuggling_page_scores(client):
    results = _scan(client, smuggling_page(PE), "invoice.html")

    assert _html_points(results) > 0, "an HTML smuggling page scored nothing"
    assert results["verdict"] in ("Suspicious", "Malicious")


def test_a_clickfix_page_scores(client):
    results = _scan(client, clickfix_page(), "verify.html")
    assert _html_points(results) > 0


def test_a_smuggling_page_inside_a_zip_is_still_analysed(client):
    """Zipping the attachment is the ordinary way past a gateway that only
    inspects HTML."""
    import io
    import zipfile

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("invoice.html", smuggling_page(PE))
    results = _scan(client, buf.getvalue(), "delivery.zip")

    assert _html_points(results) > 0, "a smuggling page inside a ZIP lost its analysis"


def test_an_ordinary_newsletter_does_not_score(client):
    results = _scan(client, ordinary_page(), "newsletter.html")
    assert _html_points(results) == 0


def test_a_huge_file_is_bounded():
    """Regex over an unbounded attachment is its own denial of service."""
    from analysis_engine.html_analyzer import MAX_HTML_BYTES

    info = analyze_html("x.html", data=b"<html>" + b"A" * (MAX_HTML_BYTES + 100_000))
    assert isinstance(info, dict)
