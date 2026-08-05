"""
The extension/content mismatch check must use the SUBMITTED filename.

Found by running the real pipeline rather than the unit tests. A PE renamed to
`photo.jpg` scored 8 — entropy only — when it should have scored 38. The
"deliberate disguise" branch is worth +30 and had never fired in production for
a single uploaded file.

The cause was a path/name confusion that unit tests could not see. Uploads are
stored in the vault as `<sha256>` with **no extension**, and `detect_file_type`
read the extension from that stored path. `os.path.splitext()` therefore always
returned `""`, which is in no extension set, so `type_mismatch` was permanently
False. Calling the analyser directly with `photo.jpg` — which is what every unit
test did — worked fine, so nothing caught it.

Renaming an executable to an image is about the cheapest evasion there is, which
is what makes a silently dead check here expensive.
"""

import io

import pytest

# A PE header plus filler. Distinct bytes per test where it matters: identical
# content submitted twice within the debounce window replays the first result,
# which silently invalidated an earlier version of these assertions.
PE_BASE = b"MZ\x90\x00\x03" + b"\x00" * 60 + b"This program cannot be run in DOS mode.\r\n"


def _pe(salt: int) -> bytes:
    return PE_BASE + bytes([salt]) + b"A" * 512


def _scan(client, payload: bytes, filename: str) -> dict:
    res = client.post("/upload",
                      files={"file": (filename, io.BytesIO(payload), "application/octet-stream")})
    assert res.status_code == 200, res.text
    status = client.get(f"/status/{res.json()['job_id']}").json()
    assert status["status"] == "Completed"
    return status["results"]


def _disguise_flagged(results: dict) -> bool:
    return any("mismatch" in r.lower() for r in results.get("reasons") or [])


@pytest.mark.parametrize("filename", ["photo.jpg", "scan.jpeg", "image.png",
                                      "report.txt", "invoice.pdf", "data.csv"])
def test_an_executable_wearing_an_innocent_extension_is_flagged(client, filename, request):
    salt = abs(hash(filename)) % 250
    results = _scan(client, _pe(salt), filename)

    assert _disguise_flagged(results), (
        f"a PE named {filename} was not reported as a disguise"
    )


@pytest.mark.parametrize("filename", ["setup.exe", "library.dll", "noextension"])
def test_an_honestly_named_executable_is_not_flagged(client, filename):
    salt = abs(hash(filename)) % 250
    results = _scan(client, _pe(salt), filename)

    assert not _disguise_flagged(results), (
        f"{filename} is named honestly and must not be called a disguise"
    )


def test_the_disguise_is_worth_more_than_entropy_alone(client):
    """Pins the actual regression: the check contributes points, not just words."""
    disguised = _scan(client, _pe(1), "holiday-photo.jpg")
    honest = _scan(client, _pe(2), "installer.exe")

    assert disguised["score"] > honest["score"], (
        "disguising an executable did not change the score at all — the mismatch "
        "branch is dead again"
    )


def test_a_real_image_is_not_flagged(client):
    """The overcorrection guard: a genuine PNG named .png is not a mismatch."""
    png = b"\x89PNG\r\n\x1a\n" + b"\x00" * 2048
    results = _scan(client, png, "logo.png")

    assert not _disguise_flagged(results)


def test_a_text_file_named_exe_is_not_a_pe(client):
    """The reverse direction: claiming to be an executable without being one is
    not the same finding, and must not be reported as a disguised PE."""
    results = _scan(client, b"just plain text, honestly\n" * 20, "totally-a-program.exe")

    assert not results.get("is_pe")
