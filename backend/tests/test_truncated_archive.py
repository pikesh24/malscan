"""
An archive we stopped unpacking part-way must never be reported Clear.

The walker stops at MAX_ZIP_FILE_COUNT members or MAX_DECOMPRESSED_BYTES, which
is correct — that is the decompression-bomb guard doing its job. What it also
means is that every member after the cutoff was never extracted, never hashed,
never YARA-scanned and never checked against MalwareBazaar. Member order comes
from the central directory, i.e. whoever built the archive chooses it, so the
padding-then-payload layout is free to construct.

The truncation was recorded on the accumulator and attached to the *output* of
calculate_score thirty lines after the verdict had already been decided, so it
could not influence it. A caveat did appear in the report body, but the verdict
was Clear, the score 0, `partial` false — and on the mobile share-sheet flow a
Clear verdict is what enables the OPEN FILE button.

The sibling guard for encrypted archives already exists in
test_encrypted_archive.py::test_encrypted_archive_is_never_reported_clear.
The existing bomb tests in test_archive_attacks.py assert only that extraction
stopped; neither asserts a verdict.
"""
import io
import zipfile

from attribution_module.scoring import calculate_score


def _truncated_archive_analysis(reason="file limit reached (500 files)"):
    """The shape main.py hands the scorer for a part-unpacked archive."""
    return {
        "file_hash": "a" * 64,
        "archive_hashes": [],
        "archive_truncated": reason,
        "static": {"suspicious_sections": [], "pe_sections": []},
    }


def test_a_part_unpacked_archive_is_not_clear():
    result = calculate_score(_truncated_archive_analysis())

    assert result["verdict"] == "Inconclusive", (
        f"a truncated archive reported {result['verdict']} at {result['score']} — "
        f"the members past the cutoff were never looked at"
    )
    assert result["inconclusive_reason"], "no reason given for the Inconclusive verdict"
    assert "500" in result["inconclusive_reason"] or "limit" in result["inconclusive_reason"].lower()


def test_truncation_does_not_downgrade_a_real_detection():
    """Inconclusive replaces a would-be Clear. It must never mask a finding."""
    data = _truncated_archive_analysis()
    data["script"] = {
        "is_script": True,
        "script_type": "VBScript",
        "codes": ["wsh_shell", "adodb_stream", "http_request"],
        "findings": ["downloads and writes to disk"],
    }
    result = calculate_score(data)

    assert result["verdict"] in ("Suspicious", "Malicious"), (
        f"a truncated archive containing a dropper was downgraded to "
        f"{result['verdict']}"
    )


def test_an_untruncated_archive_is_still_clear():
    """The guard must not make every archive Inconclusive."""
    result = calculate_score({
        "file_hash": "b" * 64,
        "archive_hashes": [],
        "archive_truncated": None,
        "static": {"suspicious_sections": [], "pe_sections": []},
    })
    assert result["verdict"] == "Clear", (
        f"an ordinary archive became {result['verdict']}"
    )


def test_a_padded_archive_is_not_clear_end_to_end(client):
    """Through the real pipeline: 600 tiny members trip the 500-file cap."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for i in range(600):
            zf.writestr(f"pad/{i:04d}.txt", f"padding {i}\n")
    payload = buf.getvalue()

    res = client.post("/upload", files={"file": ("padded.zip", io.BytesIO(payload), "application/zip")})
    assert res.status_code == 200, res.text
    status = client.get(f"/status/{res.json()['job_id']}").json()
    assert status["status"] == "Completed"
    results = status["results"]

    assert results.get("archive_truncated"), "the walker did not report truncation"
    assert results["verdict"] != "Clear", (
        f"a part-unpacked archive reported Clear with score {results['score']}"
    )
