"""
An ordinary photo or screenshot must not read as "packed or encrypted."

Found from a real report: a phone screenshot (a plain JPEG) scored 23 —
File Structure Analysis, entropy 7.929 flagged "appears to be packed or
encrypted" (+15), plus a "Large base64 blob — possible encoded payload" hit
(+8) from EXIF/XMP metadata a screenshot tool had embedded. Both are
inherent to what a JPEG *is*: DCT + Huffman-coded compressed image data
reads as high-entropy by construction, exactly like a ZIP or a GZIP stream
— formats `_NATURALLY_COMPRESSED` already exempts for the identical reason.
JPEG and PNG were simply never added to that set, so every photo anyone
scans paid a real, meaningless entropy penalty.

The risk is not hypothetical: `min(score, 60)` allows this one check alone
to climb well past the 23 seen here if a photo happens to also match a
couple of the other suspicious-string patterns, and it stacks with whatever
else a scan finds — a real path from "an ordinary photo" to "Suspicious."
"""
from attribution_module.scoring import _check_enhanced_static


def _jpeg_like(entropy: float, base64_blob: bool):
    """The static-analysis shape a real JPEG produces — not the file bytes
    themselves, which _check_enhanced_static never reads directly."""
    return {
        "magic_type": "JPEG Image",
        "file_entropy": entropy,
        "extension": ".jpg",
        "type_mismatch": False,
        "suspicious_strings": (["Large base64 blob — possible encoded payload"]
                               if base64_blob else []),
    }


def test_an_ordinary_jpeg_is_not_flagged_as_packed():
    # The exact entropy from the real screenshot that prompted this.
    score, reasons = _check_enhanced_static(_jpeg_like(7.929, base64_blob=True))

    assert score == 0, f"an ordinary JPEG scored {score}: {reasons}"
    assert not reasons, f"an ordinary JPEG produced findings: {reasons}"


def test_a_png_gets_the_same_exemption():
    data = _jpeg_like(7.6, base64_blob=False)
    data["magic_type"] = "PNG Image"
    score, reasons = _check_enhanced_static(data)
    assert score == 0, f"an ordinary PNG scored {score}: {reasons}"


def test_the_exemption_does_not_hide_a_real_type_mismatch():
    """The fix must be scoped to entropy/base64 only — a PE disguised as a
    .jpg is a real finding and must still score, regardless of magic type."""
    data = _jpeg_like(7.929, base64_blob=True)
    data["type_mismatch"] = True
    data["extension"] = ".jpg"
    data["magic_type"] = "Windows Executable (PE/EXE/DLL)"
    score, reasons = _check_enhanced_static(data)
    assert score >= 30, f"a disguised executable was not flagged: {score} {reasons}"


def test_a_genuinely_high_entropy_non_image_file_is_still_flagged():
    """The guard is scoped to known-compressed magic types, not a blanket
    entropy exemption — an unrecognised high-entropy binary is still worth
    a look."""
    score, reasons = _check_enhanced_static({
        "magic_type": "Unknown",
        "file_entropy": 7.9,
        "extension": ".bin",
        "type_mismatch": False,
        "suspicious_strings": [],
    })
    assert score > 0, "a high-entropy unrecognised file was silently cleared"
