"""
A deployment with no VirusTotal key must say so.

`render.yaml` documents the enrichment keys as optional and set by hand, so a
key-less deployment is a supported state — and it used to be the one kind of
missing intel that left no trace at all. The partial check read
`key in futures and _intel_incomplete(...)`, and with no key the lookup was
never scheduled, so `key in futures` was False and the scan counted as complete.
Every verdict came back Clear on the strength of a source nobody had consulted.

The fix discloses rather than downgrades. A key-less deployment still runs YARA,
static analysis and every format analyser; calling all of that Inconclusive
would train users to ignore the verdict, which is worse than a verdict clearly
labelled as reached without reputation data. Two flags, because the remedies
differ:

    partial                  we tried and got nothing — a retry may help
    reputation_unavailable   no key configured — a retry can never help

That distinction is load-bearing: `_find_recent_duplicate` refuses to reuse a
`partial` result, so conflating the two made every scan re-run the pipeline.
"""
import io

import pytest

from attribution_module.scoring import calculate_score


def _benign(**extra):
    data = {
        "file_hash": "c" * 64,
        "archive_hashes": [],
        "static": {"suspicious_sections": [], "pe_sections": []},
    }
    data.update(extra)
    return data


def test_missing_key_is_disclosed_in_the_report():
    result = calculate_score(_benign(intel_unconfigured=True))

    assert result["reputation_unavailable"] is True
    assert any("no VirusTotal key" in r or "reputation data" in r.lower()
               for r in result["reasons"]), (
        f"nothing in the report says reputation was never consulted: {result['reasons']}"
    )


def test_missing_key_does_not_block_the_debounce():
    """`partial` gates duplicate reuse, so it must stay about retry-ability."""
    result = calculate_score(_benign(intel_unconfigured=True))
    assert result["partial"] is False, (
        "an unconfigured key marked the scan partial, which stops _find_recent_duplicate "
        "reusing it — every resubmission would re-run the whole pipeline"
    )


def test_a_failed_lookup_is_still_partial_and_inconclusive():
    """The configured-but-failed path must keep its stricter treatment."""
    result = calculate_score(_benign(intel_partial=True))
    assert result["partial"] is True
    assert result["verdict"] == "Inconclusive"


def test_a_configured_deployment_says_nothing_about_missing_reputation():
    result = calculate_score(_benign())
    assert result["reputation_unavailable"] is False
    assert not any("no VirusTotal key" in r for r in result["reasons"])


def test_a_specific_cause_outranks_the_generic_intel_reason():
    """A password-protected archive must say so, even when VT also failed.

    Both branches gated on `verdict == "Clear"`, and the intel branch ran first
    and set it to Inconclusive — so the more useful, more actionable reason could
    never replace the generic one. "Supply the password" tells the reader what to
    do; "VirusTotal was unavailable" does not.
    """
    result = calculate_score(_benign(
        intel_partial=True,
        unexaminable=["secret.docx", "payload.exe"],
    ))

    assert result["verdict"] == "Inconclusive"
    assert "password" in (result["inconclusive_reason"] or "").lower(), (
        f"the generic intel reason buried the specific one: {result['inconclusive_reason']}"
    )


def test_a_real_detection_is_never_relabelled(client):
    """Refining an Inconclusive must not reach up and touch a real finding."""
    result = calculate_score(_benign(
        intel_partial=True,
        unexaminable=["x.bin"],
        script={
            "is_script": True, "script_type": "VBScript",
            "codes": ["wsh_shell", "adodb_stream", "http_request"],
            "findings": ["downloads and writes to disk"],
        },
    ))
    assert result["verdict"] in ("Suspicious", "Malicious")
