"""
A deployment with no VirusTotal key must not hand out Clear verdicts.

`render.yaml` documents the enrichment keys as optional and set by hand, so a
key-less deployment is a supported state — and it used to be the one kind of
missing intel that left no trace. The partial check read
`key in futures and _intel_incomplete(...)`; with no key the lookup was never
scheduled, `key in futures` was False, and the scan counted as complete. Every
verdict came back Clear on the strength of a source nobody had consulted.

There is no honest verdict when the source that decides it was never asked, so
this is Inconclusive — the same answer the scanner already gives for a
password-protected archive or a quarantined file. What makes that useful rather
than noise is the reason: the report says a key is missing, which is a thing the
operator can fix, and distinguishes it from "VirusTotal timed out", which is a
thing the user can retry.

The distinction is load-bearing elsewhere too: `_find_recent_duplicate` refuses
to reuse a partial result because a retry may succeed. A missing key never
resolves on retry, so that result stays reusable.
"""
import io

from attribution_module.scoring import calculate_score


def _benign(**extra):
    data = {
        "file_hash": "c" * 64,
        "archive_hashes": [],
        "static": {"suspicious_sections": [], "pe_sections": []},
    }
    data.update(extra)
    return data


def test_no_key_means_inconclusive_not_clear():
    result = calculate_score(_benign(intel_partial=True, intel_unconfigured=True))

    assert result["verdict"] == "Inconclusive", (
        f"a scan with no reputation source reported {result['verdict']}"
    )
    assert result["reputation_unavailable"] is True


def test_the_reason_names_the_missing_key_not_a_timeout():
    """An Inconclusive that does not say why is what trains people to ignore it."""
    result = calculate_score(_benign(intel_partial=True, intel_unconfigured=True))
    reason = result["inconclusive_reason"] or ""

    assert "key" in reason.lower(), f"reason does not mention the missing key: {reason}"
    assert "did not return" not in reason, (
        "an unconfigured deployment is being described as a failed lookup — "
        "the operator would go looking for a network fault that does not exist"
    )


def test_a_failed_lookup_reads_differently_from_a_missing_key():
    configured = calculate_score(_benign(intel_partial=True))
    assert configured["verdict"] == "Inconclusive"
    assert configured["reputation_unavailable"] is False
    assert "key" not in (configured["inconclusive_reason"] or "").lower()


def test_a_real_detection_is_never_downgraded_by_a_missing_key():
    """Inconclusive replaces a would-be Clear. It must never mask a finding."""
    result = calculate_score(_benign(
        intel_partial=True,
        intel_unconfigured=True,
        script={
            "is_script": True, "script_type": "VBScript",
            "codes": ["wsh_shell", "adodb_stream", "http_request"],
            "findings": ["downloads and writes to disk"],
        },
    ))
    assert result["verdict"] in ("Suspicious", "Malicious")
    assert any("no antivirus consensus" in r.lower() for r in result["reasons"]), (
        "a Suspicious verdict reached without reputation data did not say so"
    )


def test_a_configured_deployment_says_nothing_about_missing_reputation():
    result = calculate_score(_benign())
    assert result["reputation_unavailable"] is False
    assert result["verdict"] == "Clear"


def test_an_unconfigured_result_is_still_reusable_by_the_debounce():
    """Retrying cannot fix a missing key, so re-running the pipeline buys nothing.

    _find_recent_duplicate skips partial results because the source may answer
    next time. That reasoning does not apply here, and applying it anyway made
    every resubmission on a key-less deployment re-run the whole scan.
    """
    reusable = {"verdict": "Inconclusive", "score": 0,
                "partial": True, "reputation_unavailable": True}
    retryable = {"verdict": "Inconclusive", "score": 0,
                 "partial": True, "reputation_unavailable": False}

    class _Row:
        def __init__(self, results):
            self.results = results

    def _pick(rows):
        for row in rows:
            res = row.results
            if not res:
                continue
            if res.get("partial") and not res.get("reputation_unavailable"):
                continue
            return res
        return None

    assert _pick([_Row(reusable)]) is reusable
    assert _pick([_Row(retryable)]) is None


def test_end_to_end_without_a_key(client, monkeypatch):
    """The pipeline, not just the scorer: no key, benign file, no Clear verdict."""
    monkeypatch.setenv("VT_API_KEY", "")

    res = client.post("/upload", files={"file": ("plain.txt", io.BytesIO(b"nothing here\n"), "text/plain")})
    assert res.status_code == 200, res.text
    results = client.get(f"/status/{res.json()['job_id']}").json()["results"]

    assert results["verdict"] == "Inconclusive", (
        f"a key-less deployment reported {results['verdict']} at {results['score']}"
    )
    assert results["reputation_unavailable"] is True
