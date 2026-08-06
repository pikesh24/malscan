"""
Submitting a file must not silently publish it to a third party.

When VirusTotal does not recognise a hash, the pipeline uploads the file so the
scan can get a verdict at all. That is the right trade for a suspicious
attachment and the wrong one for a private document: anything uploaded enters
VirusTotal's corpus, where paying subscribers can download it. There was no way
to decline. The only control was unsetting VT_API_KEY, which disables
reputation for every scan on the deployment.

`allow_vt_upload=false` keeps the lookup to the hash. The cost — no reputation
verdict for an unknown file — is stated in the report rather than absorbed
silently, because "we did not check" must not read as "nothing is wrong".
"""
import io

import pytest

from analysis_engine import vt_client
from attribution_module.scoring import calculate_score


class _Resp:
    status_code = 404

    @staticmethod
    def json():
        return {}


def test_declining_prevents_the_upload(monkeypatch):
    uploaded = []
    monkeypatch.setattr(vt_client, "_get_with_rate_limit_retry", lambda *a, **k: _Resp())
    monkeypatch.setattr(vt_client, "upload_file",
                        lambda path, key: uploaded.append(path) or {"stats": {}})

    result = vt_client.get_file_report("a" * 64, "test-key", __file__, allow_upload=False)

    assert uploaded == [], "the file was uploaded despite the submitter declining"
    assert result["vt_status"] == "not_found"
    assert result["upload_declined"] is True


def test_allowing_still_uploads_an_unknown_file(monkeypatch):
    """The default path has to keep working — this is how unknown files get a verdict."""
    uploaded = []
    monkeypatch.setattr(vt_client, "_get_with_rate_limit_retry", lambda *a, **k: _Resp())
    monkeypatch.setattr(vt_client, "upload_file",
                        lambda path, key: uploaded.append(path) or {"stats": {}, "uploaded": True})

    vt_client.get_file_report("b" * 64, "test-key", __file__, allow_upload=True)

    assert uploaded, "an unknown hash was not uploaded when uploading was permitted"


def test_the_report_says_reputation_was_skipped():
    result = calculate_score({
        "file_hash": "c" * 64,
        "vt_upload_declined": True,
        "static": {"suspicious_sections": [], "pe_sections": []},
    })
    assert any("hash lookup only" in r for r in result["reasons"]), (
        f"the report does not disclose that reputation was skipped: {result['reasons']}"
    )


def test_the_endpoint_accepts_the_flag(client, monkeypatch):
    """End to end: the form field reaches the scan job."""
    seen = {}
    real = __import__("app.main", fromlist=["main"]).process_scan_job

    def _capture(job_id, file_path, original_filename="unknown", submitted_url=None,
                 allow_vt_upload=True):
        seen["allow_vt_upload"] = allow_vt_upload
        return real(job_id, file_path, original_filename, submitted_url, allow_vt_upload)

    monkeypatch.setattr("app.main.process_scan_job", _capture)

    res = client.post(
        "/upload",
        files={"file": ("private.txt", io.BytesIO(b"a private document\n"), "text/plain")},
        data={"allow_vt_upload": "false"},
    )
    assert res.status_code == 200, res.text
    assert seen.get("allow_vt_upload") is False, (
        "the endpoint ignored allow_vt_upload and would have uploaded the file"
    )


def test_uploading_is_the_default(client, monkeypatch):
    seen = {}
    real = __import__("app.main", fromlist=["main"]).process_scan_job

    def _capture(job_id, file_path, original_filename="unknown", submitted_url=None,
                 allow_vt_upload=True):
        seen["allow_vt_upload"] = allow_vt_upload
        return real(job_id, file_path, original_filename, submitted_url, allow_vt_upload)

    monkeypatch.setattr("app.main.process_scan_job", _capture)

    res = client.post("/upload", files={"file": ("x.txt", io.BytesIO(b"ordinary\n"), "text/plain")})
    assert res.status_code == 200
    assert seen.get("allow_vt_upload") is True
