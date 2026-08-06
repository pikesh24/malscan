"""
analysis_engine/vt_client.py
VirusTotal v3 API client for URL and file threat intelligence.
Supports hash lookups and automatic file upload for unknown samples.
"""

import base64
import os
import requests
import time
import logging

logger = logging.getLogger(__name__)

# ── Rate-limit retry ──────────────────────────────────────────────────────────
# VT's public tier allows 4 requests/MINUTE (240/hour, 500/day). The per-minute
# burst is the binding limit by far — a 429 here almost always means "you asked
# again too quickly", not "you are out of quota", and it clears within the
# minute. That distinction matters: without a retry, one burst 429 marks the
# whole scan 'partial' (VirusTotal is the verdict-critical source), which now
# downgrades a clean-looking result to Inconclusive. A short backoff converts
# most of those into complete scans.
VT_RATE_LIMIT_RETRIES = 2
VT_RATE_LIMIT_BACKOFF_SECONDS = 15


def _get_with_rate_limit_retry(endpoint: str, headers: dict, timeout: int = 15):
    """GET that retries ONLY on HTTP 429, with a fixed backoff.

    Any other status (including 404, which is meaningful to callers) returns
    immediately. Worst case adds ~30s to a scan — acceptable versus reporting a
    provisional verdict when a 15s wait would have produced a real one.
    """
    response = requests.get(endpoint, headers=headers, timeout=timeout)
    for attempt in range(VT_RATE_LIMIT_RETRIES):
        if response.status_code != 429:
            return response
        logger.warning(
            "VT rate limited (429); backing off %ss then retrying (%d/%d).",
            VT_RATE_LIMIT_BACKOFF_SECONDS, attempt + 1, VT_RATE_LIMIT_RETRIES,
        )
        time.sleep(VT_RATE_LIMIT_BACKOFF_SECONDS)
        response = requests.get(endpoint, headers=headers, timeout=timeout)
    return response


# Polling budgets. Attempts are chances for the ANALYSIS to finish; throttled
# responses are counted separately because being rate limited says nothing about
# whether the analysis is done.
VT_MAX_THROTTLED_POLLS = 3


def _poll_analysis(analysis_id: str, headers: dict, attempts: int, interval: int):
    """Polls /analyses/{id} until it completes. Returns (attrs, status).

    status is one of 'completed', 'pending' or 'rate_limited'.

    The bug this exists to fix: both poll loops treated any non-200 as "still
    analysing". A 429 is not progress — VirusTotal may well have finished and
    simply be throttling us — but each one consumed an attempt, so a scan could
    exhaust its budget while a real verdict sat waiting, then report
    vt_status 'queued'. That marks the scan partial and downgrades a perfectly
    good result to Inconclusive.

    It also wasted quota: nine polls at five-second intervals is twelve requests
    a minute against a four-per-minute ceiling, so most of them were always
    going to be throttled.
    """
    endpoint = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
    throttled = 0
    remaining = attempts
    # A while loop, not `for _ in range(attempts)`: inside a for loop a `continue`
    # still spends the iteration, so a throttled poll would go on consuming the
    # very budget this function exists to protect. Attempts are decremented only
    # by answers that actually tell us something about the analysis.
    while remaining > 0:
        time.sleep(interval)
        try:
            poll = requests.get(endpoint, headers=headers, timeout=15)
        except requests.RequestException as e:
            logger.warning(f"VT analysis poll failed, retrying: {e}")
            remaining -= 1
            continue

        if poll.status_code == 429:
            throttled += 1
            if throttled > VT_MAX_THROTTLED_POLLS:
                logger.warning(
                    "VT rate limited on %d analysis polls; reporting no verdict "
                    "rather than a clean one.", throttled,
                )
                return None, "rate_limited"
            # Wait out the window. Deliberately does NOT spend an attempt: being
            # throttled says nothing about whether the analysis has finished.
            time.sleep(VT_RATE_LIMIT_BACKOFF_SECONDS)
            continue

        if poll.status_code == 200:
            attrs = poll.json().get("data", {}).get("attributes", {})
            if attrs.get("status") == "completed":
                return attrs, "completed"

        remaining -= 1

    return None, "pending"


def _extract_detections(attrs: dict, limit: int = 10) -> list:
    """Pulls named vendor verdicts out of VT's per-engine results.

    Completed /files or /urls lookups expose this as 'last_analysis_results';
    the /analyses/{id} polling endpoint calls the same shape 'results'. Either
    way it's a dict of {engine_name: {category, result, ...}} — this keeps
    only the vendors that actually flagged something (malicious/suspicious),
    so the report can show real AV names instead of just totals.
    """
    results = attrs.get("last_analysis_results") or attrs.get("results") or {}
    detections = [
        {"vendor": name, "result": info.get("result") or info.get("category", "flagged")}
        for name, info in results.items()
        if info.get("category") in ("malicious", "suspicious")
    ]
    return detections[:limit]


def get_url_report(url: str, api_key: str) -> dict:
    """
    Queries VirusTotal for a URL report. If no report exists, submits
    the URL for scanning and polls for results.

    Returns dict with 'stats' (malicious/suspicious/harmless/undetected counts),
    'detections' (named vendor verdicts) and 'reputation' score, or an 'error'
    key on failure.
    """
    if not api_key:
        return {"error": "No VT API key provided", "vt_status": "error"}

    url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
    headers = {"x-apikey": api_key, "accept": "application/json"}

    try:
        # 1. Check if VT already has a report for this URL
        endpoint = f"https://www.virustotal.com/api/v3/urls/{url_id}"
        response = _get_with_rate_limit_retry(endpoint, headers)

        if response.status_code == 200:
            attrs = response.json().get("data", {}).get("attributes", {})
            return {
                "stats": attrs.get("last_analysis_stats", {}),
                "detections": _extract_detections(attrs),
                "reputation": attrs.get("reputation", 0),
                "vt_status": "found",
            }

        elif response.status_code == 404:
            # 2. URL not yet scanned — submit it
            submit_res = requests.post(
                "https://www.virustotal.com/api/v3/urls",
                headers=headers,
                data={"url": url},
                timeout=15,
            )
            if submit_res.status_code == 200:
                analysis_id = submit_res.json().get("data", {}).get("id")
                # Poll up to 5 times (~15 s) — enough for a fresh URL analysis to
                # finish reliably, still capped so it can't hold the pipeline.
                attrs, poll_status = _poll_analysis(analysis_id, headers, attempts=5, interval=3)
                if poll_status == "completed":
                    return {
                        "stats": attrs.get("stats", {}),
                        "detections": _extract_detections(attrs),
                        "reputation": 0,
                        "vt_status": "found",
                    }
                if poll_status == "rate_limited":
                    return {
                        "status": "rate_limited",
                        "message": "VT rate limit reached while waiting for URL analysis.",
                        "vt_status": "rate_limited",
                    }
                return {"status": "queued", "message": "VT analysis still pending.", "vt_status": "queued"}
            return {"error": f"VT submit failed (HTTP {submit_res.status_code})", "vt_status": "error"}

        elif response.status_code == 429:
            return {"error": "VT rate limit exceeded. Try again later.", "vt_status": "error"}
        else:
            return {"error": f"VT lookup failed (HTTP {response.status_code})", "vt_status": "error"}

    except requests.exceptions.Timeout:
        return {"error": "VT request timed out.", "vt_status": "error"}
    except Exception as e:
        logger.error(f"VT error: {e}")
        return {"error": str(e), "vt_status": "error"}


def upload_file(file_path: str, api_key: str) -> dict:
    """
    Uploads a file to VirusTotal for cloud detonation/scanning.
    Polls for completion up to ~45 seconds.
    Returns dict with 'stats' and metadata, or 'error' on failure.
    """
    if not api_key:
        return {"error": "No VT API key provided"}
    if not file_path:
        return {"error": "No file path provided"}

    headers = {"x-apikey": api_key}

    try:
        # Check file size — VT v3 requires /files/upload_url for files > 32MB
        file_size = os.path.getsize(file_path)
        if file_size > 32 * 1024 * 1024:
            # Get a special upload URL for large files
            large_resp = requests.get(
                "https://www.virustotal.com/api/v3/files/upload_url",
                headers={**headers, "accept": "application/json"},
                timeout=15,
            )
            if large_resp.status_code != 200:
                return {"error": f"VT large-file URL request failed (HTTP {large_resp.status_code})"}
            upload_url = large_resp.json().get("data")
        else:
            upload_url = "https://www.virustotal.com/api/v3/files"

        # Upload the file
        with open(file_path, "rb") as f:
            upload_resp = requests.post(
                upload_url,
                headers=headers,
                files={"file": (os.path.basename(file_path), f)},
                timeout=60,
            )

        if upload_resp.status_code != 200:
            return {"error": f"VT file upload failed (HTTP {upload_resp.status_code})", "vt_status": "error"}

        analysis_id = upload_resp.json().get("data", {}).get("id")
        if not analysis_id:
            return {"error": "VT upload succeeded but no analysis ID returned.", "vt_status": "error"}

        logger.info(f"File uploaded to VT, analysis ID: {analysis_id}")

        # Poll for results (up to ~45s)
        poll_headers = {**headers, "accept": "application/json"}
        attrs, poll_status = _poll_analysis(analysis_id, poll_headers, attempts=9, interval=5)
        if poll_status == "completed":
            return {
                "stats": attrs.get("stats", {}),
                "detections": _extract_detections(attrs),
                "reputation": 0,
                "uploaded": True,
                "vt_status": "found",
            }

        # Neither outcome is a clean verdict, and the pipeline marks both partial
        # so a re-scan retries instead of freezing a 0. They are reported apart
        # because they need different things from the operator: 'pending' means
        # wait, 'rate_limited' means the quota is the bottleneck.
        if poll_status == "rate_limited":
            return {
                "status": "rate_limited",
                "message": "VT rate limit reached while waiting for file analysis.",
                "uploaded": True,
                "vt_status": "rate_limited",
            }
        return {"status": "queued", "message": "VT file analysis still pending after upload.", "uploaded": True, "vt_status": "queued"}

    except requests.exceptions.Timeout:
        return {"error": "VT file upload timed out.", "vt_status": "error"}
    except Exception as e:
        logger.error(f"VT upload error: {e}")
        return {"error": str(e), "vt_status": "error"}


def get_file_report(file_hash: str, api_key: str, file_path: str = None,
                    allow_upload: bool = True) -> dict:
    """
    Queries VirusTotal for a file report by SHA-256 hash FIRST — an instant,
    authoritative answer for any file VT already knows (which is most real
    malware). Only when the hash is genuinely unknown (404) does it fall back to
    upload + poll.

    Every return carries a 'vt_status' discriminator so the pipeline can tell
    apart the three cases that must NOT be conflated:
      - 'found'     → a real verdict is present ('stats' populated); usable.
      - 'not_found' → VT definitively has no data on this file (benign-unknown);
                      not an error, but no verdict either.
      - 'queued' / 'error' → the lookup did not complete (still analysing, rate
                      limited, timed out). A timeout must never be scored as a
                      clean 0 — the pipeline marks these scans 'partial'.
    """
    if not api_key:
        return {"error": "No VT API key provided", "vt_status": "error"}
    if not file_hash:
        return {"error": "No file hash provided", "vt_status": "error"}

    headers = {"x-apikey": api_key, "accept": "application/json"}

    try:
        endpoint = f"https://www.virustotal.com/api/v3/files/{file_hash}"
        response = _get_with_rate_limit_retry(endpoint, headers)

        if response.status_code == 200:
            attrs = response.json().get("data", {}).get("attributes", {})
            return {
                "stats": attrs.get("last_analysis_stats", {}),
                "detections": _extract_detections(attrs),
                "reputation": attrs.get("reputation", 0),
                "type_description": attrs.get("type_description"),
                "meaningful_name": attrs.get("meaningful_name"),
                "popular_threat_classification": attrs.get("popular_threat_classification"),
                # How widely VT has actually encountered this sample. A report
                # can show every engine "undetected" simply because the file was
                # submitted once — by us, on a previous scan — which is not the
                # same as a file the world has held and cleared. Scoring uses
                # this to refuse to read a lone submission as a consensus.
                "times_submitted": attrs.get("times_submitted"),
                "first_submission_date": attrs.get("first_submission_date"),
                "vt_status": "found",
            }
        elif response.status_code == 404:
            # Hash not found. Uploading is how an unknown file gets a verdict at
            # all, but it also publishes the artifact: anything sent here enters
            # VirusTotal's corpus, where paid subscribers can download it. That
            # is the right trade for a suspicious attachment and the wrong one
            # for a private document, so the submitter decides.
            if not allow_upload:
                logger.info(f"Hash {file_hash[:16]}... unknown; upload declined by submitter.")
                return {
                    "status": "unknown",
                    "message": ("File not found in VirusTotal, and it was not uploaded "
                                "because this scan requested hash lookup only."),
                    "vt_status": "not_found",
                    "upload_declined": True,
                }
            if file_path and os.path.exists(file_path):
                logger.info(f"Hash {file_hash[:16]}... unknown, uploading file to VT.")
                return upload_file(file_path, api_key)
            return {"status": "unknown", "message": "File not found in VirusTotal database.", "vt_status": "not_found"}
        elif response.status_code == 429:
            return {"error": "VT rate limit exceeded. Try again later.", "vt_status": "error"}
        else:
            return {"error": f"VT file lookup failed (HTTP {response.status_code})", "vt_status": "error"}

    except requests.exceptions.Timeout:
        return {"error": "VT request timed out.", "vt_status": "error"}
    except Exception as e:
        logger.error(f"VT file error: {e}")
        return {"error": str(e), "vt_status": "error"}
