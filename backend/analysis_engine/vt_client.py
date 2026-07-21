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
                for _ in range(5):
                    time.sleep(3)
                    poll = requests.get(
                        f"https://www.virustotal.com/api/v3/analyses/{analysis_id}",
                        headers=headers,
                        timeout=15,
                    )
                    if poll.status_code == 200:
                        attrs = poll.json().get("data", {}).get("attributes", {})
                        if attrs.get("status") == "completed":
                            return {
                                "stats": attrs.get("stats", {}),
                                "detections": _extract_detections(attrs),
                                "reputation": 0,
                                "vt_status": "found",
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
        for attempt in range(9):
            time.sleep(5)
            poll = requests.get(
                f"https://www.virustotal.com/api/v3/analyses/{analysis_id}",
                headers=poll_headers,
                timeout=15,
            )
            if poll.status_code == 200:
                attrs = poll.json().get("data", {}).get("attributes", {})
                if attrs.get("status") == "completed":
                    return {
                        "stats": attrs.get("stats", {}),
                        "detections": _extract_detections(attrs),
                        "reputation": 0,
                        "uploaded": True,
                        "vt_status": "found",
                    }

        # Still analysing after the budget — NOT a clean verdict, just incomplete.
        # 'vt_status: queued' tells the pipeline to mark the scan partial (and
        # therefore not cache it) so a re-scan re-tries instead of freezing a 0.
        return {"status": "queued", "message": "VT file analysis still pending after upload.", "uploaded": True, "vt_status": "queued"}

    except requests.exceptions.Timeout:
        return {"error": "VT file upload timed out.", "vt_status": "error"}
    except Exception as e:
        logger.error(f"VT upload error: {e}")
        return {"error": str(e), "vt_status": "error"}


def get_file_report(file_hash: str, api_key: str, file_path: str = None) -> dict:
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
                "vt_status": "found",
            }
        elif response.status_code == 404:
            # Hash not found — upload the file if we have it
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
