"""
analysis_engine/urlscan_client.py
URLScan.io API client — submits a URL for sandbox analysis
and retrieves the screenshot + network behaviour data.
"""

import requests
import time
import logging

logger = logging.getLogger(__name__)


def scan_url(url: str, api_key: str) -> dict:
    """
    Submits a URL to URLScan.io for a public scan, waits for the
    result, and returns screenshot URL + page metadata.

    Returns dict with keys: screenshot_url, page_title, page_ip,
    page_country, verdicts, outgoing_domains.  Or 'error' on failure.
    """
    if not api_key:
        return {"error": "No URLScan API key provided"}

    headers = {"API-Key": api_key, "Content-Type": "application/json"}
    payload = {"url": url, "visibility": "public"}

    try:
        # 1. Submit the scan
        submit = requests.post(
            "https://urlscan.io/api/v1/scan/",
            headers=headers,
            json=payload,
            timeout=15,
        )

        if submit.status_code == 429:
            return {"error": "URLScan rate limit exceeded."}
        if submit.status_code not in (200, 201):
            error_detail = ""
            try:
                error_detail = submit.json().get("message", "")
            except Exception:
                pass

            # URLScan blocks scans of major/popular domains
            if "prevented" in error_detail.lower() or "blocked" in error_detail.lower() or "silly" in error_detail.lower():
                return {"error": "URLScan does not allow scanning this domain (popular site blocked by policy)."}
            if error_detail:
                return {"error": f"URLScan error: {error_detail}"}
            return {"error": f"URLScan submit failed (HTTP {submit.status_code})"}

        result_url = submit.json().get("api")
        scan_uuid = submit.json().get("uuid")

        if not result_url:
            return {"error": "No result URL returned from URLScan."}

        # 2. Poll for completion (up to ~100s)
        for attempt in range(20):
            time.sleep(5)
            result = requests.get(result_url, timeout=15)
            if result.status_code == 200:
                data = result.json()
                page = data.get("page", {})
                verdicts = data.get("verdicts", {}).get("overall", {})
                lists = data.get("lists", {})

                return {
                    "screenshot_url": f"https://urlscan.io/screenshots/{scan_uuid}.png",
                    "page_url": data.get("task", {}).get("url"),
                    "page_title": page.get("title", ""),
                    "page_ip": page.get("ip", ""),
                    "page_country": page.get("country", ""),
                    "page_server": page.get("server", ""),
                    "is_malicious": verdicts.get("malicious", False),
                    "verdict_score": verdicts.get("score", 0),
                    "outgoing_domains": (lists.get("domains") or [])[:10],
                }

        return {"error": "URLScan analysis timed out after 100 seconds. The site may be slow or blocked."}

    except requests.exceptions.Timeout:
        return {"error": "URLScan request timed out."}
    except Exception as e:
        logger.error(f"URLScan error: {e}")
        return {"error": str(e)}
