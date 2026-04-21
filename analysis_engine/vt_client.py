"""
analysis_engine/vt_client.py
VirusTotal v3 API client for URL threat intelligence.
"""

import base64
import requests
import time
import logging

logger = logging.getLogger(__name__)


def get_url_report(url: str, api_key: str) -> dict:
    """
    Queries VirusTotal for a URL report. If no report exists, submits
    the URL for scanning and polls for results.

    Returns dict with 'stats' (malicious/suspicious/harmless/undetected counts)
    and 'reputation' score, or an 'error' key on failure.
    """
    if not api_key:
        return {"error": "No VT API key provided"}

    url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
    headers = {"x-apikey": api_key, "accept": "application/json"}

    try:
        # 1. Check if VT already has a report for this URL
        endpoint = f"https://www.virustotal.com/api/v3/urls/{url_id}"
        response = requests.get(endpoint, headers=headers, timeout=15)

        if response.status_code == 200:
            attrs = response.json().get("data", {}).get("attributes", {})
            return {
                "stats": attrs.get("last_analysis_stats", {}),
                "reputation": attrs.get("reputation", 0),
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
                # Poll up to 4 times (12 s total)
                for _ in range(4):
                    time.sleep(3)
                    poll = requests.get(
                        f"https://www.virustotal.com/api/v3/analyses/{analysis_id}",
                        headers=headers,
                        timeout=15,
                    )
                    if poll.status_code == 200:
                        attrs = poll.json().get("data", {}).get("attributes", {})
                        if attrs.get("status") == "completed":
                            return {"stats": attrs.get("stats", {}), "reputation": 0}
                return {"status": "queued", "message": "VT analysis still pending."}
            return {"error": f"VT submit failed (HTTP {submit_res.status_code})"}

        elif response.status_code == 429:
            return {"error": "VT rate limit exceeded. Try again later."}
        else:
            return {"error": f"VT lookup failed (HTTP {response.status_code})"}

    except requests.exceptions.Timeout:
        return {"error": "VT request timed out."}
    except Exception as e:
        logger.error(f"VT error: {e}")
        return {"error": str(e)}


def get_file_report(file_hash: str, api_key: str) -> dict:
    """
    Queries VirusTotal for a file report by SHA-256 hash.
    Returns dict with 'stats' and 'reputation', or 'error' on failure.
    """
    if not api_key:
        return {"error": "No VT API key provided"}
    if not file_hash:
        return {"error": "No file hash provided"}

    headers = {"x-apikey": api_key, "accept": "application/json"}

    try:
        endpoint = f"https://www.virustotal.com/api/v3/files/{file_hash}"
        response = requests.get(endpoint, headers=headers, timeout=15)

        if response.status_code == 200:
            attrs = response.json().get("data", {}).get("attributes", {})
            return {
                "stats": attrs.get("last_analysis_stats", {}),
                "reputation": attrs.get("reputation", 0),
                "type_description": attrs.get("type_description"),
                "meaningful_name": attrs.get("meaningful_name"),
                "popular_threat_classification": attrs.get("popular_threat_classification"),
            }
        elif response.status_code == 404:
            return {"status": "unknown", "message": "File not found in VirusTotal database."}
        elif response.status_code == 429:
            return {"error": "VT rate limit exceeded. Try again later."}
        else:
            return {"error": f"VT file lookup failed (HTTP {response.status_code})"}

    except requests.exceptions.Timeout:
        return {"error": "VT request timed out."}
    except Exception as e:
        logger.error(f"VT file error: {e}")
        return {"error": str(e)}
