"""
analysis_engine/sandbox_client.py
Hybrid Analysis (HA) API client — submits a file for dynamic sandbox
execution and retrieves the verdict + environment details.

API docs: https://www.hybrid-analysis.com/docs/api/v2
"""

import requests
import time
import logging
import os

logger = logging.getLogger(__name__)

HA_BASE = "https://www.hybrid-analysis.com/api/v2"


def submit_file(file_path: str, api_key: str, environment_id: int = 160) -> dict:
    """
    Submits a file to Hybrid Analysis for sandbox detonation.

    environment_id defaults:
      100 = Windows 7 32-bit
      110 = Windows 7 64-bit
      160 = Windows 10 64-bit  (recommended default)
      200 = Android Static Analysis
      300 = Linux 64-bit

    Returns dict with sandbox verdict, threat_score, classification,
    mitre_attcks, and a permalink.  Or 'error' key on failure.
    """
    if not api_key:
        return {"error": "No Hybrid Analysis API key provided"}

    headers = {
        "api-key": api_key,
        "User-Agent": "Falcon Sandbox",
    }

    # Detect APK and route to Android environment
    if file_path.lower().endswith(".apk"):
        environment_id = 200

    try:
        # 1. Submit file
        filename = os.path.basename(file_path)
        with open(file_path, "rb") as f:
            submit_res = requests.post(
                f"{HA_BASE}/submit/file",
                headers=headers,
                files={"file": (filename, f)},
                data={"environment_id": environment_id},
                timeout=30,
            )

        if submit_res.status_code == 429:
            return {"error": "Hybrid Analysis rate limit exceeded."}
        if submit_res.status_code not in (200, 201):
            return {"error": f"HA submit failed (HTTP {submit_res.status_code})"}

        job_id = submit_res.json().get("job_id")
        sha256 = submit_res.json().get("sha256")

        if not job_id:
            return {"error": "No job_id returned from Hybrid Analysis."}

        # 2. Poll for completion (up to ~90s — sandbox takes time)
        for attempt in range(9):
            time.sleep(10)
            state_res = requests.get(
                f"{HA_BASE}/report/{sha256}:160/state",
                headers=headers,
                timeout=15,
            )
            if state_res.status_code == 200:
                state = state_res.json().get("state", "")
                if state == "SUCCESS":
                    break
        else:
            # Did not finish within our window — return pending status
            return {
                "status": "pending",
                "message": "Hybrid Analysis sandbox still running.",
                "permalink": f"https://www.hybrid-analysis.com/sample/{sha256}",
            }

        # 3. Fetch the summary report
        report_res = requests.get(
            f"{HA_BASE}/report/{sha256}:160/summary",
            headers=headers,
            timeout=15,
        )

        if report_res.status_code != 200:
            return {
                "status": "partial",
                "message": "Sandbox finished but report unavailable.",
                "permalink": f"https://www.hybrid-analysis.com/sample/{sha256}",
            }

        data = report_res.json()

        return {
            "verdict": data.get("verdict"),
            "threat_score": data.get("threat_score"),
            "threat_level": data.get("threat_level"),
            "classification_tags": data.get("classification_tags", []),
            "mitre_attcks": [
                {"tactic": m.get("tactic"), "technique": m.get("technique"), "attck_id": m.get("attck_id")}
                for m in (data.get("mitre_attcks") or [])
            ][:10],
            "total_processes": data.get("total_processes"),
            "total_network_connections": data.get("total_network_connections"),
            "domains": (data.get("domains") or [])[:10],
            "hosts": (data.get("hosts") or [])[:10],
            "is_malicious": data.get("verdict") == "malicious",
            "permalink": f"https://www.hybrid-analysis.com/sample/{sha256}",
        }

    except requests.exceptions.Timeout:
        return {"error": "Hybrid Analysis request timed out."}
    except Exception as e:
        logger.error(f"Hybrid Analysis error: {e}")
        return {"error": str(e)}
