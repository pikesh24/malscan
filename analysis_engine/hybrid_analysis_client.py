"""
analysis_engine/hybrid_analysis_client.py
Hybrid Analysis (Falcon Sandbox) v2 API client.
Submits files for dynamic analysis and retrieves behavioral summaries.
"""

import requests
import time
import logging
import os

logger = logging.getLogger(__name__)

BASE_URL = "https://hybrid-analysis.com/api/v2"

def submit_file(file_path: str, api_key: str) -> dict:
    """
    Submits a file for analysis, waits for completion, and returns a summary.
    Includes: threat_score, verdict, screenshots, and behavioral indicators.
    """
    if not api_key:
        return {"error": "No Hybrid Analysis API key provided"}
    if not os.path.exists(file_path):
        return {"error": "File not found for submission"}

    headers = {
        "api-key": api_key,
        "User-Agent": "Falcon Sandbox"
    }

    try:
        # 1. Submit the file
        # We use environment '160' which is Windows 10 64-bit
        logger.info(f"[HA DEBUG] Opening file: repr={repr(file_path)}, len={len(file_path)}")
        print(f"[HA DEBUG] Opening file: repr={repr(file_path)}, len={len(file_path)}")
        with open(file_path, "rb") as f:
            files = {"file": f}
            data = {"environment_id": 160}  # integer, not string

            response = requests.post(
                f"{BASE_URL}/submit/file",
                headers=headers,
                files=files,
                data=data,
                timeout=30
            )

        if response.status_code not in (200, 201):
            return {"error": f"Submission failed (HTTP {response.status_code}): {response.text}"}

        job_id = response.json().get("job_id")
        if not job_id:
            return {"error": "No job_id returned from Hybrid Analysis"}

        # 2. Poll for completion (up to ~3 minutes)
        for _ in range(18):
            time.sleep(10)
            status_res = requests.get(
                f"{BASE_URL}/report/{job_id}/summary",
                headers=headers,
                timeout=15
            )
            
            if status_res.status_code == 200:
                report = status_res.json()
                # Ensure we have the actual analysis data
                if report.get("verdict"):
                    return {
                        "job_id": job_id,
                        "verdict": report.get("verdict"),
                        "threat_score": report.get("threat_score", 0),
                        "environment_description": report.get("environment_description"),
                        "analysis_start_time": report.get("analysis_start_time"),
                        "threat_level": report.get("threat_level_status"),
                        "mitre_attcks": [a.get("attck_id_name") for a in report.get("mitre_attcks", []) if a.get("attck_id_name")],
                        "indicators": [i.get("description") for i in report.get("indicators", [])[:10]],
                        "report_url": f"https://www.hybrid-analysis.com/sample/{report.get('sha256')}"
                    }
            
            # If 404, it's still processing
            elif status_res.status_code != 404:
                break

        return {"status": "pending", "message": "Hybrid Analysis still processing after 3 minutes."}

    except Exception as e:
        logger.error(f"Hybrid Analysis error: {e}")
        return {"error": str(e)}
