"""
analysis_engine/urlscan_client.py
URLScan.io API client — sandbox analysis of URLs.

Every scan is pinned to one country so the report is reproducible. Left
unpinned, URLScan picks the vantage point itself ("automatic country
detection based on the TLD of the URL, GeoIP information of the server and
of the user"), and a geolocalised site renders differently every run —
google.com came back Dutch, Spanish or behind a bot check depending on which
exit node happened to serve it.

Fast path: their search API is checked first for a recent scan of the same
URL (by anyone) — instant result, no quota burned. Reuse is only accepted
when that scan ran from the pinned country too, otherwise it reintroduces
exactly the drift the pin exists to remove.
"""

import os
import time
import logging
from datetime import datetime, timedelta, timezone

import requests

logger = logging.getLogger(__name__)

# A previous public scan of the same URL is trusted for this long.
RECENT_SCAN_MAX_AGE_DAYS = 7

# Vantage points URLScan will accept, from GET /api/v1/availableCountries/.
# Anything outside this set is rejected at submit time, so it is checked here
# rather than spending a request to find out.
SUPPORTED_COUNTRIES = {
    "de", "us", "jp", "fr", "gb", "nl", "ca", "it", "es", "se", "fi", "dk",
    "no", "is", "au", "nz", "pl", "sg", "pt", "at", "ch", "il", "tr", "tw",
}
DEFAULT_SCAN_COUNTRY = "us"

# Candidates to consider before giving up on reuse and scanning fresh. The
# country a scan ran from is only in the full result, not the search summary
# (searching scanner.country needs a paid plan), so each candidate costs a
# retrieve — cheap, but not worth paying indefinitely.
MAX_REUSE_CANDIDATES = 3


def scan_country() -> str:
    """The vantage point to scan from. URLSCAN_COUNTRY overrides the default."""
    country = (os.environ.get("URLSCAN_COUNTRY") or DEFAULT_SCAN_COUNTRY).strip().lower()
    if country not in SUPPORTED_COUNTRIES:
        logger.warning(
            f"URLSCAN_COUNTRY={country!r} is not a URLScan vantage point; "
            f"using {DEFAULT_SCAN_COUNTRY!r}"
        )
        return DEFAULT_SCAN_COUNTRY
    return country


def _parse_result(data: dict, scan_uuid: str) -> dict:
    page = data.get("page", {})
    verdicts = data.get("verdicts", {}).get("overall", {})
    lists = data.get("lists", {})
    return {
        "screenshot_url": f"https://urlscan.io/screenshots/{scan_uuid}.png",
        # What was submitted. Named page_url for historical reasons; it is the
        # TASK url, not the page the browser ended up on.
        "page_url": data.get("task", {}).get("url"),
        # Where the browser actually landed. URLScan drives a real browser, so
        # this is the far end of any redirect chain — and it costs nothing to
        # read, because the request was already made by them, not by us. That
        # distinction is what makes using it safe: Malscan never follows the
        # link itself, so no new SSRF surface is opened.
        "final_url": page.get("url") or data.get("task", {}).get("url"),
        "page_title": page.get("title", ""),
        "page_ip": page.get("ip", ""),
        "page_country": page.get("country", ""),
        "page_server": page.get("server", ""),
        # Where the browser ran, as opposed to where the server sits. Recorded
        # from the result rather than assumed from the request, so it stays
        # honest if URLScan ever ignores the pin.
        "scan_country": (data.get("scanner") or {}).get("country", ""),
        "is_malicious": verdicts.get("malicious", False),
        "verdict_score": verdicts.get("score", 0),
        # Trimmed for the report, which renders these as chips.
        "outgoing_domains": (lists.get("domains") or [])[:10],
        # Untrimmed(-ish) equivalents for analysis. The display cap above would
        # silently drop the interesting host on a page with many third parties,
        # and the resource chain is exactly where the interesting host hides.
        # Request URLs are preferred over the domain list because they carry the
        # path, which is what shows a payload being fetched.
        "resource_urls": (lists.get("urls") or [])[:60],
        "resource_ips": (lists.get("ips") or [])[:20],
    }


def _find_recent_scan(url: str, headers: dict, country: str) -> dict | None:
    """
    Looks up an existing recent public scan of this exact URL, run from the
    same country we would have scanned from — instant, and consistent with a
    fresh scan. A scan from anywhere else is skipped: reusing it is what made
    the same URL render in a different language run to run.
    """
    try:
        search = requests.get(
            "https://urlscan.io/api/v1/search/",
            params={"q": f'task.url:"{url}"', "size": MAX_REUSE_CANDIDATES},
            headers=headers,
            timeout=10,
        )
        if search.status_code != 200:
            return None
        hits = search.json().get("results") or []

        for hit in hits:
            # Per-candidate, so one malformed hit costs that candidate rather
            # than the whole fast path.
            try:
                scanned_at = datetime.fromisoformat(hit["task"]["time"].replace("Z", "+00:00"))
                if datetime.now(timezone.utc) - scanned_at > timedelta(days=RECENT_SCAN_MAX_AGE_DAYS):
                    continue

                result_api = hit.get("result")
                scan_uuid = hit.get("_id", "")
                if not result_api:
                    continue
                result = requests.get(result_api, headers=headers, timeout=15)
                if result.status_code != 200:
                    continue

                parsed = _parse_result(result.json(), scan_uuid)
            except Exception as e:
                logger.debug(f"URLScan: skipping unusable search hit: {e}")
                continue

            # Missing means an older scan that never recorded one; unknown is
            # not the same as matching, so it is not reused either.
            if parsed["scan_country"].lower() != country:
                logger.info(
                    f"URLScan: skipping scan {scan_uuid} — ran from "
                    f"{parsed['scan_country'] or 'unknown'}, want {country}"
                )
                continue

            logger.info(
                f"URLScan: reused existing scan {scan_uuid} from "
                f"{scanned_at.date()} ({country})"
            )
            return parsed
        return None
    except Exception as e:
        logger.warning(f"URLScan search fast-path failed (falling back to fresh scan): {e}")
        return None


def scan_url(url: str, api_key: str) -> dict:
    """
    Returns sandbox data for a URL: screenshot URL, page metadata and the
    URLScan verdict. Reuses a recent existing scan when available; otherwise
    submits a fresh public scan and polls for completion.

    Returns dict with keys: screenshot_url, page_title, page_ip,
    page_country, scan_country, is_malicious, verdict_score, outgoing_domains.
    Or 'error' / 'status: pending' on failure.
    """
    if not api_key:
        return {"error": "No URLScan API key provided"}

    headers = {"API-Key": api_key, "Content-Type": "application/json"}
    country = scan_country()

    # 0. Fast path: a recent scan of this exact URL, from the same country
    existing = _find_recent_scan(url, headers, country)
    if existing is not None:
        return existing

    payload = {"url": url, "visibility": "public", "country": country}

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
            if "prevented" in error_detail.lower() or "blocked" in error_detail.lower():
                return {"error": "URLScan does not allow scanning this domain (major site blocked by policy)."}
            if error_detail:
                return {"error": f"URLScan error: {error_detail}"}
            return {"error": f"URLScan submit failed (HTTP {submit.status_code})"}

        result_url = submit.json().get("api")
        scan_uuid = submit.json().get("uuid")

        if not result_url:
            return {"error": "No result URL returned from URLScan."}

        # 2. Poll for completion. Typical scans finish in 15-35s; first check
        # after 6s (never ready sooner), then every 4s up to ~45s total so a
        # slow scan doesn't hold the whole pipeline hostage.
        time.sleep(6)
        for attempt in range(10):
            if attempt > 0:
                time.sleep(4)
            result = requests.get(result_url, headers=headers, timeout=15)
            if result.status_code == 200:
                parsed = _parse_result(result.json(), scan_uuid)
                # The pin is a request, not a guarantee. If URLScan ever scans
                # from somewhere else the result is still worth keeping, but it
                # should not be silent — this is the one line that tells you the
                # screenshots went back to drifting.
                if parsed["scan_country"].lower() != country:
                    logger.warning(
                        f"URLScan scanned from {parsed['scan_country'] or 'unknown'}, "
                        f"not the requested {country} — screenshots may not be reproducible"
                    )
                return parsed

        return {"status": "pending", "message": "URLScan analysis still running."}

    except requests.exceptions.Timeout:
        return {"error": "URLScan request timed out."}
    except Exception as e:
        logger.error(f"URLScan error: {e}")
        return {"error": str(e)}
