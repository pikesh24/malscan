"""
How MALSCAN treats indicators belonging to well-known domains.

Two very different things were sharing one list. XML namespace identifiers
(`http://www.w3.org/2001/XMLSchema`) are boilerplate embedded in every Office
and PDF file, with nothing behind them — dropping them is right. Reputable
platforms (`github.com`, `drive.google.com`) host arbitrary user content, and
dropping those hid real payload links: a document whose only malicious link
pointed at `raw.githubusercontent.com` produced a report reading "no network
indicators extracted".

Reputation belongs to whoever controls a domain. It never extends to an
arbitrary path someone else uploaded there.
"""

from app.main import (
    _is_namespace_identifier,
    _is_reputable_host,
    _is_suppressible_indicator,
    _pick_best_url,
    _rank_urls_by_risk,
    _strip_safe_indicators,
)


def _strip(urls, domains=None, keep=None):
    iocs = {"urls": list(urls), "domains": list(domains or []), "ips": []}
    _strip_safe_indicators(iocs, keep=keep)
    return iocs


# ── Namespace boilerplate is still dropped ────────────────────────────────────

def test_namespace_identifiers_are_dropped():
    """The reason the list exists: every PDF/Office file embeds these."""
    noise = [
        "http://www.w3.org/2001/XMLSchema",
        "http://schemas.microsoft.com/office/2004/12/omml",
        "http://schemas.android.com/apk/res/android",
        "http://ns.adobe.com/xap/1.0/",
        "http://purl.org/dc/elements/1.1/",
    ]
    assert _strip(noise)["urls"] == []
    for url in noise:
        assert _is_namespace_identifier(url), url


def test_reserved_documentation_domains_are_dropped():
    """RFC 2606 names are never real infrastructure."""
    assert _strip(["http://example.com/thing", "http://example.org/"])["urls"] == []


# ── Payload links on reputable hosts must survive ─────────────────────────────

PAYLOAD_URLS = [
    "https://raw.githubusercontent.com/attacker/repo/main/payload.ps1",
    "https://github.com/badactor/malware/releases/download/v1/loader.exe",
    "https://storage.googleapis.com/attacker-bucket/stage2.bin",
    "https://drive.google.com/uc?export=download&id=EVIL",
]


def test_payload_urls_on_reputable_hosts_are_not_dropped():
    """GitHub and Google Drive are among the most abused malware-staging hosts.

    Deleting these was a false negative with a published list of 25 domains an
    attacker could host on to become invisible.
    """
    kept = _strip(PAYLOAD_URLS)["urls"]
    assert len(kept) == len(PAYLOAD_URLS), f"dropped: {set(PAYLOAD_URLS) - set(kept)}"


def test_payload_url_can_be_chosen_for_external_scanning():
    """A payload link must be eligible for VirusTotal/URLScan, not skipped."""
    picked = _pick_best_url(["https://github.com/x/releases/download/v1/loader.exe"])
    assert picked is not None


def test_path_bearing_reputable_urls_are_never_suppressed():
    """A URLhaus hit on a specific payload URL is real evidence and must stand,
    even though the domain hosting it is reputable."""
    for url in PAYLOAD_URLS:
        assert not _is_suppressible_indicator(url), url


# ── Bare references to reputable hosts: kept, but still not scored on ─────────

def test_bare_reputable_host_is_kept_in_the_report():
    """A link in a scanned file is the subject of the scan, not boilerplate.

    Extracted-and-allow-listed used to mean "delete", so scanning a text file
    containing only https://mail.google.com produced an empty report claiming no
    indicators were extracted — which was not true.
    """
    iocs = _strip(["https://mail.google.com"], domains=["mail.google.com"])
    assert iocs["urls"] == ["https://mail.google.com"]
    assert iocs["domains"] == ["mail.google.com"]


def test_bare_reputable_host_is_still_suppressible_for_intel():
    """Junk feed entries on big domains are why suppression exists.

    Malware configs routinely reference google.com as a connectivity check, and
    a 100%-confidence ThreatFox entry on it once scored google.com as Malicious.
    A bare host carries no payload, so a "hit" on it is noise.
    """
    assert _is_suppressible_indicator("https://mail.google.com")
    assert _is_suppressible_indicator("google.com")
    assert _is_reputable_host("mail.google.com")


def test_bare_reputable_host_is_not_an_external_scan_target():
    """Nothing to learn from sending google.com to VirusTotal."""
    assert _pick_best_url(["https://mail.google.com"]) is None


# ── Anchoring: reputation follows the registrable domain, not a substring ─────

def test_reputation_does_not_leak_to_lookalike_domains():
    """The typosquat bug at a larger scale: matching must be anchored."""
    for host in ("google.com.evil.tk", "github.com.phish.xyz", "google-drive-share.tk"):
        assert not _is_reputable_host(host), host
        assert not _is_suppressible_indicator(f"http://{host}/x"), host
    assert _strip(["http://google.com.evil.tk/payload"])["urls"] != []


# ── Which link gets analysed in a multi-link file ─────────────────────────────
# Everything downstream took whatever came first, and IOC lists are sorted
# alphabetically for reproducibility — so a decoy link that sorted earlier beat
# the payload link, and which one a scan examined came down to spelling.

def test_riskiest_url_wins_not_the_alphabetically_first():
    urls = ["http://aaa-harmless.example/page", "http://zzz-evil.tk/payload.exe"]
    assert _pick_best_url(urls) == "http://zzz-evil.tk/payload.exe"
    assert _pick_best_url(list(reversed(urls))) == "http://zzz-evil.tk/payload.exe"


def test_ranking_is_deterministic_on_ties():
    """Equal-risk URLs keep alphabetical order, so repeat scans agree."""
    urls = ["https://bbb.example/a", "https://aaa.example/a"]
    assert _rank_urls_by_risk(urls) == _rank_urls_by_risk(list(reversed(urls)))
    assert _rank_urls_by_risk(urls)[0] == "https://aaa.example/a"


def test_ranking_skips_boilerplate_and_bare_reputable_hosts():
    ranked = _rank_urls_by_risk([
        "http://www.w3.org/2001/XMLSchema",
        "https://mail.google.com",
        "http://payload-host.tk/loader.exe",
    ])
    assert ranked == ["http://payload-host.tk/loader.exe"]


def test_payload_on_reputable_host_outranks_a_bare_reference():
    """The GitHub payload case: reputable domain, but a real file on it."""
    ranked = _rank_urls_by_risk([
        "https://mail.google.com",
        "https://github.com/x/releases/download/v1/loader.exe",
    ])
    assert ranked[0] == "https://github.com/x/releases/download/v1/loader.exe"
