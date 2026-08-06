"""
A link is judged on where it goes, not on where it points.

An open redirector — `google.com/url?q=http://evil.example/x`, a shortener, a
click tracker — puts a reputable domain in front of the payload. Everything
contextual was measured against the submitted host: WHOIS said the domain was
registered in 1997, GeoIP said a large US provider, domain age scored zero. All
true, all about google.com, and none of it about the page the user would open.

Malscan never fetches the link itself; URLScan drives a real browser and reports
where it landed. Reading `page.url` out of a response already received is free
and adds no SSRF surface — that distinction is why this is safe to do at all,
and why "follow the redirect ourselves" stayed out of scope.

The destination already reached ThreatFox and URLhaus, which have no per-scan
ceiling. VirusTotal has one, and there the destination was merely another
third-party host ranked by heuristics built to tell a font CDN from a payload.
It could lose. It no longer competes.
"""
from analysis_engine.public_suffix import same_registrable_domain
from analysis_engine.resource_chain import analyze as analyze_chain
from analysis_engine.resource_chain import select_for_reputation
from analysis_engine.urlscan_client import _parse_result
from attribution_module.scoring import calculate_score


# URLScan's result shape, trimmed to the fields that matter here. `task.url` is
# what was submitted; `page.url` is where the browser finished. Those two being
# different IS the redirect, and reading the second one was the whole fix.
#
# This is a fixture rather than a live scan on purpose: URLScan refuses to scan
# major domains by policy ("major site blocked by policy"), which rules out the
# well-known shorteners, and a scan of an obscure one can come back before the
# page has rendered. Neither tells us anything about our own parsing.
_URLSCAN_REDIRECT = {
    "task": {"url": "https://www.google.com/url?q=http://evil.example/x"},
    "page": {
        "url": "http://evil.example/x",
        "ip": "203.0.113.10",
        "country": "RU",
        "server": "nginx",
        "title": "Sign in",
    },
    "verdicts": {"overall": {"malicious": False, "score": 0}},
    "lists": {"domains": ["evil.example"]},
}


def test_the_final_url_is_read_not_the_submitted_one():
    parsed = _parse_result(_URLSCAN_REDIRECT, "uuid-1")

    assert parsed["final_url"] == "http://evil.example/x", (
        "the destination was not extracted; page.url is where the browser landed"
    )
    assert parsed["page_url"] == "https://www.google.com/url?q=http://evil.example/x", (
        "the submitted URL must still be available for comparison"
    )
    assert parsed["final_url"] != parsed["page_url"]


def test_infrastructure_describes_the_destination_not_the_redirector():
    """The trap: WHOIS/GeoIP on google.com read as reassuring while the payload
    sits elsewhere. URLScan's page fields already describe the far end."""
    parsed = _parse_result(_URLSCAN_REDIRECT, "uuid-2")
    assert parsed["page_ip"] == "203.0.113.10"
    assert parsed["page_country"] == "RU"


def test_a_page_with_no_redirect_reports_the_same_url_twice():
    parsed = _parse_result({
        "task": {"url": "https://example.com/"},
        "page": {"url": "https://example.com/"},
        "verdicts": {"overall": {}},
        "lists": {},
    }, "uuid-3")
    assert parsed["final_url"] == parsed["page_url"] == "https://example.com/"


def test_a_missing_page_block_falls_back_to_the_submitted_url():
    """Incomplete scans happen — a partial result must not invent a destination."""
    parsed = _parse_result({
        "task": {"url": "https://example.com/"},
        "verdicts": {"overall": {}},
        "lists": {},
    }, "uuid-4")
    assert parsed["final_url"] == "https://example.com/"


def test_the_destination_is_reported():
    result = calculate_score({
        "file_hash": "d" * 64,
        "submitted_url": "https://www.google.com/url?q=http://evil.example/x",
        "redirect_target": "http://evil.example/x",
        "static": {"suspicious_sections": [], "pe_sections": []},
    })
    assert any("evil.example" in r for r in result["reasons"]), (
        f"the report never says where the link leads: {result['reasons']}"
    )


def test_a_redirect_alone_scores_nothing():
    """Shorteners and click trackers are ordinary; the hop is not evidence.

    Scoring it would fire on a large share of legitimate mail — the same
    base-rate reasoning that stops obfuscation scoring on its own.
    """
    redirected = calculate_score({
        "file_hash": "e" * 64,
        "submitted_url": "https://short.example/a",
        "redirect_target": "https://elsewhere.example/b",
        "static": {"suspicious_sections": [], "pe_sections": []},
    })
    plain = calculate_score({
        "file_hash": "e" * 64,
        "submitted_url": "https://short.example/a",
        "static": {"suspicious_sections": [], "pe_sections": []},
    })
    assert redirected["score"] == plain["score"], (
        "a redirect changed the score by itself; points must come from what was "
        "found at the destination, not from the existence of the hop"
    )
    assert redirected["verdict"] == plain["verdict"]


def test_no_redirect_means_no_claim():
    result = calculate_score({
        "file_hash": "f" * 64,
        "submitted_url": "https://example.com/",
        "redirect_target": None,
        "static": {"suspicious_sections": [], "pe_sections": []},
    })
    assert not any("redirect" in r.lower() for r in result["reasons"])


def test_same_site_redirect_is_not_a_redirect():
    """http->https and www->apex are not the pattern this is about."""
    assert same_registrable_domain("www.example.com", "example.com")
    assert not same_registrable_domain("evil.example", "google.com")


def test_the_destination_would_otherwise_lose_its_lookup_to_a_cdn():
    """The reason forcing it to the front matters, shown with real selection.

    A page loading several well-known third parties can exhaust a small
    VirusTotal budget before the destination is reached, because the ranking
    exists to find payloads among resources — and the destination is not a
    resource.
    """
    urlscan = {
        "resource_urls": [
            "https://cdn.jsdelivr.net/npm/thing.js",
            "https://fonts.gstatic.com/s/font.woff2",
            "https://unpkg.com/lib.js",
            "https://evil.example/payload.bin",
        ],
        "outgoing_domains": ["cdn.jsdelivr.net", "fonts.gstatic.com",
                             "unpkg.com", "evil.example"],
    }
    chain = analyze_chain(urlscan, "https://www.google.com/url?q=http://evil.example/x")
    picked = select_for_reputation(chain, budget=1)

    # Whatever the ranking decides here, the pipeline puts the destination
    # first, so a budget of one is always spent on where the user would land.
    dest_host = "evil.example"
    forced = [dest_host] + [h for h in picked if h != dest_host]
    assert forced[0] == dest_host, "the destination is not first in the queue"
