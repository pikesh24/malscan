"""
Third-party resource chain: extraction, classification and scoring.

The check exists because a page is its domain plus everything it loads, and
reputation was only ever asked about the domain. deutschland.com scored 0/100
while serving a script from an S3 bucket that 9 VirusTotal vendors flagged.

The danger in fixing that is overcorrection. Object storage, free hosting and
CDNs carry an enormous share of the ordinary web, so a rule like "flag pages
that load from S3" would fire across the Tranco top 10,000 and mean nothing —
the standard tests/live/base_rates.py sets for every other signal here. The
false-positive tests below are therefore the point of this file, not a footnote
to it: structure is allowed to describe and to order lookups, but only
reputation (and one genuinely rare conjunction) is allowed to score.
"""

import pytest

from analysis_engine import resource_chain as rc
from attribution_module.scoring import _check_resource_chain


def _urlscan(urls=(), domains=()):
    return {
        "screenshot_url": "https://urlscan.io/screenshots/x.png",
        "resource_urls": list(urls),
        "outgoing_domains": list(domains),
    }


def _score(chain):
    return _check_resource_chain({"resource_chain": chain})


# ── False positives: the ordinary web must stay at zero ──────────────────────

def test_ordinary_page_scores_nothing():
    """Fonts, analytics and a tag manager are most of the web's third parties."""
    chain = rc.analyze(_urlscan(urls=[
        "https://example.com/index.html",
        "https://fonts.googleapis.com/css?family=Inter",
        "https://fonts.gstatic.com/s/inter/v1/font.woff2",
        "https://www.google-analytics.com/analytics.js",
        "https://www.googletagmanager.com/gtm.js?id=GTM-XYZ",
    ]), "https://example.com")

    score, reasons = _score(chain)
    assert score == 0, f"ordinary third parties scored {score}: {reasons}"


def test_anonymous_hosting_alone_scores_nothing():
    """The exact overcorrection to avoid. Vast numbers of legitimate sites serve
    assets from object storage; 'it is on S3' is not evidence of anything."""
    chain = rc.analyze(_urlscan(urls=[
        "https://shop.example/index.html",
        "https://assets-prod.s3.amazonaws.com/app.css",
        "https://cdn.example-corp.pages.dev/bundle.css",
    ]), "https://shop.example")

    assert any("anonymous_hosting" in h["facets"] for h in chain["hosts"]), \
        "the facet should still be recorded — it is reported and ranks lookups"
    score, _ = _score(chain)
    assert score == 0, "structure alone must not score"


def test_clean_reputation_on_an_anonymous_host_scores_nothing():
    """If VirusTotal has looked and found nothing, being on S3 does not override
    it. Inventing a score here is what would flag half the web."""
    chain = rc.analyze(_urlscan(urls=[
        "https://site.example/",
        "https://bucket123.s3.amazonaws.com/widget.css",
    ]), "https://site.example")
    for entry in chain["hosts"]:
        entry["checked"] = True
        entry["virustotal"] = {"malicious": 0, "suspicious": 0, "harmless": 60, "undetected": 12}

    score, _ = _score(chain)
    assert score == 0


def test_single_vendor_detection_is_noise():
    """Mirrors _check_virustotal: one vendor is a false positive, not a signal."""
    chain = rc.analyze(_urlscan(urls=[
        "https://site.example/", "https://third.example/x.css",
    ]), "https://site.example")
    for entry in chain["hosts"]:
        entry["virustotal"] = {"malicious": 1, "suspicious": 0, "harmless": 60, "undetected": 30}

    score, _ = _score(chain)
    assert score == 0


def test_first_party_resources_are_not_a_chain():
    """A site loading its own assets, including its own bucket, is not a chain."""
    chain = rc.analyze(_urlscan(urls=[
        "https://example.com/",
        "https://cdn.example.com/app.js",
        "https://example.com/download/setup.exe",
    ]), "https://example.com")

    assert chain["hosts"] == [], f"first-party hosts leaked in: {chain['hosts']}"
    assert _score(chain)[0] == 0


def test_empty_or_failed_urlscan_is_inert():
    for data in ({}, {"error": "URLScan rate limit exceeded."}, {"status": "pending"}):
        chain = rc.analyze(data, "https://example.com")
        assert chain["skipped"] is True
        assert _score(chain) == (0, [])


# ── True positives ───────────────────────────────────────────────────────────

def test_malicious_third_party_scores_and_names_the_host():
    """The deutschland.com case: clean wrapper, malicious loaded resource."""
    chain = rc.analyze(_urlscan(urls=[
        "https://deutschland.com/",
        "https://digiadmin2024.s3.amazonaws.com/loader.css",
    ]), "https://deutschland.com")
    for entry in chain["hosts"]:
        if entry["host"].startswith("digiadmin"):
            entry["virustotal"] = {"malicious": 9, "suspicious": 0, "harmless": 50, "undetected": 33}

    score, reasons = _score(chain)
    assert score >= 70, "a 9-vendor detection on a loaded resource must be decisive"
    assert any("digiadmin2024.s3.amazonaws.com" in r for r in reasons), \
        "the report must name the offending host, not just move the total"


def test_executable_from_a_third_party_scores_without_any_reputation():
    """The day-zero case the user asked about: reputation knows nothing, because
    the infrastructure is new. A page auto-fetching an .exe from someone else's
    host is rare enough on its own to be worth points."""
    chain = rc.analyze(_urlscan(urls=[
        "https://invoice-portal.example/",
        "https://brand-new-bucket.s3.amazonaws.com/invoice.exe",
    ]), "https://invoice-portal.example")

    score, reasons = _score(chain)
    assert score >= 25, "an executable pulled from a third party must score unaided"
    assert any("executable" in r.lower() for r in reasons)


def test_intel_hit_on_a_loaded_resource_scores():
    chain = rc.analyze(_urlscan(urls=[
        "https://site.example/", "https://bad.example/payload.css",
    ]), "https://site.example")
    chain["intel_hits"] = [{"source": "urlhaus", "found": True,
                            "matched_url": "https://bad.example/payload.css"}]

    score, reasons = _score(chain)
    assert score >= 45
    assert any("urlhaus" in r for r in reasons)


# ── Transparency: a clean total must not imply the chain was vetted ──────────

def test_unchecked_hosts_are_reported_even_when_nothing_scores():
    chain = rc.analyze(_urlscan(urls=[
        "https://site.example/", "https://unknown-third-party.example/x.css",
    ]), "https://site.example")

    score, reasons = _score(chain)
    assert score == 0
    assert any("not" in r and "reputation-checked" in r for r in reasons), \
        "a 0 score alongside unchecked hosts must say they were unchecked"


# ── Lookup budgeting ─────────────────────────────────────────────────────────

def test_javascript_does_not_count_as_a_payload():
    """Regression: .js was originally treated as an executable payload, which
    ranked Google Analytics above a malicious bucket. With a budget of 3 the
    lookups went to Google and the real host was never checked."""
    chain = rc.analyze(_urlscan(urls=[
        "https://site.example/",
        "https://www.google-analytics.com/analytics.js",
        "https://evil-bucket.s3.amazonaws.com/x.css",
    ]), "https://site.example")

    assert rc.select_for_reputation(chain, 3)[0].startswith("evil-bucket"), \
        "budget must go to the anonymous host, not the analytics script"
    assert _score(chain)[0] == 0, ".js must not score as a payload"


def test_budget_is_not_spent_on_merely_unknown_hosts():
    """An unremarkable host is most of the web — including fonts.googleapis.com,
    which is not in the Tranco top 10,000. Spending a rate-limited lookup there
    is worse than not spending it."""
    chain = rc.analyze(_urlscan(urls=[
        "https://site.example/",
        "https://fonts.googleapis.com/css",
        "https://fonts.gstatic.com/font.woff2",
    ]), "https://site.example")

    assert rc.select_for_reputation(chain, 3) == []


def test_budget_is_capped_and_deduplicated_per_registrable_domain():
    urls = ["https://site.example/"] + [
        f"https://bucket{i}.s3.amazonaws.com/f.css" for i in range(6)
    ] + ["https://1.2.3.4/x.css"]
    chain = rc.analyze(_urlscan(urls=urls), "https://site.example")

    picks = rc.select_for_reputation(chain, 2)
    assert len(picks) <= 2
    regs = {rc.classify_host(p)["registrable_domain"] for p in picks}
    assert len(regs) == len(picks), "two lookups were spent on one registrable domain"


def test_raw_ip_host_is_prioritised_for_lookup():
    chain = rc.analyze(_urlscan(urls=[
        "https://site.example/", "https://198.51.100.7/x.css",
        "https://ordinary-cdn.example/y.css",
    ]), "https://site.example")

    assert rc.select_for_reputation(chain, 1) == ["198.51.100.7"]


# ── Extraction ───────────────────────────────────────────────────────────────

def test_hosts_come_from_request_urls_not_just_the_trimmed_domain_list():
    """outgoing_domains is capped at 10 for display. A page with many third
    parties would otherwise hide the interesting host behind that cap."""
    urls = [f"https://t{i}.example/x.css" for i in range(15)] + [
        "https://late-and-interesting.s3.amazonaws.com/p.css"
    ]
    chain = rc.analyze(_urlscan(urls=urls, domains=[f"t{i}.example" for i in range(10)]),
                       "https://site.example")

    assert any(h["host"].startswith("late-and-interesting") for h in chain["hosts"])


def test_domain_list_is_used_when_request_urls_are_absent():
    """Reused older scans may carry only the domain list."""
    chain = rc.analyze(_urlscan(domains=["third-party.example"]), "https://site.example")
    assert [h["host"] for h in chain["hosts"]] == ["third-party.example"]
