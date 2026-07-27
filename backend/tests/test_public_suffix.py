"""
Registrable-domain (eTLD+1) computation against the vendored Public Suffix List.

This is the anchor every reputation and brand check needs. Three separate false
positives this session came from substring or last-two-label matching on
hostnames — brand subdomains, youtu.be, then brand-owned sibling domains — and
the fix each time was to compare what someone actually controls.

The shared-hosting cases are the ones that matter most: `github.io` and
`web.app` are *public suffixes*, so `evil.github.io` is a domain a stranger
took, not part of GitHub. Getting that wrong would let anyone inherit a
reputable domain's standing by uploading a page.
"""

import pytest

from analysis_engine.public_suffix import (
    public_suffix,
    registrable_domain,
    same_registrable_domain,
)


@pytest.mark.parametrize("host,expected", [
    # Ordinary
    ("google.com",              "google.com"),
    ("mail.google.com",         "google.com"),
    ("a.b.c.google.com",        "google.com"),
    ("netbanking.hdfcbank.com", "hdfcbank.com"),
    # Multi-label suffixes — "last two labels" gets all of these wrong
    ("www.bbc.co.uk",           "bbc.co.uk"),
    ("foo.bar.co.in",           "bar.co.in"),
    ("sbi.co.in",               "sbi.co.in"),
    ("eportal.incometax.gov.in", "incometax.gov.in"),
    ("shop.example.com.au",     "example.com.au"),
    # Shared hosting: the suffix is the platform, so each tenant is its own
    # registrable domain
    ("evil.github.io",          "evil.github.io"),
    ("phish.web.app",           "phish.web.app"),
    ("login.pages.dev",         "login.pages.dev"),
    ("bad.workers.dev",         "bad.workers.dev"),
    ("someone.blogspot.com",    "someone.blogspot.com"),
    # Attacker prefixing a brand
    ("google.com.evil.tk",      "evil.tk"),
    ("secure.google.com.phish.xyz", "phish.xyz"),
    # Degenerate input
    ("localhost",               "localhost"),
    ("192.168.1.1",             "192.168.1.1"),
    ("",                        ""),
])
def test_registrable_domain(host, expected):
    assert registrable_domain(host) == expected


@pytest.mark.parametrize("host,expected", [
    ("google.com",       "com"),
    ("www.bbc.co.uk",    "co.uk"),
    ("evil.github.io",   "github.io"),
    ("x.pages.dev",      "pages.dev"),
    ("thing.madeup",     "madeup"),   # unknown TLD -> PSL's implicit "*" rule
])
def test_public_suffix(host, expected):
    assert public_suffix(host) == expected


def test_a_public_suffix_is_not_a_registrable_domain():
    """Bare "github.io" has nothing registered under it."""
    assert registrable_domain("github.io") == "github.io"
    assert public_suffix("github.io") == "github.io"


def test_same_registrant_groups_subdomains():
    assert same_registrable_domain("mail.google.com", "google.com")
    assert same_registrable_domain("netbanking.hdfcbank.com", "www.hdfcbank.com")


@pytest.mark.parametrize("a,b", [
    # Different tenants on the same shared host are different parties. Getting
    # this wrong is how an attacker inherits a platform's reputation.
    ("evil.github.io",   "github.io"),
    ("evil.github.io",   "good.github.io"),
    ("phish.web.app",    "legit.web.app"),
    # A brand prefixed onto an attacker's domain
    ("google.com.evil.tk", "google.com"),
    # Same brand, different registration
    ("google.com",       "google.co.in"),
])
def test_different_registrants_are_not_conflated(a, b):
    assert not same_registrable_domain(a, b)


def test_missing_list_does_not_crash(monkeypatch):
    """A scanner must degrade, not fall over, if the vendored list goes missing."""
    import analysis_engine.public_suffix as ps

    monkeypatch.setattr(ps, "_rules", None)
    monkeypatch.setattr(ps, "_DATA", "/nonexistent/psl.dat")
    ps.public_suffix.cache_clear()
    ps.registrable_domain.cache_clear()
    try:
        assert ps.registrable_domain("mail.google.com") == "google.com"
    finally:
        monkeypatch.setattr(ps, "_rules", None)
        ps.public_suffix.cache_clear()
        ps.registrable_domain.cache_clear()
