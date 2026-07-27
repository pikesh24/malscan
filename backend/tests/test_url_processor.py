"""Unit tests for analysis_engine/url_processor.py heuristics."""

from analysis_engine.url_processor import analyze_url


def test_clean_https_brand_has_no_flags():
    result = analyze_url("https://www.google.com")
    assert result["suspicious_flags"] == []


def test_raw_ip_url_flagged():
    result = analyze_url("http://1.2.3.4/payload")
    flags = " ".join(result["suspicious_flags"])
    assert "raw IP" in flags


def test_http_not_https_flagged():
    result = analyze_url("http://example.com")
    flags = " ".join(result["suspicious_flags"])
    assert "HTTPS" in flags


def test_url_shortener_flagged():
    result = analyze_url("https://bit.ly/3xYzAbC")
    flags = " ".join(result["suspicious_flags"])
    assert "shortener" in flags


def test_suspicious_tld_flagged():
    result = analyze_url("https://free-prizes.xyz")
    flags = " ".join(result["suspicious_flags"])
    assert ".xyz" in flags


def test_typosquatting_detected():
    result = analyze_url("https://paypa1.com/login")
    flags = " ".join(result["suspicious_flags"])
    assert "impersonate" in flags


def test_brand_in_longer_domain_detected():
    result = analyze_url("https://hdfcbank-secure-login.com")
    flags = " ".join(result["suspicious_flags"])
    assert "impersonate" in flags


def test_dangerous_file_extension_flagged():
    result = analyze_url("https://example.com/update.exe")
    flags = " ".join(result["suspicious_flags"])
    assert ".exe" in flags


def test_empty_url_returns_clean_structure():
    result = analyze_url("")
    assert result["suspicious_flags"] == []
    assert result["domain"] is None


# ── A brand's own other domains are not impersonations of it ──────────────────
# The subdomain fix (mail.google.com) handled only one shape. Real traffic uses
# the brand on other TLDs and on sibling domains the brand also owns, and the
# substring test flagged all of them.

import pytest  # noqa: E402

from analysis_engine.url_processor import analyze_url as _au  # noqa: E402


def _score(url):
    return min(sum(_au(url).get("flag_weights") or []), 60)


@pytest.mark.parametrize("url", [
    "https://s3.dualstack.us-east-1.amazonaws.com/bucket/file.txt",  # scored 60
    "https://www.amazon.in/gp/product/B0ABC",                        # Amazon India, 35
    "https://login.microsoftonline.com/common/oauth2/v2.0/authorize",# M365 sign-in, 35
    "https://www.google.co.in/search?q=x",
    "https://fbcdn.net/asset.png",
    "https://outlook.office365.com/mail/",
    "https://mail.google.com/",
    "https://netbanking.hdfcbank.com/",
])
def test_brand_owned_domains_are_not_typosquats(url):
    flags = " ".join(_au(url)["suspicious_flags"]).lower()
    assert "impersonate" not in flags, f"{url} reported as impersonation: {flags}"
    assert _score(url) < 35, f"{url} scored {_score(url)}"


@pytest.mark.parametrize("url,brand", [
    ("http://hdfcbank-secure.tk/login", "hdfcbank"),
    ("http://amazon-security-alert.tk/verify", "amazon"),
    ("http://microsoft-login.xyz/auth", "microsoft"),
    ("https://paypa1.com/signin", "paypal"),
    ("http://g00gle.com/", "google"),
    ("http://google.com.evil.tk/", "google"),
])
def test_real_lookalikes_are_still_caught(url, brand):
    flags = " ".join(_au(url)["suspicious_flags"]).lower()
    assert "impersonate" in flags, f"{url} no longer detected as a lookalike"
    assert _score(url) >= 35, f"{url} only scored {_score(url)}"


def test_typosquat_is_not_double_counted():
    """s3...amazonaws.com collected both the substring and homoglyph flags —
    35+35 for one observation — because normalising digits elsewhere in the host
    left the brand still matching."""
    flags = _au("http://g00gle.com/")["suspicious_flags"]
    impersonation = [f for f in flags if "impersonate" in f.lower()]
    assert len(impersonation) == 1, f"counted twice: {impersonation}"


# ── Established sites are not lookalikes of other sites ───────────────────────
# Measured against the Tranco top 10,000: 2% of it reached Suspicious, entirely
# from the typosquat check. Spelling cannot separate telegraph.co.uk (one edit
# from telegram.org) from paypa1.com — traffic can.

@pytest.mark.parametrize("url", [
    "https://telegraph.co.uk/",          # 1 edit from telegram.org
    "https://telegra.ph/",               # Telegram's own publishing platform
    "https://wetter.com/",               # 2 edits from twitter.com
    "https://moodle.org/",               # 2 edits from google.com
    "https://media.net/",                # 2 edits from india.gov.in
    "https://applvn.com/",               # 2 edits from apple.com
    "https://youku.com/",                # 2 edits from youtube.com
    "https://google-analytics.com/",     # brand as a token, Google's own
    "https://apple-dns.net/",            # brand as a token, Apple's own
    "https://amazon-adsystem.com/",      # brand as a token, Amazon's own
    "https://googledomains.com/",        # Google's own registrar
    "https://onlinesbi.com/",            # SBI's real netbanking domain
])
def test_established_sites_are_not_flagged_as_impersonation(url):
    flags = " ".join(_au(url)["suspicious_flags"]).lower()
    assert "impersonate" not in flags, f"{url}: {flags}"
    assert _score(url) < 35


@pytest.mark.parametrize("url", [
    "http://sbi-netbanking-verify.tk/",   # 3-char brand: was undetectable
    "http://npci-upi-refund.tk/",         # 4-char brand: was undetectable
    "http://paytm-kyc-update.tk/",
    "http://phonepe-refund.xyz/",
    "http://paypal.com.secure-login.ml/", # brand pushed into a subdomain
])
def test_indian_brand_lookalikes_are_caught(url):
    """SBI and NPCI were skipped entirely by a `len(brand) < 5` guard, so India's
    largest bank could never be a typosquat target — squarely in the P0 threat
    model. Short brands are now matched as tokens, which is precise enough."""
    assert "impersonate" in " ".join(_au(url)["suspicious_flags"]).lower(), url
    assert _score(url) >= 35
