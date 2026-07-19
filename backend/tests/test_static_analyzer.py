"""Unit tests for analysis_engine/static_analyzer.py."""

import os
import tempfile

from analysis_engine.static_analyzer import (
    extract_iocs, analyze_pe, is_reportable_ip, is_reportable_url,
)


def _write_temp(content: bytes) -> str:
    fd, path = tempfile.mkstemp(prefix="malscan_sa_")
    with os.fdopen(fd, "wb") as f:
        f.write(content)
    return path


def test_extract_iocs_finds_ips_and_urls():
    path = _write_temp(b"connect to http://bad-domain.example/payload.bin and ping 8.8.8.8 now")
    try:
        iocs = extract_iocs(path)
        assert "8.8.8.8" in iocs["ips"]
        assert any(u.startswith("http://bad-domain.example") for u in iocs["urls"])
    finally:
        os.unlink(path)


def test_extract_iocs_empty_file():
    path = _write_temp(b"")
    try:
        iocs = extract_iocs(path)
        assert iocs["ips"] == []
        assert iocs["urls"] == []
    finally:
        os.unlink(path)


def test_extract_iocs_missing_file():
    iocs = extract_iocs("definitely/not/a/real/file.bin")
    assert iocs == {"ips": [], "domains": [], "urls": []}


def test_analyze_pe_on_non_pe():
    path = _write_temp(b"just a text file, not an executable")
    try:
        info = analyze_pe(path)
        assert info.get("is_pe") is False
    finally:
        os.unlink(path)


# ── Binary IOC extraction: keep real indicators, drop garbage ─────────────────

def test_extract_iocs_drops_binary_garbage_keeps_real_indicators():
    """Regression (the cricket14.exe case): scanning a binary must NOT emit
    mojibake URLs or junk IPs, while a genuine embedded URL/IP survives."""
    blob = (
        b"\xff\xfe\x00PADDING"
        b" http://server.cricketacademygame.com/config.bin "
        b"127.0.0.1 0.0.0.0 2.3.0.0 45.33.32.156 "
        b"\x80\x81http://moji\xe2\x80\x99bake.evil trailing"
    )
    iocs = extract_iocs("x", data=blob)
    # Only the one globally-routable IP survives; loopback / unspecified /
    # x.x.x.0 network-base are all rejected.
    assert iocs["ips"] == ["45.33.32.156"]
    assert "http://server.cricketacademygame.com/config.bin" in iocs["urls"]
    # The high-byte-broken fragment ('http://moji') has no dotted host → dropped.
    assert all("moji" not in u for u in iocs["urls"])
    # Output is sorted → deterministic downstream enrichment selection.
    assert iocs["ips"] == sorted(iocs["ips"])
    assert iocs["urls"] == sorted(iocs["urls"])
    # "domains" key is always present (consumers rely on it).
    assert "domains" in iocs


def test_is_reportable_ip_rules():
    assert is_reportable_ip("8.8.8.8")
    assert is_reportable_ip("45.33.32.156")
    for bad in ("127.0.0.1", "0.0.0.0", "10.0.0.5", "192.168.1.1",
                "169.254.1.1", "224.0.0.1", "2.3.0.0", "999.1.1.1", "not.an.ip", ""):
        assert not is_reportable_ip(bad), bad


def test_is_reportable_url_rules():
    assert is_reportable_url("http://example.com/a")
    assert is_reportable_url("https://sub.domain.co.uk/x?y=1")
    assert is_reportable_url("http://8.8.8.8/x")
    for bad in ("http://mojibake", "ftp://x.com/a", "javascript:alert(1)",
                "http:///nohost", "notaurl", "http://", ""):
        assert not is_reportable_url(bad), bad
