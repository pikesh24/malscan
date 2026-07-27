"""
The screenshot proxy is server-side fetch on behalf of a caller, so it is SSRF
surface: whatever it can reach, an attacker can reach through it — cloud
metadata at 169.254.169.254, localhost, the private network.

AUDIT_REPORT flagged this as open. The host allowlist covers the URL the caller
supplies, but `requests.get` follows redirects by default, so only the FIRST hop
is checked. Everything after it is unvalidated.
"""

import pytest
import requests

from app import main as app_main


class _FakeResp:
    def __init__(self, status=200, content=b"\x89PNG\r\n", headers=None, url=""):
        self.status_code = status
        self.content = content
        self.headers = headers or {"content-type": "image/png"}
        self.url = url
        self.is_redirect = status in (301, 302, 303, 307, 308)
        self.is_permanent_redirect = status in (301, 308)

    def raise_for_status(self):
        if self.status_code >= 400:
            raise requests.HTTPError(response=self)

    def iter_content(self, chunk_size=8192):
        for i in range(0, len(self.content), chunk_size):
            yield self.content[i:i + chunk_size]

    def close(self):
        pass


def test_disallowed_host_is_rejected(client):
    for url in ("https://169.254.169.254/latest/meta-data/",
                "https://localhost:8001/status/x",
                "http://urlscan.io/screenshot.png",          # scheme downgrade
                "https://evil.example/x.png"):
        res = client.get("/proxy/image", params={"url": url})
        assert res.status_code == 400, f"{url} was not rejected"


def test_redirect_off_the_allowlist_is_not_followed(client, monkeypatch):
    """The allowlist guards the URL supplied, not where it leads.

    An open redirect on the allowed host would otherwise turn this into a proxy
    for the internal network — the classic cloud-metadata SSRF.
    """
    captured = {}

    def fake_get(url, **kwargs):
        captured["url"] = url
        captured["allow_redirects"] = kwargs.get("allow_redirects", True)
        # Pretend the allowed host redirects somewhere it should not go.
        return _FakeResp(status=302, headers={"location": "http://169.254.169.254/"})

    monkeypatch.setattr(app_main.requests, "get", fake_get)
    res = client.get("/proxy/image", params={"url": "https://urlscan.io/screenshots/x.png"})

    assert captured.get("allow_redirects") is False, \
        "redirects are followed, so only the first hop is validated"
    assert res.status_code != 200, "a redirect response was passed through as an image"


def test_oversized_response_is_capped(client, monkeypatch):
    """`resp.content` pulls the whole body into memory with no ceiling."""
    huge = b"\x89PNG" + b"\x00" * (40 * 1024 * 1024)
    monkeypatch.setattr(app_main.requests, "get", lambda url, **kw: _FakeResp(content=huge))

    res = client.get("/proxy/image", params={"url": "https://urlscan.io/screenshots/x.png"})
    if res.status_code == 200:
        assert len(res.content) < len(huge), "no size cap on the proxied body"


def test_a_normal_screenshot_still_proxies(client, monkeypatch):
    png = b"\x89PNG\r\n\x1a\n" + b"\x00" * 512
    monkeypatch.setattr(app_main.requests, "get", lambda url, **kw: _FakeResp(content=png))

    res = client.get("/proxy/image", params={"url": "https://urlscan.io/screenshots/ok.png"})
    assert res.status_code == 200
    assert res.content == png
