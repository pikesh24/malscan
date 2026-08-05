"""
An internal address is not a C2 server.

`is_reportable_ip` has always rejected private, loopback and reserved ranges, so
a bare `10.0.0.5` never became an indicator. `is_reportable_url` did not apply
the same rule, so `http://10.0.0.5/panel` was accepted — and then scored 25 for
"URL uses a raw IP address instead of a domain — common in C2 and phishing",
which is the identical score a genuine public C2 address receives.

Found by scanning realistic content rather than crafted samples: a
docker-compose file, a README, an internal wiki page naming an admin panel. All
three scored 25 and had the reader's internal addressing published into the
indicator list. Loopback happened to be filtered further down the pipeline,
so the behaviour was inconsistent as well as wrong.

25 does not flip a verdict alone — Suspicious starts at 35 — but it is 25 points
of pure noise on ordinary internal documentation, and two more weak signals push
it over.
"""

import io

import pytest

from analysis_engine.static_analyzer import is_reportable_url

# Documentation and reserved ranges are NOT usable as the "genuine public IP"
# case. 198.51.100.0/24 is TEST-NET-2 (RFC 5737) and 203.0.113.0/24 is
# TEST-NET-3; both are correctly rejected as reserved, which cost one iteration
# of this test to work out. 8.8.8.8 is genuinely routable.
PUBLIC_IP = "8.8.8.8"


def _scan(client, payload: bytes, name: str) -> dict:
    res = client.post("/upload",
                      files={"file": (name, io.BytesIO(payload), "text/plain")})
    assert res.status_code == 200, res.text
    status = client.get(f"/status/{res.json()['job_id']}").json()
    assert status["status"] == "Completed"
    return status["results"]


def _url_points(results: dict) -> int:
    for entry in results.get("score_breakdown") or []:
        if entry["label"] == "URL Anomalies":
            return entry["points"]
    return 0


# ── The policy itself ────────────────────────────────────────────────────────

@pytest.mark.parametrize("url", [
    "http://192.168.1.10/admin",
    "http://192.168.1.10:5000/health",
    "http://10.0.0.5/panel",
    "http://172.16.0.1/",
    "http://127.0.0.1:8080/x",
    "http://169.254.169.254/latest/meta-data/",
])
def test_urls_pointing_at_non_routable_addresses_are_not_indicators(url):
    assert is_reportable_url(url) is False, f"{url} was accepted as an indicator"


@pytest.mark.parametrize("url", [
    f"http://{PUBLIC_IP}/panel",
    "https://1.1.1.1/",
    "https://example.com/guide",
    "http://sub.domain.example/path",
])
def test_genuinely_routable_urls_are_still_indicators(url):
    assert is_reportable_url(url) is True, f"{url} was wrongly filtered out"


def test_the_url_policy_agrees_with_the_ip_policy():
    """The two must not disagree — that disagreement was the bug."""
    from analysis_engine.static_analyzer import is_reportable_ip

    for ip in ("192.168.1.10", "10.0.0.5", "127.0.0.1", "172.16.0.1", PUBLIC_IP, "1.1.1.1"):
        assert is_reportable_url(f"http://{ip}/x") == is_reportable_ip(ip), (
            f"policies disagree on {ip}"
        )


# ── Realistic content must not score ─────────────────────────────────────────

@pytest.mark.parametrize("name,body", [
    ("docker-compose", b"services:\n  api:\n    url: http://192.168.1.10:5000/health\n"),
    ("internal wiki", b"The admin panel is at http://192.168.1.10/admin (VPN only).\n"),
    ("dev readme", b"Run the server, then open http://127.0.0.1:8080/ in your browser.\n"),
    ("lan notes", b"Printer at http://10.0.0.5/status and NAS at http://10.0.0.9/\n"),
], ids=["docker-compose", "wiki", "readme", "lan-notes"])
def test_ordinary_internal_documentation_scores_nothing(client, name, body):
    results = _scan(client, body, f"{name.replace(' ', '-')}.txt")

    assert _url_points(results) == 0, (
        f"{name} scored {_url_points(results)} on URL Anomalies for referencing an "
        f"internal address"
    )


def test_internal_addresses_are_not_published_as_indicators(client):
    """A shared report should not carry the reader's internal addressing."""
    results = _scan(client, b"Admin at http://192.168.1.10/admin\n", "internal.txt")

    urls = (results.get("indicators") or {}).get("urls") or []
    assert not any("192.168" in u for u in urls), f"internal address leaked: {urls}"


# ── The detection that must survive ──────────────────────────────────────────

def test_a_public_raw_ip_url_still_scores(client):
    """The overcorrection guard: this check exists for a reason and must keep
    firing on genuinely routable addresses."""
    results = _scan(client, f"C2 observed at http://{PUBLIC_IP}/panel\n".encode(), "c2.txt")

    assert _url_points(results) > 0, "a raw public IP URL stopped being flagged"
    urls = (results.get("indicators") or {}).get("urls") or []
    assert any(PUBLIC_IP in u for u in urls)


def test_a_mixed_file_keeps_the_public_address_and_drops_the_private_one(client):
    results = _scan(
        client,
        f"internal http://192.168.1.10/admin and external http://{PUBLIC_IP}/panel\n".encode(),
        "mixed.txt",
    )

    urls = " ".join((results.get("indicators") or {}).get("urls") or [])
    assert PUBLIC_IP in urls, "the routable address was dropped"
    assert "192.168" not in urls, "the internal address was kept"
