"""
WHOIS / DNS / GeoIP field mapping.

Every infrastructure weight set in phase B reads one of these fields, and the
weights were measured through this exact code — so a renamed or dropped key
silently invalidates the measurement rather than raising anything. `creation_date`
in particular has to arrive in a form `_parse_age_days` can read: it silently
returned an age of ~205 days for a five-day-old domain until this session,
because the parser sliced dates by the length of the format string.

The functions are network calls, so the transports are stubbed and only the
mapping is exercised.
"""

import pytest

from analysis_engine import osint_enricher


class _Resp:
    def __init__(self, payload, status=200):
        self._payload, self.status_code = payload, status

    def json(self):
        return self._payload


class _Whois(dict):
    """python-whois returns an attribute-accessible dict-like object."""
    def __getattr__(self, item):
        try:
            return self[item]
        except KeyError:
            raise AttributeError(item)


# ── WHOIS ─────────────────────────────────────────────────────────────────────

def test_registrar_and_creation_date_are_mapped(monkeypatch):
    monkeypatch.setattr(osint_enricher.whois, "whois", lambda d: _Whois(
        registrar="NameCheap, Inc.",
        creation_date="2020-01-15 10:30:00",
        expiration_date="2027-01-15 10:30:00",
        emails=["abuse@namecheap.com"],
    ))
    out = osint_enricher.get_whois("example.com")
    assert out["registrar"] == "NameCheap, Inc."
    assert "2020-01-15" in out["creation_date"]


def test_creation_date_survives_in_a_parseable_form(monkeypatch):
    """The date has to reach _parse_age_days in a shape it can read — the whole
    domain-age signal was dead because that contract was never checked."""
    from attribution_module.scoring import _parse_age_days

    monkeypatch.setattr(osint_enricher.whois, "whois", lambda d: _Whois(
        registrar="R", creation_date="2026-07-20 10:30:00",
        expiration_date="", emails=[],
    ))
    age = _parse_age_days(osint_enricher.get_whois("x.example")["creation_date"])
    assert age is not None and age < 400, f"creation_date not parseable, got age {age}"


def test_registries_returning_a_list_of_dates_are_handled(monkeypatch):
    """Several registries return a list; taking the raw list would stringify to
    "[datetime(...), datetime(...)]" and never parse."""
    monkeypatch.setattr(osint_enricher.whois, "whois", lambda d: _Whois(
        registrar="R",
        creation_date=["2019-05-01 00:00:00", "2019-05-02 00:00:00"],
        expiration_date=["2028-05-01 00:00:00"], emails=[],
    ))
    out = osint_enricher.get_whois("x.example")
    assert out["creation_date"].startswith("2019-05-01"), \
        f"list-valued creation_date not unwrapped: {out['creation_date']!r}"


def test_whois_failure_is_an_error_not_an_empty_domain(monkeypatch):
    """A WHOIS server refusing the connection is common (.gov, several ccTLDs).
    It must not read as 'this domain has no registrar and no age'."""
    def boom(_):
        raise ConnectionError("socket closed")
    monkeypatch.setattr(osint_enricher.whois, "whois", boom)
    out = osint_enricher.get_whois("x.gov")
    assert "error" in out
    assert not out.get("registrar")


# ── GeoIP ─────────────────────────────────────────────────────────────────────

def test_geoip_fields_are_mapped(monkeypatch):
    payload = {
        "status": "success", "country": "Russia", "countryCode": "RU",
        "isp": "Media Land LLC", "org": "Media Land",
        "as": "AS206728 Media Land LLC", "lat": 55.7, "lon": 37.6,
        "city": "Moscow", "regionName": "Moscow",
    }
    monkeypatch.setattr(osint_enricher.requests, "get", lambda *a, **k: _Resp(payload))
    out = osint_enricher.get_geoip("203.0.113.1")

    # scoring reads countryCode and asn; renaming either silently disables the
    # country and hosting checks measured in phase B.
    assert out["countryCode"] == "RU"
    assert out["asn"] == "AS206728 Media Land LLC"
    assert out["isp"] == "Media Land LLC"
    assert out["city"] == "Moscow" and out["region"] == "Moscow"


def test_anycast_asn_reaches_the_scorer(monkeypatch):
    """The Cloudflare fix keys on the ASN string arriving intact."""
    from attribution_module.scoring import _anycast_provider

    monkeypatch.setattr(osint_enricher.requests, "get", lambda *a, **k: _Resp({
        "status": "success", "country": "Canada", "countryCode": "CA",
        "isp": "Cloudflare, Inc.", "as": "AS13335 Cloudflare, Inc.",
    }))
    assert _anycast_provider(osint_enricher.get_geoip("203.0.113.2")["asn"]) == "Cloudflare"


def test_geoip_failure_status_is_an_error(monkeypatch):
    """ip-api returns HTTP 200 with status:fail for a reserved address."""
    monkeypatch.setattr(osint_enricher.requests, "get", lambda *a, **k: _Resp(
        {"status": "fail", "message": "reserved range"}))
    out = osint_enricher.get_geoip("10.0.0.1")
    assert "error" in out
    assert not out.get("countryCode")


def test_geoip_network_failure_is_an_error(monkeypatch):
    def boom(*a, **k):
        raise TimeoutError("no route")
    monkeypatch.setattr(osint_enricher.requests, "get", boom)
    assert "error" in osint_enricher.get_geoip("203.0.113.3")


# ── DNS ───────────────────────────────────────────────────────────────────────

def test_dns_returns_all_record_types(monkeypatch):
    class _RD:
        def __init__(self, text):
            self._t = text

        def to_text(self):
            return self._t

    def resolve(domain, rtype, **kw):
        return {"A": [_RD("93.184.216.34")],
                "MX": [_RD("10 mail.example.com.")],
                "TXT": [_RD('"v=spf1 -all"')]}[rtype]

    monkeypatch.setattr(osint_enricher.dns.resolver, "resolve", resolve)
    out = osint_enricher.get_dns_records("example.com")
    assert out["A"] == ["93.184.216.34"]
    assert out["MX"] and out["TXT"]


def test_missing_record_types_are_empty_not_missing(monkeypatch):
    """A domain with no MX is normal; the key must still exist so the report and
    scorer can read it without guarding every access."""
    def resolve(domain, rtype, **kw):
        raise Exception("NXDOMAIN")

    monkeypatch.setattr(osint_enricher.dns.resolver, "resolve", resolve)
    out = osint_enricher.get_dns_records("example.com")
    assert out == {"A": [], "MX": [], "TXT": []}
