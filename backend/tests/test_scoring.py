"""Unit tests for attribution_module/scoring.py — the verdict engine."""

from datetime import datetime, timedelta

from attribution_module.scoring import calculate_score

EICAR_SHA256 = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"


def _days_ago(days: int) -> str:
    """Domain age is scored in bands, so a hardcoded date would drift into a
    different band as months pass — the test would keep passing while quietly
    testing something else."""
    return (datetime.utcnow() - timedelta(days=days)).strftime("%Y-%m-%d")


def test_benign_input_is_clear():
    result = calculate_score({})
    assert result["score"] == 0
    assert result["verdict"] == "Clear"
    assert result["reasons"] == []
    assert result["family"] == "Unknown"


def test_eicar_hash_is_malicious():
    result = calculate_score({"file_hash": EICAR_SHA256})
    assert result["score"] == 100
    assert result["verdict"] == "Malicious"
    assert result["family"] == "EICAR-Test-File"


def test_malwarebazaar_hit_is_malicious():
    result = calculate_score({
        "osint": {"malwarebazaar": {"found": True, "threat_name": "TestThreat", "first_seen": "2024"}},
    })
    assert result["score"] == 100
    assert result["verdict"] == "Malicious"
    assert any("MalwareBazaar" in r for r in result["reasons"])


def test_flagged_registrar_is_reported_but_not_scored():
    """Measured at 6.8% of the Tranco top 10,000, every hit Namecheap.

    The list is also incoherent — Namecheap is flagged, GoDaddy is not, though it
    is larger and at least as abused. It cannot carry points, but an analyst
    still wants to see who the domain was registered through.
    """
    result = calculate_score({
        "osint": {"whois": {"registrar": "NameCheap, Inc."}},
    })
    assert result["score"] == 0
    assert result["verdict"] == "Clear"
    assert any("Registrar" in r for r in result["reasons"]), \
        "registrar must still appear in the report as context"


def test_budget_hosting_is_weak_but_bulletproof_hosting_is_not():
    """OVH and M247 are mainstream; Media Land exists to ignore abuse reports."""
    budget = calculate_score({
        "osint": {"geoip": {"countryCode": "RU", "country": "Russia", "asn": "AS9009 M247 Ltd"}},
    })
    bulletproof = calculate_score({
        "osint": {"geoip": {"countryCode": "RU", "country": "Russia",
                            "asn": "AS206728 Media Land LLC"}},
    })
    # country 5 + budget 5 — nowhere near the 35-point Suspicious threshold
    assert budget["score"] == 10
    assert budget["verdict"] == "Clear"
    assert bulletproof["score"] > budget["score"]


def test_country_alone_barely_moves_the_score():
    """8.3% of the top 10,000 sit in a listed country, and for CDN-fronted sites
    the field reports an anycast edge rather than the host. Geography is not
    evidence."""
    result = calculate_score({
        "osint": {"geoip": {"countryCode": "CN", "country": "China"}},
    })
    assert result["score"] == 5
    assert result["verdict"] == "Clear"


def test_url_flags_push_to_suspicious():
    result = calculate_score({
        "url": {"suspicious_flags": ["flag one", "flag two"]},
    })
    assert result["score"] >= 40
    assert result["verdict"] == "Suspicious"


def test_dangerous_apk_permissions_score():
    """The SMS read+send combo scores; it is a pattern, not a headcount."""
    result = calculate_score({
        "apk": {
            "is_apk": True,
            "dangerous_permissions": [
                "android.permission.READ_SMS",
                "android.permission.SEND_SMS",
                "android.permission.READ_CONTACTS",
            ],
        },
    })
    assert result["score"] >= 15
    assert any("SMS" in r for r in result["reasons"])


def test_apk_permission_volume_alone_does_not_score():
    """Counting dangerous permissions measures app complexity, not malice.

    Every real messaging app requests camera, microphone, contacts, location and
    storage. The old `count >= 5 → +35` rule put a legitimate SMS app and an
    SMS-stealing trojan at the same score off byte-identical permission sets, so
    volume now carries no weight — while the report still lists what was asked
    for, because suppressing the score is not a reason to suppress the context.
    """
    result = calculate_score({
        "apk": {
            "is_apk": True,
            "dangerous_permissions": [
                "android.permission.CAMERA",
                "android.permission.RECORD_AUDIO",
                "android.permission.READ_CONTACTS",
                "android.permission.ACCESS_FINE_LOCATION",
                "android.permission.READ_EXTERNAL_STORAGE",
                "android.permission.READ_PHONE_STATE",
            ],
        },
    })
    assert result["score"] == 0
    assert result["verdict"] == "Clear"
    assert any("sensitive permission" in r for r in result["reasons"]), \
        "permissions must still be reported as context even when they score nothing"


def test_apk_critical_permission_scores_alone():
    """A rare capability carries weight a pile of ordinary ones does not."""
    result = calculate_score({
        "apk": {
            "is_apk": True,
            "dangerous_permissions": ["android.permission.BIND_DEVICE_ADMIN"],
        },
    })
    assert result["verdict"] == "Suspicious"
    assert any("BIND_DEVICE_ADMIN" in r for r in result["reasons"])


def test_apk_banking_overlay_combo():
    """Overlay + accessibility together is the banking-trojan credential-capture
    pattern, and is worth more than either permission on its own."""
    combo = calculate_score({
        "apk": {
            "is_apk": True,
            "dangerous_permissions": [
                "android.permission.SYSTEM_ALERT_WINDOW",
                "android.permission.BIND_ACCESSIBILITY_SERVICE",
            ],
        },
    })
    overlay_only = calculate_score({
        "apk": {
            "is_apk": True,
            "dangerous_permissions": ["android.permission.SYSTEM_ALERT_WINDOW"],
        },
    })
    assert combo["score"] > overlay_only["score"]
    assert any("banking-overlay" in r for r in combo["reasons"])


def test_ordinary_pdf_with_forms_is_clear():
    """Regression: a textbook/form PDF (JS + open-action, clean VT) must NOT be flagged.

    Real-world bug: scored 90/Malicious for an ordinary textbook PDF because
    /JavaScript (+40) and /OpenAction (+35) were treated as malware signals
    while a 62-engine clean VirusTotal result was ignored.
    """
    result = calculate_score({
        "document": {
            "doc_type": "pdf",
            "has_javascript": True,      # interactive form JS
            "has_auto_action": True,     # "open at page 1"
            "has_js_auto_combo": False,  # NOT wired together
        },
        "osint": {"virustotal": {"stats": {"malicious": 0, "suspicious": 0, "harmless": 0, "undetected": 62}}},
    })
    assert result["verdict"] == "Clear", f"benign PDF flagged: {result['score']} {result['reasons']}"


def test_driveby_pdf_combo_is_flagged():
    result = calculate_score({
        "document": {
            "doc_type": "pdf",
            "has_javascript": True,
            "has_auto_action": True,
            "has_js_auto_combo": True,   # JS bound directly to OpenAction
            "has_launch_action": True,
        },
    })
    assert result["score"] >= 70
    assert result["verdict"] == "Malicious"


def test_vt_clean_does_not_dampen_confirmed_intel():
    """A MalwareBazaar hash hit must stay Malicious even if VT engines miss it."""
    result = calculate_score({
        "osint": {
            "malwarebazaar": {"found": True, "threat_name": "FreshThreat", "first_seen": "2026"},
            "virustotal": {"stats": {"malicious": 0, "suspicious": 0, "harmless": 0, "undetected": 62}},
        },
    })
    assert result["score"] >= 70
    assert result["verdict"] == "Malicious"


def test_output_contract_keys():
    """Both frontends consume this exact shape — guard it."""
    result = calculate_score({"iocs": {"ips": ["1.2.3.4"], "domains": ["x.com"], "urls": []}})
    for key in ("score", "verdict", "family", "attribution", "reasons",
                "indicators", "osint_summary", "graph_nodes", "graph_edges", "partial"):
        assert key in result
    assert result["indicators"]["ips"] == ["1.2.3.4"]


# ── Weak-IOC corroboration cap ────────────────────────────────────────────────

def test_lone_embedded_ioc_intel_capped_at_suspicious():
    """Regression (the example.com 'Appleseed' case): a single 75%-confidence
    ThreatFox hit on a domain EMBEDDED in an uploaded file must not alone reach
    Malicious — cap it at Suspicious."""
    result = calculate_score({
        "file_hash": "deadbeef",
        "iocs": {"domains": ["appleseed.example"]},
        "osint": {"threatfox": {"found": True, "confidence": 75,
                                "malware_printable": "Appleseed",
                                "matched_ioc": "appleseed.example"}},
    })
    assert result["verdict"] == "Suspicious"
    assert result["score"] < 70
    assert any("capped at Suspicious" in r for r in result["reasons"])


def test_embedded_ioc_intel_with_hash_corroboration_stays_malicious():
    """Same weak hit, but a MalwareBazaar hash match corroborates it → Malicious."""
    result = calculate_score({
        "file_hash": "deadbeef",
        "osint": {
            "threatfox": {"found": True, "confidence": 75, "malware_printable": "X",
                          "matched_ioc": "appleseed.example"},
            "malwarebazaar": {"found": True, "threat_name": "Real", "first_seen": "2026"},
        },
    })
    assert result["verdict"] == "Malicious"
    assert result["score"] >= 70


def test_threatfox_hash_match_is_full_weight():
    """A ThreatFox match on the FILE HASH (not an embedded IOC) is authoritative
    hash-based evidence — never capped."""
    result = calculate_score({
        "file_hash": "deadbeef",
        "osint": {"threatfox": {"found": True, "confidence": 75, "malware_printable": "X",
                                "matched_ioc": "deadbeef"}},
    })
    assert result["verdict"] == "Malicious"


def test_url_submission_ioc_intel_not_capped():
    """For a submitted URL the URL IS the artifact, so a URLhaus/ThreatFox hit on
    it is primary evidence — the embedded-IOC cap must not fire."""
    result = calculate_score({
        "submitted_url": "http://evil.example/x",
        "iocs": {"urls": ["http://evil.example/x"]},
        "osint": {
            "threatfox": {"found": True, "confidence": 100, "malware_printable": "Y",
                          "matched_ioc": "http://evil.example/x"},
            "urlhaus": {"found": True, "threat": "malware_download",
                        "matched_url": "http://evil.example/x"},
        },
    })
    assert result["verdict"] == "Malicious"
    assert result["score"] >= 70
    assert not any("capped at Suspicious" in r for r in result["reasons"])


def test_infrastructure_alone_cannot_reach_malicious():
    """Context is not a verdict about the artifact.

    A five-day-old domain on a bulletproof ASN with a cheap registrar used to
    reach 95 — while nothing about the artifact had been examined. Every
    legitimate business registered last week on budget hosting looks identical.

    Two independent defences now hold this down: the weights themselves (measured
    in tests/live/base_rates.py) and the artifact-evidence rule. This asserts the
    outcome, not which of the two did the work.
    """
    result = calculate_score({
        "osint": {
            "geoip": {"countryCode": "RU", "country": "Russia",
                      "asn": "AS206728 Media Land LLC", "isp": "Media Land LLC"},
            "whois": {"creation_date": _days_ago(5), "registrar": "Reg.ru LLC"},
        },
    })
    assert result["verdict"] != "Malicious"
    # Down-weighted, not suppressed — the findings still reach the report.
    assert any("high-risk country" in r for r in result["reasons"])
    assert any("bulletproof" in r for r in result["reasons"])
    assert any("Registrar" in r for r in result["reasons"])


def test_ordinary_new_business_is_clear():
    """The other side of the same coin: a company that registered its domain last
    week through a budget registrar and put it behind Cloudflare is what every new
    legitimate business looks like on day one."""
    result = calculate_score({
        "osint": {
            "geoip": {"countryCode": "US", "country": "United States",
                      "asn": "AS13335 Cloudflare, Inc.", "isp": "Cloudflare, Inc."},
            "whois": {"creation_date": _days_ago(5), "registrar": "NameCheap, Inc."},
        },
    })
    assert result["verdict"] == "Clear", result["reasons"]


def test_artifact_evidence_still_reaches_malicious():
    """The cap keys on where evidence came from, not how much there is.

    A PDF that runs JavaScript on open and can launch a program is a finding
    about the submitted file itself, so it is free to reach Malicious even
    though no threat-intel feed has ever heard of it.
    """
    result = calculate_score({
        "document": {
            "doc_type": "pdf",
            "has_javascript": True,
            "has_auto_action": True,
            "has_js_auto_combo": True,
            "has_launch_action": True,
        },
    })
    assert result["verdict"] == "Malicious"
    assert not any("capped at Suspicious" in r for r in result["reasons"])


def test_partial_intel_flag_surfaced():
    """A scan whose VT lookup didn't complete is tagged partial and says so."""
    assert calculate_score({"osint": {}})["partial"] is False
    partial = calculate_score({"intel_partial": True, "osint": {}})
    assert partial["partial"] is True
    assert any("incomplete" in r.lower() for r in partial["reasons"])


def test_partial_intel_downgrades_clear_to_inconclusive():
    """With nothing found AND the verdict-critical source missing, we cannot tell
    'nothing is wrong' from 'we could not check' — so it must not read as Clear."""
    assert calculate_score({"osint": {}})["verdict"] == "Clear"
    partial = calculate_score({"intel_partial": True, "osint": {}})
    assert partial["verdict"] == "Inconclusive"


def test_every_emitted_label_has_an_axis():
    """Every score_breakdown label must map to a radar axis.

    _build_risk_profile silently drops labels missing from _LABEL_TO_AXIS, so an
    unmapped one still renders as a bar in ScoreComposition but disappears from
    RiskRadar — the two views of the same number stop agreeing, with nothing
    failing to say so. ("Weak-IOC Corroboration Cap" was unmapped for exactly
    that reason.)

    Reads the labels back out of the source rather than from a hand-kept list,
    so adding a record() call with a new label fails here until it is mapped.
    """
    import ast
    import inspect

    from attribution_module import scoring

    tree = ast.parse(inspect.getsource(scoring))
    emitted = {
        node.args[0].value
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "record"
        and node.args
        and isinstance(node.args[0], ast.Constant)
        and isinstance(node.args[0].value, str)
    }

    assert emitted, "found no record() calls — the AST scan needs updating"

    unmapped = sorted(emitted - set(scoring._LABEL_TO_AXIS))
    assert not unmapped, (
        f"score_breakdown label(s) with no radar axis: {unmapped}. "
        "Add them to _LABEL_TO_AXIS or they vanish from the risk profile."
    )


# ── Anycast CDNs: the country field describes an edge, not the host ───────────

def test_cdn_fronted_host_does_not_claim_a_country():
    """Measured on 237 popular sites: Canada was the most common country at 71,
    of which 63 were Cloudflare and 6 Fastly. None of those sites are Canadian.

    The report was stating a location it could not know — including telling a
    user an Indian bank was hosted in Canada.
    """
    result = calculate_score({
        "osint": {"geoip": {"countryCode": "CA", "country": "Canada",
                            "asn": "AS13335 Cloudflare, Inc.", "isp": "Cloudflare, Inc."}},
    })
    joined = " ".join(result["reasons"])
    assert "Cloudflare" in joined and "not the host" in joined
    assert "high-risk country" not in joined
    assert result["osint_summary"]["anycast_cdn"] == "Cloudflare"


def test_cdn_in_a_listed_country_is_not_scored_on_geography():
    """A Cloudflare edge answering from Russia says nothing about the origin."""
    result = calculate_score({
        "osint": {"geoip": {"countryCode": "RU", "country": "Russia",
                            "asn": "AS13335 Cloudflare, Inc.", "isp": "Cloudflare"}},
    })
    assert result["score"] == 0, result["reasons"]


def test_direct_hosting_still_reports_its_country():
    """The fix must not blind the check where geolocation is meaningful."""
    result = calculate_score({
        "osint": {"geoip": {"countryCode": "RU", "country": "Russia",
                            "asn": "AS206728 Media Land LLC", "isp": "Media Land LLC"}},
    })
    joined = " ".join(result["reasons"])
    assert "high-risk country" in joined
    assert "bulletproof" in joined
    assert result["osint_summary"]["anycast_cdn"] is None
