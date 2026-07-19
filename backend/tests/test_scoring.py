"""Unit tests for attribution_module/scoring.py — the verdict engine."""

from attribution_module.scoring import calculate_score

EICAR_SHA256 = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"


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


def test_flagged_registrar_raises_score():
    result = calculate_score({
        "osint": {"whois": {"registrar": "NameCheap, Inc."}},
    })
    assert result["score"] >= 15
    assert any("Registrar" in r for r in result["reasons"])


def test_high_risk_country_and_asn():
    result = calculate_score({
        "osint": {"geoip": {"countryCode": "RU", "country": "Russia", "asn": "AS9009 M247 Ltd"}},
    })
    # +20 country, +20 suspicious ASN
    assert result["score"] >= 40
    assert result["verdict"] in ("Suspicious", "Malicious")


def test_url_flags_push_to_suspicious():
    result = calculate_score({
        "url": {"suspicious_flags": ["flag one", "flag two"]},
    })
    assert result["score"] >= 40
    assert result["verdict"] == "Suspicious"


def test_dangerous_apk_permissions_score():
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
    # 3 dangerous perms (+20) and SMS read+send combo (+15)
    assert result["score"] >= 35
    assert any("SMS" in r for r in result["reasons"])


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


def test_partial_intel_flag_surfaced():
    """A scan whose VT lookup didn't complete is tagged partial and says so."""
    assert calculate_score({"osint": {}})["partial"] is False
    partial = calculate_score({"intel_partial": True, "osint": {}})
    assert partial["partial"] is True
    assert any("incomplete" in r.lower() for r in partial["reasons"])
