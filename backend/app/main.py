"""
backend/app/main.py

FastAPI application: file-upload and URL-submission endpoints, the scan
pipeline (process_scan_job), and the status / report endpoints.
"""

import hashlib, os, re, uuid, sys, time, zipfile, tempfile, shutil
import asyncio
from collections import defaultdict, deque

# Windows Playwright fix: use ProactorEventLoop for subprocess support
if sys.platform == "win32":
    asyncio.set_event_loop_policy(asyncio.WindowsProactorEventLoopPolicy())
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta
from urllib.parse import urlparse, urlunparse
import requests

# ── Safety limits ─────────────────────────────────────────────────────────────
MAX_UPLOAD_BYTES      = 50  * 1024 * 1024   # 50 MB hard cap
# Budgets for the WHOLE archive tree, not per archive — see _new_archive_scan().
MAX_DECOMPRESSED_BYTES = 200 * 1024 * 1024  # 200 MB total decompressed
MAX_ZIP_FILE_COUNT    = 500                  # files extracted across all nesting
MAX_ARCHIVE_DEPTH     = 3                    # archive layers opened (zip-in-zip-in-zip)
MAX_INNER_INTEL_LOOKUPS = 8                  # rate-limited hash lookups on members
MAX_INNER_READ_BYTES  = 25 * 1024 * 1024     # hold a member in memory below this
_ARCHIVE_COPY_CHUNK   = 1024 * 1024
MAX_URL_LENGTH        = 2048                 # /submit-url input cap
RATE_LIMIT_MAX        = 30                   # submissions per window per client IP
RATE_LIMIT_WINDOW_S   = 60
from dotenv import load_dotenv
from fastapi import BackgroundTasks, FastAPI, UploadFile, File, Form, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from fastapi.responses import HTMLResponse, Response
from .database import SessionLocal, init_db
from .models import ScanJob
from .security import sanitize_filename, cleanup_vault

# Load .env from backend directory
load_dotenv(os.path.join(os.path.dirname(__file__), '..', '.env'))

# analysis_engine/ and attribution_module/ live one level up (in backend/), as
# siblings of this app/ package — add backend/ to sys.path so they import.
backend_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
if backend_dir not in sys.path:
    sys.path.insert(0, backend_dir)

try:
    from analysis_engine.static_analyzer import (
        extract_iocs, analyze_pe, analyze_suspicious_strings,
        is_reportable_ip, is_reportable_url,
    )
    from analysis_engine.osint_enricher import get_whois, get_dns_records, get_geoip
    from analysis_engine.url_processor import analyze_url
    from analysis_engine.public_suffix import public_suffix
    from analysis_engine.vt_client import get_url_report, get_file_report
    from analysis_engine.urlscan_client import scan_url as urlscan_scan
    from analysis_engine.resource_chain import (
        analyze as analyze_resource_chain,
        select_for_reputation as select_resource_lookups,
    )
    from analysis_engine.apk_analyzer import analyze_apk
    from analysis_engine.document_analyzer import analyze_document
    from analysis_engine.lnk_analyzer import analyze_lnk
    from analysis_engine.html_analyzer import analyze_html
    from analysis_engine.extension_analyzer import analyze_extension
    from analysis_engine.script_analyzer import analyze_script
    from analysis_engine.yara_scanner import scan_file as yara_scan_file
    from analysis_engine.malwarebazaar_client import check_hash as mb_check_hash
    from analysis_engine.threatfox_client import check_iocs as tf_check_iocs
    from analysis_engine.urlhaus_client import check_urls as uh_check_urls
    from analysis_engine.abuseipdb_client import check_ips as ab_check_ips
    from attribution_module.scoring import calculate_score
    from attribution_module.clustering import cluster_iocs
    from attribution_module.reporter import generate_report, get_report_path
except ImportError as e:
    print(f"Warning: Module import failed: {e}")

from .indicator_index import lookup_prior_jobs, index_job_indicators, backfill_indicator_index

app = FastAPI()

# CORS: default to local dev origins; override with a comma-separated
# MALSCAN_ALLOWED_ORIGINS env var in production (e.g. "https://malscan.example").
# Safe to keep strict — the web frontend reaches the API same-origin through the
# Next.js /api rewrite, and the mobile app is a native client (not subject to
# CORS). Set MALSCAN_ALLOWED_ORIGINS="*" to explicitly opt back into wildcard.
_allowed_origins_env = os.environ.get("MALSCAN_ALLOWED_ORIGINS", "").strip()
if _allowed_origins_env == "*":
    _allowed_origins = ["*"]
elif _allowed_origins_env:
    _allowed_origins = [o.strip() for o in _allowed_origins_env.split(",") if o.strip()]
else:
    _allowed_origins = ["http://localhost:3000", "http://127.0.0.1:3000"]

app.add_middleware(
    CORSMiddleware,
    allow_origins=_allowed_origins,
    allow_credentials=False,
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)

# Overridable so tests (and future cloud deploys) can isolate their artifacts.
VAULT_DIR = os.environ.get("MALSCAN_VAULT_DIR", "app/vault")
os.makedirs(VAULT_DIR, exist_ok=True)
VAULT_RETENTION_DAYS = int(os.environ.get("MALSCAN_VAULT_RETENTION_DAYS", "30"))
# Hard ceiling on stored artifacts. Retention alone bounds nothing over a short
# window: at the submission limit a single client can write gigabytes in minutes,
# and none of it is eligible for age-based deletion for weeks.
VAULT_MAX_BYTES = int(os.environ.get("MALSCAN_VAULT_MAX_BYTES", str(2 * 1024 * 1024 * 1024)))
cleanup_vault(VAULT_DIR, days_old=VAULT_RETENTION_DAYS)
# This used to be the only call, at import. A process that stays up for ninety
# days accumulated ninety days of artifacts, because nothing ran it again.
_last_vault_sweep = time.monotonic()
VAULT_SWEEP_INTERVAL_S = 3600


def _vault_bytes() -> int:
    total = 0
    with os.scandir(VAULT_DIR) as entries:
        for entry in entries:
            if entry.is_file():
                try:
                    total += entry.stat().st_size
                except OSError:
                    pass
    return total


def _maintain_vault() -> None:
    """Sweep on a timer, and refuse new writes once the vault is over budget."""
    global _last_vault_sweep
    now = time.monotonic()
    if now - _last_vault_sweep >= VAULT_SWEEP_INTERVAL_S:
        _last_vault_sweep = now
        try:
            cleanup_vault(VAULT_DIR, days_old=VAULT_RETENTION_DAYS)
        except Exception as exc:
            print(f"Vault sweep failed: {exc}")
    if _vault_bytes() > VAULT_MAX_BYTES:
        raise HTTPException(
            status_code=507,
            detail="The scanner is out of storage for new submissions. Try again later.",
        )

# ── Rate limiting (in-memory, per client IP) ──────────────────────────────────
_submission_log: dict = defaultdict(deque)
# Only swept once the table is larger than a plausible number of real clients,
# so the common case stays a dict insert and nothing more.
_SUBMISSION_LOG_MAX_IPS = 10_000

def _enforce_rate_limit(request: Request) -> None:
    """Sliding-window limiter for submission endpoints. Raises 429 when exceeded.

    In-process and per-worker: N workers means N times the stated limit, and a
    restart forgets everything. A shared store (Redis) is the real answer and is
    not free, so this is a speed bump rather than a control — see docs.
    """
    client_ip = request.client.host if request.client else "unknown"
    now = time.monotonic()
    log = _submission_log[client_ip]
    while log and now - log[0] > RATE_LIMIT_WINDOW_S:
        log.popleft()
    if len(log) >= RATE_LIMIT_MAX:
        raise HTTPException(
            status_code=429,
            detail=f"Too many submissions — limit is {RATE_LIMIT_MAX} per minute. Please wait and try again.",
        )
    log.append(now)
    # Every distinct source IP allocated a deque that was never reclaimed, so the
    # limiter's own bookkeeping grew without bound — a slow leak on a public
    # endpoint, and reachable by anyone able to vary a source address. Drop the
    # entries that have aged out entirely.
    if len(_submission_log) > _SUBMISSION_LOG_MAX_IPS:
        for ip in [ip for ip, entries in _submission_log.items() if not entries]:
            del _submission_log[ip]

# ── Indicator policy ──────────────────────────────────────────────────────────
# These were one list, and merging them caused a false negative: a document whose
# only malicious link pointed at raw.githubusercontent.com produced a report
# reading "no network indicators extracted", because allow-listed indicators were
# DELETED. That handed anyone a published list of domains to host payloads on and
# stay invisible. The two kinds of entry need opposite treatment.

# Boilerplate identifiers. Not destinations — they name an XML schema or are
# reserved by RFC 2606. Every Office and PDF file embeds several. Nothing is ever
# hosted at them, so deleting them outright is correct and keeps reports readable.
NAMESPACE_IDENTIFIERS = {
    "w3.org", "xmlsoap.org", "openxmlformats.org", "xml.org",
    "schemas.microsoft.com", "schemas.android.com",
    "purl.org", "dublincore.org", "ns.adobe.com", "java.sun.com",
    "example.com", "example.net", "example.org", "example.edu",
    "localhost", "127.0.0.1", "0.0.0.0", "::1",
}

# Real platforms with real content. A bare reference to one carries no threat —
# and low-quality feeds do tag them (malware configs ping google.com as a
# connectivity check, which once scored google.com itself as Malicious). But they
# host arbitrary user uploads, so reputation covers WHO RUNS THE DOMAIN and never
# an arbitrary path someone else put there. github.com is trustworthy;
# github.com/<anyone>/<anything> is a stranger's file.
REPUTABLE_HOSTS = {
    "google.com", "googleapis.com", "gstatic.com", "microsoft.com",
    "apple.com", "adobe.com", "oracle.com", "sun.com",
    "mozilla.org", "mozilla.com", "webkit.org", "apache.org",
    "github.com", "githubusercontent.com", "verisign.com",
}


def _host_matches(host: str, patterns: set) -> bool:
    """Exact host or a subdomain of one. Anchored to the end deliberately —
    substring matching is what made every brand subdomain look like a typosquat,
    and here it would let `google.com.evil.tk` inherit Google's reputation.

    Entries that are themselves public suffixes are refused. 120 of the Tranco
    top 10,000 are shared-hosting suffixes — `github.io` at rank 115,
    `workers.dev` at 93, `blogspot.com` at 111 — so anything built from
    popularity will eventually contain one. Suffix-matching on `github.io` would
    trust every page a stranger uploads there, which is precisely where phishing
    is hosted. `raw.githubusercontent.com` stays trusted because
    `githubusercontent.com` is a registrable domain GitHub owns, not a suffix
    others can register under.
    """
    host = (host or "").lower().split(":")[0]
    for p in patterns:
        if host != p and not host.endswith("." + p):
            continue
        if host != p and public_suffix(p) == p:
            continue  # p is shared hosting; a tenant under it is not p
        return True
    return False


def _url_host(url: str) -> str:
    """Host of a URL, tolerating the scheme-less forms that reach the IOC set.

    `iocs["domains"]` holds bare hosts and extraction sometimes yields
    `github.com/x/p.exe` with no scheme, which urlparse reads as all-path.
    """
    try:
        parsed = urlparse(url)
        if parsed.netloc:
            return parsed.netloc
        return (url or "").split("#", 1)[0].split("?", 1)[0].partition("/")[0]
    except Exception:
        return ""


# Certificate-distribution endpoints: the revocation lists, OCSP responders and
# CA certificates that Authenticode embeds in EVERY code-signed binary
# (crl3.digicert.com/…crl, ocsp.digicert.com, cacerts.digicert.com/…crt). They
# state who signed the file, not what it communicates with — but they were
# extracted as network indicators, so a *properly code-signed* executable
# reported ~19 embedded URLs and was scored for the volume. Signing correctly
# made a file look worse.
#
# Matched by shape rather than by a domain allow-list, deliberately: the hosts
# arrive with trailing DER bytes glued on ("ocsp.digicert.com0", "…RootCA.crt0E")
# so exact-domain matching misses them. This is narrower than "reputable host" —
# a payload hosted on a legitimate domain is still reported, which is a
# distinction the surrounding code already protects.
_CERT_HOST_RE = re.compile(r"^https?://(?:ocsp|crl\d*|cacerts?|pki|certs?)[.\-]", re.I)
_CERT_PATH_RE = re.compile(r"\.(?:crl|crt|cer|p7[bc])", re.I)


def _is_certificate_infrastructure(url: str) -> bool:
    """True for a code-signing certificate/revocation endpoint."""
    if not url:
        return False
    return bool(_CERT_HOST_RE.match(url)) or bool(_CERT_PATH_RE.search(url))


def _is_namespace_identifier(value: str) -> bool:
    """Boilerplate with nothing behind it — safe to delete from the report."""
    return _host_matches(_url_host(value) or value, NAMESPACE_IDENTIFIERS)


def _is_reputable_host(value: str) -> bool:
    return _host_matches(_url_host(value) or value, REPUTABLE_HOSTS)


def _has_content_path(url: str) -> bool:
    """True when a URL points at something specific rather than just a domain.

    `https://mail.google.com` is a reference to Google. `https://github.com/
    x/releases/download/v1/loader.exe` is a file a stranger uploaded. Only the
    second can be a payload, so only the first is eligible for suppression.
    """
    try:
        parsed = urlparse(url)
        if parsed.netloc:
            return bool((parsed.path or "").strip("/")) or bool(parsed.query)
        # Scheme-less: urlparse puts the whole string in .path, so a bare
        # "google.com" would read as path-bearing. Split by hand instead.
        raw = (url or "").split("#", 1)[0]
        return bool(raw.partition("/")[2].strip("/")) or "?" in raw
    except Exception:
        return False


def _is_suppressible_indicator(value: str) -> bool:
    """True when a threat-intel 'hit' on this indicator should be treated as noise.

    Namespace boilerplate always qualifies. A reputable host qualifies only as a
    bare reference — the moment a path or query is attached, the URL identifies
    content the domain's owner did not put there, and a URLhaus or ThreatFox
    match on it is real evidence that must stand.
    """
    if _is_namespace_identifier(value):
        return True
    return _is_reputable_host(value) and not _has_content_path(value)


def _is_safe_host(host: str) -> bool:
    """Back-compat: host belongs to a namespace identifier or a reputable domain."""
    return _host_matches(host, NAMESPACE_IDENTIFIERS | REPUTABLE_HOSTS)

def _is_safe_url(url: str) -> bool:
    """Returns True if the URL belongs to a known-safe domain."""
    return _is_safe_host(_url_host(url))

def _strip_safe_indicators(iocs: dict, keep: str = None) -> None:
    """Drop known-safe / metadata-namespace indicators from `iocs` in place.

    Every PDF/Office document embeds boilerplate XML-namespace URLs (e.g.
    http://www.w3.org/... and http://ns.adobe.com/...). Left in, these benign
    identifiers get sent to ThreatFox/URLhaus (where a low-confidence match can
    flag the file), resolved to a hosting IP (a misleading "threat origin"), and
    scored as "not HTTPS" URL anomalies. This removes them before any of that.
    `keep` (the deliberately-submitted URL/domain) is always preserved.
    """
    keep_set = set()
    if keep:
        keep_set.add(keep)
        # A submitted URL and the host inside it are the same artifact, but the
        # IOC set holds them as separate entries: "https://github.com/" in urls,
        # "github.com" in domains. Keeping only the literal submitted string left
        # the derived host to be stripped as allow-listed — and WHOIS, DNS and
        # GeoIP are all looked up from domains[0] AFTER this runs, so submitting
        # an allow-listed URL produced a report with no enrichment at all: no
        # registrar, no DNS records, no geolocation, no domain node in the graph.
        try:
            host = urlparse(keep).netloc.split(":")[0]
            if host:
                keep_set.add(host)
        except Exception:
            pass
    # Only boilerplate is deleted. Reputable hosts stay: a link inside a scanned
    # file is the subject of the scan, not noise, and deleting it produced
    # reports that claimed "no network indicators extracted" when there were some.
    # They simply do not attract threat-intel lookups or scoring — see
    # _is_suppressible_indicator.
    iocs["urls"]    = [u for u in (iocs.get("urls") or [])
                       if u in keep_set or (not _is_namespace_identifier(u)
                                            and not _is_certificate_infrastructure(u))]
    iocs["domains"] = [d for d in (iocs.get("domains") or []) if d in keep_set or not _is_namespace_identifier(d)]
    # Loopback/unspecified addresses live in NAMESPACE_IDENTIFIERS — defence in
    # depth alongside is_reportable_ip at extraction time.
    iocs["ips"]     = [i for i in (iocs.get("ips") or [])     if i in keep_set or not _is_namespace_identifier(i)]

def _url_risk(url: str) -> int:
    """Heuristic weight of a URL — the sum of its flag weights.

    analyze_url is pure and does no I/O, so every extracted URL can be scored
    without cost. That is what makes risk-ranking affordable.
    """
    try:
        return sum(analyze_url(url).get("flag_weights") or [])
    except Exception:
        return 0


def _rank_urls_by_risk(urls: list) -> list:
    """Scannable URLs, most dangerous first.

    Everything downstream used to take whatever came first, and IOC lists are
    sorted alphabetically for reproducibility — so in a document containing
    `aaa-harmless.example/x` and `zzz-evil.tk/payload.exe`, the harmless link
    won and the payload was never analysed, scanned, or enriched. Which link a
    scan examined came down to spelling.

    Ties keep alphabetical order so results stay deterministic.
    """
    candidates = [
        u for u in (urls or [])
        if is_reportable_url(u) and not _is_suppressible_indicator(u)
    ]
    return sorted(candidates, key=lambda u: (-_url_risk(u), u))


def _pick_best_url(urls: list) -> str | None:
    """The riskiest URL worth sending to VirusTotal / URLScan, or None.

    Skips anything a scan would learn nothing from: namespace boilerplate, and
    bare references to reputable domains (scanning `google.com` tells us
    nothing). A path-bearing URL on a reputable host is NOT skipped — that is a
    specific file someone uploaded to a platform, which is exactly the case
    worth scanning and exactly what used to be dropped.

    Requires a real dotted/IP host (is_reportable_url) so a malformed indicator
    scraped from a binary can't be sent to URLScan and trigger 'Invalid URL
    format'.
    """
    ranked = _rank_urls_by_risk(urls)
    return ranked[0] if ranked else None


def _normalize_url(url: str) -> str:
    """Semantics-preserving URL normalization for a stable cache key.

    Lowercases scheme + host and drops a redundant default port and a bare
    trailing '/', so `HTTP://Evil.COM/` and `http://evil.com` map to the same
    hash (and therefore the same cached verdict). Path/query/fragment case is
    left untouched. A bare hostname is just lowercased.
    """
    try:
        url = (url or "").strip()
        parsed = urlparse(url)
        if not parsed.scheme:
            # bare domain submission (no scheme) — hostnames are case-insensitive
            return url.lower() if _DOMAIN_RE.match(url) else url
        host = (parsed.hostname or "").lower()
        if not host:
            return url
        netloc = host
        if parsed.port and not (
            (parsed.scheme == "http" and parsed.port == 80)
            or (parsed.scheme == "https" and parsed.port == 443)
        ):
            netloc = f"{host}:{parsed.port}"
        path = "" if parsed.path == "/" else parsed.path
        return urlunparse((parsed.scheme.lower(), netloc, path, parsed.params, parsed.query, parsed.fragment))
    except Exception:
        return url


# ── Duplicate-submission debounce ─────────────────────────────────────────────
# Deliberately NOT a result cache. A 24h cache used to replay a verdict verbatim
# for a whole day, which meant a single wrong answer (a junk ThreatFox hit that
# scored google.com as Malicious) stayed wrong until the TTL expired, and a
# sample that VirusTotal had not caught up with yet froze at its safer-looking
# early verdict. Threat intel moves — a rescan SHOULD be allowed to disagree.
#
# What remains is a short debounce whose only job is to collapse accidental
# duplicate submissions (a double-clicked button, an app retry, a resubmit after
# a flaky network) so one user action costs one scan's worth of external API
# quota. Anything past the window is a genuine rescan and runs the full pipeline.
# 5 seconds, not 60. The only thing this may collapse is a double-clicked button
# or an app retry — a single user action that must not cost two scans' worth of
# VirusTotal quota (4 requests/minute on the free tier).
#
# It must never collapse a DELIBERATE rescan. Someone who reads a verdict,
# doubts it and presses scan again is asking a second question and has to get a
# freshly computed answer; threat intel moves, and a stale reply to a real
# question is the behaviour this engine exists to avoid. Sixty seconds was long
# enough to swallow that.
RESULT_DEBOUNCE_SECONDS = 5

def _find_recent_duplicate(db, file_hash: str, exclude_job_id: str):
    """Most-recent Completed, NON-partial ScanJob with identical bytes submitted
    within the debounce window. Returns its stored `results` to copy, or None.

    Partial results (a verdict-critical intel source did not complete) are never
    reused, so a rate-limited scan can't be handed back as if it were finished.
    """
    if not file_hash:
        return None
    cutoff = datetime.utcnow() - timedelta(seconds=RESULT_DEBOUNCE_SECONDS)
    rows = (
        db.query(ScanJob)
        .filter(
            ScanJob.file_hash == file_hash,
            ScanJob.status == "Completed",
            ScanJob.created_at >= cutoff,
            ScanJob.job_id != exclude_job_id,
        )
        .order_by(ScanJob.created_at.desc())
        .limit(5)
        .all()
    )
    for row in rows:
        res = row.results
        if res and not res.get("partial"):
            return res
    return None

# ── Archive extraction (ZIP + RAR) ────────────────────────────────────────────
# Malware is very commonly shipped inside a ZIP or RAR, so we recurse into both
# and scan the inner files. Python's stdlib handles ZIP; RAR needs an external
# decompression backend (unrar / bsdtar / 7z) driven via the `rarfile` library.
# Following the same graceful-degradation pattern as YARA and Playwright: if no
# backend is installed, RAR *inner* extraction is skipped (the archive is still
# hashed and top-level scanned) rather than crashing the pipeline.
def _configure_rar_backend() -> bool:
    try:
        import rarfile
    except Exception:
        return False
    # rarfile walks its configured tool list and uses the first that works. Point
    # each tool var at an absolute path we can find, so a backend that isn't on
    # PATH (e.g. msys2's bsdtar on Windows) is still usable.
    found = False
    for attr, names in (
        ("UNRAR_TOOL",   ["unrar", "unrar.exe"]),
        ("UNAR_TOOL",    ["unar", "unar.exe"]),
        ("BSDTAR_TOOL",  ["bsdtar", "bsdtar.exe"]),
        ("SEVENZIP_TOOL",["7z", "7z.exe", "7za", "7zz"]),
    ):
        for n in names:
            resolved = shutil.which(n)
            if resolved:
                setattr(rarfile, attr, resolved)
                found = True
                break
    # Common Windows install locations that aren't on PATH.
    for cand, attr in (
        (r"C:\msys64\usr\bin\bsdtar.exe",        "BSDTAR_TOOL"),
        (r"C:\msys64\ucrt64\bin\bsdtar.exe",     "BSDTAR_TOOL"),
        (r"C:\Program Files\7-Zip\7z.exe",       "SEVENZIP_TOOL"),
        (r"C:\Program Files (x86)\7-Zip\7z.exe", "SEVENZIP_TOOL"),
    ):
        if os.path.exists(cand):
            setattr(rarfile, attr, cand)
            found = True
    return found

RAR_ENABLED = _configure_rar_backend()
if not RAR_ENABLED:
    print("RAR extraction disabled: no unrar/bsdtar/7z backend found "
          "(install one to scan inside .rar archives; RAR files are still hashed + top-level scanned).")


def _open_extractable_archive(file_path: str):
    """Open a supported, recursively-scannable container. Returns
    (archive, members, kind) or (None, None, None). Callers exclude APKs
    (handled by apk_analyzer). ZIP covers Office-OpenXML/JAR too."""
    try:
        if zipfile.is_zipfile(file_path):
            zf = zipfile.ZipFile(file_path, "r")
            return zf, zf.infolist(), "zip"
    except Exception as e:
        print(f"ZIP open failed: {e}")
    if RAR_ENABLED:
        try:
            import rarfile
            if rarfile.is_rarfile(file_path):
                rf = rarfile.RarFile(file_path)
                return rf, rf.infolist(), "rar"
        except Exception as e:
            print(f"RAR open failed: {e}")
    return None, None, None


# Container formats identified by magic bytes but with no extraction backend
# here. Naming the format in a report while never reading a byte of its contents
# is the same false-clean the password-protected case produced: "nothing found"
# describing a scan that never looked. Keyed on the magic_type strings
# static_analyzer emits, so the two lists cannot drift apart silently.
UNSUPPORTED_CONTAINER_TYPES = {
    "7-Zip Archive":                "7-Zip",
    "GZIP Compressed":              "GZIP",
    "BZIP2 Compressed":             "BZIP2",
    "XZ Compressed":                "XZ",
    "Microsoft Cabinet (CAB) File": "Microsoft Cabinet (CAB)",
    "InstallShield CAB":            "InstallShield CAB",
    "TAR Archive":                  "TAR",
    "ISO 9660 Disc Image":          "ISO disc image",
}


def _unextractable_container(magic_type: str) -> str | None:
    """Names the container format when the file is one we cannot open, else None.

    RAR is conditional rather than listed: it IS supported, but only when an
    unrar/bsdtar/7z backend exists on the host. Without one the scan silently
    examined nothing, which docs/RUNNING.md warns about generally but no report
    ever said out loud.
    """
    if magic_type in UNSUPPORTED_CONTAINER_TYPES:
        return UNSUPPORTED_CONTAINER_TYPES[magic_type]
    if magic_type == "RAR Archive" and not RAR_ENABLED:
        return "RAR (no extraction backend installed on this server)"
    return None


# zipfile.ZipInfo and rarfile.RarInfo expose the same three member attributes,
# so one loop handles both — these normalize the small API differences.
def _member_name(m) -> str:
    return getattr(m, "filename", "") or ""

def _member_size(m) -> int:
    return getattr(m, "file_size", 0) or 0

def _is_encrypted_member_error(exc: Exception) -> bool:
    """True when a member failed to extract because it is password-protected.

    Matched on type name and message rather than a specific exception class:
    zipfile raises a bare RuntimeError("... is encrypted, password required for
    extraction"), while rarfile raises PasswordRequired or RarWrongPassword —
    and rarfile is an optional dependency, so it cannot be referenced directly
    here without coupling this check to whether RAR support is installed.
    """
    if "password" in type(exc).__name__.lower() or "encrypt" in type(exc).__name__.lower():
        return True
    message = str(exc).lower()
    return "password" in message or "encrypted" in message


def _member_is_dir(m) -> bool:
    is_dir = getattr(m, "is_dir", None)
    if callable(is_dir):
        try:
            return bool(is_dir())
        except Exception:
            pass
    return _member_name(m).endswith("/")


# ── Per-member analysis ───────────────────────────────────────────────────────
# Every detector that runs on the submitted artifact now also runs on each file
# inside it. Previously only IOC extraction and PE parsing did, which meant
# wrapping a sample in a ZIP defeated three separate engines at once: YARA saw
# the container's DEFLATE-compressed bytes (so rules written against PE structure
# could never match), document analysis saw "a ZIP" rather than the maldoc inside
# it, and hash intel only ever knew the wrapper's hash. All three reported
# success while examining the wrong bytes.

def _sha256_of(path: str, data: bytes = None) -> str:
    """SHA-256 of a member, reusing already-read bytes when the caller has them
    and streaming from disk otherwise so a large member is never held twice."""
    if data is not None:
        return hashlib.sha256(data).hexdigest()
    h = hashlib.sha256()
    try:
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(_ARCHIVE_COPY_CHUNK), b""):
                h.update(chunk)
    except Exception:
        return ""
    return h.hexdigest()


def _new_archive_scan() -> dict:
    """Accumulator threaded through an entire archive tree.

    The bomb budgets (files_seen / bytes_seen) live here rather than per archive
    deliberately: under per-archive accounting, 500 files each holding 500 files
    is 250,000 extractions and every single one is "within limits". Nested
    archives must spend from the same allowance as the top level.
    """
    return {
        "files_seen": 0,
        "bytes_seen": 0,
        "truncated": None,
        "contents": [],
        "iocs": {"ips": [], "domains": [], "urls": []},
        "suspicious_sections": [],
        "suspicious_strings": [],
        "yara_matches": [],
        "documents": [],
        # (member name, apk_info) for every APK found inside. An APK arriving
        # wrapped in a ZIP is the same threat as one arriving directly, and the
        # permission scoring is the strongest Android signal available.
        "apks": [],
        # (member name, script_info) for script members with findings. A .js or
        # .vbs dropper is a standard second stage inside an archive or ISO.
        "scripts": [],
        # (member name, extension_info) for browser extensions found inside.
        "extensions": [],
        # (member name, html_info) for HTML members with findings — a smuggling
        # page is routinely zipped so the mail gateway sees an archive instead.
        "htmls": [],
        # (member name, lnk_info) for shortcuts with findings. A malicious .lnk
        # almost always arrives inside a container, because that is what strips
        # the mark-of-the-web warning.
        "lnks": [],
        "hash_candidates": [],
        "unreadable": [],
        # Members that could not be extracted because the archive is
        # password-protected. Distinct from `unreadable`, which is for files
        # that DID extract and then failed to read (usually AV quarantine).
        "encrypted": [],
        # Set when the artifact is a container format with no extraction backend
        # here (7-Zip, CAB, ISO, TAR, RAR without unrar). Holds the format name.
        "unsupported_container": None,
        "is_pe": False,
        "imphash": None,
    }


def _copy_member_bounded(archive, member, dest_path: str, budget_left: int):
    """Extract one member, refusing to write more than `budget_left` bytes.
    Returns bytes written, or None if the member ran past the budget.

    The declared size in an archive header is attacker-controlled — a member can
    claim 1 KB and expand to gigabytes. Trusting that header (what this did
    before) means the bomb is already on disk by the time the total is noticed,
    so the copy itself is capped rather than just the prediction of it.
    """
    written = 0
    with archive.open(member) as src, open(dest_path, "wb") as dst:
        while True:
            chunk = src.read(_ARCHIVE_COPY_CHUNK)
            if not chunk:
                break
            written += len(chunk)
            if written > budget_left:
                return None
            dst.write(chunk)
    return written


def _scan_archive_tree(file_path: str, acc: dict, depth: int = 1) -> None:
    """Extract one archive and analyse every member, recursing into nested
    archives up to MAX_ARCHIVE_DEPTH.

    Safe against Zip Slip, decompression bombs and archive-in-archive
    amplification. A member that cannot be read is skipped, never fatal.
    """
    archive, members, kind = _open_extractable_archive(file_path)
    if archive is None:
        return

    extract_dir, extracted = None, []
    try:
        extract_dir = tempfile.mkdtemp(prefix="malscan_arc_")
        real_extract_dir = os.path.realpath(extract_dir)

        for member in members:
            # ── Archive bomb: too many files (across the whole tree) ──────────
            if acc["files_seen"] >= MAX_ZIP_FILE_COUNT:
                acc["truncated"] = f"file limit reached ({MAX_ZIP_FILE_COUNT} files)"
                print(f"Archive bomb blocked: more than {MAX_ZIP_FILE_COUNT} files across the archive tree")
                break

            # ── Archive bomb: decompressed size (across the whole tree) ───────
            budget_left = MAX_DECOMPRESSED_BYTES - acc["bytes_seen"]
            if budget_left <= 0 or _member_size(member) > budget_left:
                acc["truncated"] = f"size limit reached ({MAX_DECOMPRESSED_BYTES // 1024 // 1024} MB decompressed)"
                print(f"Archive bomb blocked: decompressed size exceeds {MAX_DECOMPRESSED_BYTES // 1024 // 1024} MB")
                break

            # ── Zip Slip protection ───────────────────────────────────────────
            # commonpath avoids the prefix-sibling bug of a bare startswith
            # (e.g. "/x/dir" vs "/x/dir_evil") and an absolute/other-drive
            # member path (ValueError → outside).
            member_name = _member_name(member)
            member_path = os.path.realpath(os.path.join(extract_dir, member_name))
            try:
                inside = os.path.commonpath([real_extract_dir, member_path]) == real_extract_dir
            except ValueError:
                inside = False
            if not inside:
                print(f"Zip Slip blocked: {member_name}")
                continue

            if _member_is_dir(member):
                os.makedirs(member_path, exist_ok=True)
                continue

            os.makedirs(os.path.dirname(member_path), exist_ok=True)
            try:
                written = _copy_member_bounded(archive, member, member_path, budget_left)
            except Exception as me:
                # A backend that can't decompress one member (e.g. an
                # unsupported RAR compression) must not abort the scan.
                if _is_encrypted_member_error(me):
                    # Password-protected. Every inner detector is bypassed —
                    # no hash for MalwareBazaar/VirusTotal, no YARA, no PE or
                    # document analysis — so the scan MUST say it could not
                    # look inside rather than let "nothing found" read as
                    # "nothing there". Encrypting the payload and mailing the
                    # password separately is a standard way of getting a
                    # sample past exactly this kind of scanner.
                    acc["encrypted"].append(member_name)
                    print(f"Archive member '{member_name}' is password-protected — not scanned")
                else:
                    print(f"Archive member '{member_name}' extraction failed: {me}")
                continue
            if written is None:
                acc["truncated"] = f"size limit reached ({MAX_DECOMPRESSED_BYTES // 1024 // 1024} MB decompressed)"
                print(f"Archive bomb blocked: '{member_name}' expanded past the decompression budget")
                try:
                    os.remove(member_path)
                except OSError:
                    pass
                break

            acc["files_seen"] += 1
            acc["bytes_seen"] += written
            extracted.append((member_path, member_name))

        # Analyse after extracting, so a member that recurses cannot disturb the
        # iteration over this archive's own member list.
        for member_path, member_name in extracted:
            _analyze_archive_member(member_path, member_name, acc, depth)
    except Exception as ze:
        print(f"{(kind or 'archive').upper()} extraction error: {ze}")
    finally:
        try:
            archive.close()
        except Exception:
            pass
        # Always clean up temp extraction directory
        if extract_dir and os.path.exists(extract_dir):
            shutil.rmtree(extract_dir, ignore_errors=True)


def _analyze_archive_member(inner_path: str, display_name: str, acc: dict, depth: int) -> None:
    """Run the artifact-level detectors on one extracted member and record what
    fired on it, so a hit can name the specific file rather than just 'the archive'."""
    try:
        size = os.path.getsize(inner_path)
    except OSError:
        return

    # Read once and share the bytes across analysers; stream instead when the
    # member is big enough that holding it (plus each analyser's own copy) costs
    # more than re-reading it.
    #
    # A member that extracts but cannot be read back is almost always real-time
    # antivirus quarantining it in the gap between the two — routine on Windows
    # precisely when an archive DOES contain malware. Left unrecorded, the most
    # dangerous file in the archive is the one that reports nothing, and "found
    # nothing" reads identically to "was never able to look".
    data = None
    try:
        with open(inner_path, "rb") as f:
            if size <= MAX_INNER_READ_BYTES:
                data = f.read()
            else:
                f.read(1)   # touch it, so an unreadable large member fails here too
    except OSError as e:
        acc["unreadable"].append(display_name)
        acc["contents"].append({
            "name": display_name, "sha256": "", "size": size, "depth": depth,
            "is_pe": False, "ioc_count": 0, "yara_rules": [], "doc_type": None,
            "unreadable": type(e).__name__,
        })
        print(f"Archive member '{display_name}' could not be read after extraction "
              f"({type(e).__name__}) — commonly antivirus quarantine")
        return

    inner_iocs = extract_iocs(inner_path, data=data)
    for k in ("ips", "domains", "urls"):
        acc["iocs"][k].extend(inner_iocs.get(k) or [])

    inner_pe = analyze_pe(inner_path, data=data, filename=display_name)
    acc["suspicious_sections"].extend(inner_pe.get("suspicious_sections") or [])
    if inner_pe.get("is_pe"):
        acc["is_pe"] = True
        acc["imphash"] = acc["imphash"] or inner_pe.get("imphash")

    inner_yara = yara_scan_file(inner_path)
    for m in (inner_yara.get("yara_matches") or []):
        entry = dict(m)
        entry["source_file"] = display_name
        acc["yara_matches"].append(entry)

    inner_doc = analyze_document(inner_path, display_name) or {}
    if inner_doc.get("doc_type") not in (None, "unknown"):
        acc["documents"].append((display_name, inner_doc))

    # A shortcut inside an archive. This is the ordinary way a malicious .lnk
    # travels — inside a ZIP or an ISO, because the container strips the
    # mark-of-the-web warning the user would otherwise see.
    inner_lnk = analyze_lnk(inner_path, data=data)
    if inner_lnk.get("is_lnk") and inner_lnk.get("suspicious"):
        acc["lnks"].append((display_name, inner_lnk))

    inner_html = analyze_html(inner_path, data=data, filename=display_name)
    if inner_html.get("is_html") and inner_html.get("codes"):
        acc["htmls"].append((display_name, inner_html))

    inner_script = analyze_script(inner_path, data=data, filename=display_name)
    if inner_script.get("is_script") and inner_script.get("codes"):
        acc["scripts"].append((display_name, inner_script))

    # An APK inside an archive. Only ZIP members are asked, so this costs one
    # archive open on the members that could possibly be APKs and nothing on the
    # rest. Without it, wrapping a banking trojan in a ZIP discarded every
    # Android-specific signal — permissions, overlay/accessibility conjunction,
    # DEX strings — while still looking thoroughly scanned.
    try:
        if zipfile.is_zipfile(inner_path):
            inner_ext = analyze_extension(inner_path)
            if inner_ext.get("is_extension") and inner_ext.get("codes"):
                acc["extensions"].append((display_name, inner_ext))
            inner_apk = analyze_apk(inner_path)
            if inner_apk.get("is_apk"):
                acc["apks"].append((display_name, inner_apk))
                for k in ("ips", "urls"):
                    acc["iocs"][k] = sorted(
                        set(acc["iocs"][k]) | set(inner_apk.get(f"dex_{k}") or [])
                    )
    except Exception as e:
        print(f"APK analysis of member '{display_name}' failed: {e}")

    acc["suspicious_strings"].extend(
        analyze_suspicious_strings(inner_path, data=data).get("suspicious_strings") or []
    )

    sha = _sha256_of(inner_path, data=data)
    acc["contents"].append({
        "name":       display_name,
        "sha256":     sha,
        "size":       size,
        "depth":      depth,
        "is_pe":      inner_pe.get("is_pe", False),
        "ioc_count":  len(inner_iocs.get("urls") or []) + len(inner_iocs.get("ips") or []),
        "yara_rules": [m.get("rule") for m in (inner_yara.get("yara_matches") or [])],
        "doc_type":   inner_doc.get("doc_type"),
    })
    if sha:
        acc["hash_candidates"].append({
            "name":   display_name,
            "sha256": sha,
            "is_pe":  bool(inner_pe.get("is_pe")),
            "is_doc": inner_doc.get("doc_type") not in (None, "unknown"),
        })

    # Nested container: recurse. Bounded by MAX_ARCHIVE_DEPTH and by the shared
    # budget above, so double-zipping neither hides a payload nor multiplies work.
    if depth < MAX_ARCHIVE_DEPTH:
        _scan_archive_tree(inner_path, acc, depth + 1)


def _merge_unique(base, extra) -> list:
    """Order-preserving union. Suspicious strings score +8 each for the first
    five, so twenty copies of one flag from twenty identical members would
    otherwise crowd every other signal out of the window."""
    out = list(base or [])
    for item in extra or []:
        if item not in out:
            out.append(item)
    return out


def _merge_yara_matches(container: dict, inner: list) -> dict:
    """Fold member matches into the container's YARA result.

    Deduplicated by rule: scoring charges 40 per critical match, so one rule
    firing on twenty copies of the same payload would read as twenty times the
    evidence. The member names move onto the surviving match instead, so the
    report can still say which files it hit.
    """
    merged = list(container.get("yara_matches") or [])
    by_rule = {m.get("rule"): m for m in merged}
    for m in inner or []:
        rule, src = m.get("rule"), m.get("source_file")
        existing = by_rule.get(rule)
        if existing is None:
            entry = dict(m)
            entry.pop("source_file", None)
            entry["source_files"] = [src] if src else []
            merged.append(entry)
            by_rule[rule] = entry
        elif src:
            existing.setdefault("source_files", [])
            if src not in existing["source_files"]:
                existing["source_files"].append(src)
    container["yara_matches"] = merged
    container["match_count"] = len(merged)
    return container


def _document_threat_rank(doc: dict) -> tuple:
    """Order document findings by the signals scoring.py actually charges for.

    _check_document_threats takes ONE document dict, so an archive holding
    several has to nominate its worst; ranking on the same flags keeps that
    choice aligned with what the scorer would have charged for each.
    """
    if not doc or doc.get("doc_type") in (None, "unknown"):
        return (0, 0, 0, 0, 0, 0, 0)
    return (
        int(bool(doc.get("has_launch_action"))),
        int(bool(doc.get("has_js_auto_combo"))),
        int(bool(doc.get("has_macros"))),
        len(doc.get("suspicious_macro_keywords") or []),
        int(bool(doc.get("has_embedded_files"))),
        int(bool(doc.get("has_javascript"))),
        int(bool(doc.get("has_auto_action"))),
    )


def _promote_archive_document(container_doc: dict, acc: dict) -> dict:
    """Let an archive's most dangerous member stand in as *the* document.

    A ZIP is not a document, so analyze_document on the container finds nothing —
    which is precisely how a maldoc inside a ZIP scored zero for document threats.
    """
    docs = acc.get("documents") or []
    if not docs:
        return container_doc
    name, worst = max(docs, key=lambda nd: _document_threat_rank(nd[1]))
    if _document_threat_rank(worst) <= _document_threat_rank(container_doc or {}):
        return container_doc
    promoted = dict(worst)
    promoted["source_file"] = name
    return promoted


def _select_inner_intel_targets(acc: dict, limit: int) -> list:
    """Which member hashes are worth spending a rate-limited lookup on.

    Executables first, then documents (what MalwareBazaar actually indexes), then
    everything else — deduplicated by hash and capped, so a 500-file archive
    cannot turn into 500 abuse.ch requests.
    """
    ranked = sorted(
        acc.get("hash_candidates") or [],
        key=lambda c: (0 if c["is_pe"] else 1 if c["is_doc"] else 2),
    )
    seen, targets = set(), []
    for c in ranked:
        if c["sha256"] in seen:
            continue
        seen.add(c["sha256"])
        targets.append(c)
        if len(targets) >= limit:
            break
    return targets


_osint_executor = ThreadPoolExecutor(max_workers=8, thread_name_prefix="osint")

# VirusTotal lookups spent on a page's third-party hosts, over and above the one
# spent on the page itself. The free tier allows 4 requests/minute, so this is a
# hard ceiling rather than a preference — resource_chain ranks the candidates so
# the small budget lands on the hosts most worth asking about, and returns fewer
# than the budget when nothing clears the bar.
RESOURCE_VT_BUDGET = int(os.environ.get("RESOURCE_VT_BUDGET", "2"))
# abuse.ch has no comparable rate ceiling, so the bound here is only about not
# posting an unbounded list from a page with hundreds of third parties.
MAX_RESOURCE_INTEL_HOSTS = 20

init_db()

# One-time backfill of the indicator index from existing completed jobs
# (idempotent — no-op once populated, and a no-op on a fresh/test DB).
_bf_db = SessionLocal()
try:
    backfill_indicator_index(_bf_db)
finally:
    _bf_db.close()


def process_scan_job(job_id: str, file_path: str, original_filename: str = "unknown", submitted_url: str = None,
                     allow_vt_upload: bool = True):
    db = SessionLocal()
    job = db.query(ScanJob).filter(ScanJob.job_id == job_id).first()
    if not job:
        db.close()
        return

    try:
        scan_started_at = time.time()

        # ── 0. Duplicate-submission debounce ─────────────────────────────────
        # Only collapses the same bytes resubmitted within seconds (double-click,
        # app retry, resubmit after a flaky network) so one user action costs one
        # scan's worth of external API quota. A genuine rescan later runs the full
        # pipeline and is allowed to return a different answer as intel moves.
        # File metadata (name, URL, duration) is refreshed to this request; the
        # analytical result is copied unchanged.
        recent = _find_recent_duplicate(db, job.file_hash, exclude_job_id=job_id)
        if recent is not None:
            score_data = dict(recent)
            score_data["original_filename"] = original_filename
            score_data["debounced"] = True
            score_data["scan_duration_seconds"] = round(time.time() - scan_started_at, 2)
            if submitted_url:
                score_data["submitted_url"] = submitted_url
            else:
                score_data.pop("submitted_url", None)
            job.results = score_data
            job.status = "Completed"
            db.commit()
            return

        job.status = "Processing"
        db.commit()

        # ── 1. Static Analysis ───────────────────────────────────────────────
        # Read the artifact once and reuse the bytes across analyzers, instead of
        # re-reading a (up to 50 MB) file from disk for each pass.
        # If this read fails, EVERY analyser below silently receives nothing:
        # extraction, PE parsing, YARA and the document analysers all return
        # empty, and the scan reports Clear on a file it never opened. The
        # commonest cause is real-time antivirus on the scanning host
        # quarantining the sample between upload and analysis — which correlates
        # with the file being genuinely malicious, making this the worst
        # possible moment to return a clean verdict. Observed in this project's
        # own test run, where a fixture containing a download cradle was
        # confiscated mid-scan.
        artifact_unreadable = None
        try:
            with open(file_path, "rb") as f:
                raw_bytes = f.read()
        except Exception as e:
            raw_bytes = None
            artifact_unreadable = type(e).__name__
            print(f"Artifact could not be read ({artifact_unreadable}) — "
                  f"commonly antivirus quarantine. Nothing was analysed.")
        iocs    = extract_iocs(file_path, data=raw_bytes)
        # original_filename, not the vault path: the vault stores files under
        # their hash with no extension, so without this the disguise check is dead.
        pe_info = analyze_pe(file_path, data=raw_bytes, filename=original_filename)
        apk_info = {}

        # ── 1b. Archive Extraction — ZIP + RAR + APK (Zip-Slip / bomb safe) ───
        # APKs are walked here too, not just by apk_analyzer: that reads the
        # manifest and DEX strings, but everything else an APK carries — a
        # bundled .so payload, a second APK, an embedded document — is visible
        # only to this walk. Self-extracting EXEs come along for free, since
        # _open_extractable_archive sniffs content rather than the extension.
        archive_scan = _new_archive_scan()
        _scan_archive_tree(file_path, archive_scan)

        # A container we can name but cannot open. Recorded on the same footing
        # as a password-protected archive, because the user-visible failure is
        # identical: the report describes a 7-Zip archive (or an ISO, or a RAR
        # on a host with no backend) while nothing inside it was ever read.
        _unsupported = _unextractable_container(pe_info.get("magic_type", ""))
        if _unsupported and not archive_scan["contents"]:
            archive_scan["unsupported_container"] = _unsupported
            print(f"Container format not extractable here: {_unsupported} — contents not scanned")

        archive_contents = archive_scan["contents"]
        if archive_contents:
            for k in ("ips", "domains", "urls"):
                iocs[k] = sorted(set((iocs.get(k) or []) + archive_scan["iocs"][k]))
            pe_info["suspicious_sections"].extend(archive_scan["suspicious_sections"])
            if archive_scan["is_pe"]:
                pe_info["is_pe"] = True
                pe_info["imphash"] = pe_info.get("imphash") or archive_scan["imphash"]

        # ── 1c. APK Analysis ─────────────────────────────────────────────────
        # Gated on content, not on the filename. analyze_apk already answers the
        # question itself — it requires a readable ZIP containing
        # AndroidManifest.xml and returns is_apk False otherwise — so calling it
        # for any ZIP costs one archive open and removes a rename as an evasion.
        # Permission scoring is the strongest Android signal in the product;
        # `evil.apk` renamed `evil.zip` used to discard all of it.
        if zipfile.is_zipfile(file_path):
            apk_info = analyze_apk(file_path)
            if apk_info.get("is_apk"):
                for k in ("ips", "urls"):
                    apk_key = f"dex_{k}"
                    iocs[k] = list(set(iocs.get(k, []) + apk_info.get(apk_key, [])))

        # A ZIP is a wrapper, so an APK found inside it is evidence about the
        # thing the user submitted — the same reasoning that promotes an archive
        # member's MalwareBazaar hit below. Only when the container is not itself
        # an APK: a direct APK's own manifest always wins.
        if not apk_info.get("is_apk") and archive_scan.get("apks"):
            member_name, inner_apk = archive_scan["apks"][0]
            apk_info = dict(inner_apk)
            apk_info["matched_file"] = member_name
            print(f"APK found inside archive member '{member_name}' — analysing its manifest")

        # ── 1c-2. Browser extension ──────────────────────────────────────────
        # A .crx is a ZIP, so the archive walk already hashed its members and
        # found nothing: the manifest is small JSON and the payload is ordinary
        # JavaScript. The permission model is the part that matters.
        extension_info = {}
        if zipfile.is_zipfile(file_path):
            extension_info = analyze_extension(file_path)
        if not extension_info.get("is_extension") and archive_scan.get("extensions"):
            member_name, inner = archive_scan["extensions"][0]
            extension_info = dict(inner)
            extension_info["matched_file"] = member_name
            print(f"Browser extension inside archive member '{member_name}'")

        # ── 1d. Document Analysis (PDF / Office / OLE) ───────────────────────
        doc_info = analyze_document(file_path, original_filename)

        # ── 1d-2. Windows shortcut ───────────────────────────────────────────
        # Content-gated like the APK path: a .lnk is routinely renamed, and the
        # signature (header size plus CLSID) is unambiguous.
        lnk_info = analyze_lnk(file_path, data=raw_bytes)
        # A shortcut found inside the archive is evidence about what was
        # submitted, same as a promoted APK or MalwareBazaar hit. Only when the
        # artifact is not itself a shortcut.
        if not lnk_info.get("is_lnk") and archive_scan.get("lnks"):
            member_name, inner = archive_scan["lnks"][0]
            lnk_info = dict(inner)
            lnk_info["matched_file"] = member_name
            print(f"Suspicious shortcut inside archive member '{member_name}'")
        if lnk_info.get("is_lnk"):
            # A shortcut's command line frequently carries the second-stage URL,
            # which is an indicator in its own right.
            lnk_iocs = extract_iocs(file_path, data=(lnk_info.get("arguments") or "").encode())
            for k in ("ips", "domains", "urls"):
                iocs[k] = sorted(set((iocs.get(k) or []) + (lnk_iocs.get(k) or [])))

        # ── 1d-3. HTML attachment ────────────────────────────────────────────
        # An HTML attachment carries no macro and often no URL, so it read as
        # inert text. The payload is inside the page and assembled by script in
        # the browser, which is exactly why nothing on the network path sees it.
        html_info = analyze_html(file_path, data=raw_bytes, filename=original_filename)
        if not html_info.get("is_html") and archive_scan.get("htmls"):
            member_name, inner = archive_scan["htmls"][0]
            html_info = dict(inner)
            html_info["matched_file"] = member_name
            print(f"Suspicious HTML inside archive member '{member_name}'")

        # ── 1d-4. Script dropper ─────────────────────────────────────────────
        # Scripts were covered only by raw string matching and YARA, which
        # misses anything obfuscated -- and obfuscation is the norm, because a
        # script is text and rewriting text is free.
        script_info = analyze_script(file_path, data=raw_bytes, filename=original_filename)
        if not script_info.get("is_script") and archive_scan.get("scripts"):
            member_name, inner = archive_scan["scripts"][0]
            script_info = dict(inner)
            script_info["matched_file"] = member_name
            print(f"Suspicious script inside archive member '{member_name}'")
        for _u in script_info.get("urls") or []:
            if _u not in (iocs.get("urls") or []):
                iocs.setdefault("urls", []).append(_u)

        # ── 1e. Suspicious string patterns ───────────────────────────────────
        string_info = analyze_suspicious_strings(file_path, data=raw_bytes)
        pe_info["suspicious_strings"] = string_info.get("suspicious_strings", [])

        # ── 1f. YARA scan ────────────────────────────────────────────────────
        yara_result = yara_scan_file(file_path)

        # ── 1g. Fold in what the archive members found ───────────────────────
        # Deliberately after 1d–1f: these merge INTO the container's own results,
        # so those have to exist first. Each merge is deduplicated — see the
        # helpers — because scoring charges per match, and an archive holding
        # twenty copies of one payload is not twenty times the evidence.
        if archive_contents:
            doc_info = _promote_archive_document(doc_info, archive_scan)
            pe_info["suspicious_strings"] = _merge_unique(
                pe_info.get("suspicious_strings"), archive_scan["suspicious_strings"]
            )
            yara_result = _merge_yara_matches(yara_result, archive_scan["yara_matches"])

        # ── 2. OSINT Enrichment (concurrent) ──────────────────────────────────
        osint_data = {}
        loop = asyncio.new_event_loop()

        domains = iocs.get("domains", [])
        urls = iocs.get("urls", [])
        
        # Ensure submitted_url is processed if it's a direct domain or url submission
        if submitted_url:
            if submitted_url.startswith("http://") or submitted_url.startswith("https://"):
                if submitted_url not in urls:
                    urls.append(submitted_url)
            else:
                if submitted_url not in domains:
                    domains.append(submitted_url)
                    
        if not domains and urls:
            from urllib.parse import urlparse
            for u in urls:
                try:
                    host = urlparse(u).netloc.split(":")[0]
                    if host and host not in domains:
                        domains.append(host)
                except Exception:
                    pass
            iocs["domains"] = domains

        # Drop known-safe / metadata-namespace indicators (PDF boilerplate like
        # the w3.org and ns.adobe.com XML namespaces) before any external
        # threat-intel lookup, DNS resolution, or heuristic scoring — otherwise a
        # benign document's metadata gets matched against ThreatFox/URLhaus and
        # flagged. The deliberately-submitted URL/domain is always preserved.
        iocs["urls"] = urls
        iocs["domains"] = domains
        _strip_safe_indicators(iocs, keep=submitted_url)

        # Deterministic ordering. IOC lists originate from Python set()s, whose
        # iteration order varies with PYTHONHASHSEED across restarts — which then
        # changes WHICH single indicator gets enriched (domains[0], public_ips[0],
        # _pick_best_url) and the graph's [:8]/[:6] slices. Sorting here removes
        # that restart-dependent variance so the same file enriches identically.
        for k in ("ips", "domains", "urls"):
            iocs[k] = sorted(iocs.get(k, []))
        urls = iocs["urls"]
        domains = iocs["domains"]
        ips = iocs["ips"]

        vt_key = os.environ.get("VT_API_KEY")
        us_key = os.environ.get("URLSCAN_API_KEY")

        # The riskiest scannable URL, not the alphabetically first one.
        scan_target_url = submitted_url or _pick_best_url(iocs.get("urls", []))

        # Only one domain gets WHOIS/DNS/GeoIP (they are slow and rate-limited),
        # so which one matters. Taking domains[0] meant spelling decided: a file
        # citing mail.google.com and netbanking.hdfcbank.com enriched Google,
        # because "m" sorts before "n" — and the registrar finding for the domain
        # actually worth looking at never appeared. Prefer the host of the URL we
        # judged riskiest, falling back to alphabetical when there is no URL.
        enrich_domain = None
        if scan_target_url:
            enrich_domain = next((d for d in domains if d == _url_host(scan_target_url)), None)
        if not enrich_domain and domains:
            enrich_domain = domains[0]

        # Build a list of futures to run concurrently
        futures = {}
        if enrich_domain:
            futures["whois"] = loop.run_in_executor(_osint_executor, get_whois, enrich_domain)
            futures["dns"]   = loop.run_in_executor(_osint_executor, get_dns_records, enrich_domain)
        import socket
        # Only globally-routable, real IPs are worth geolocating / abuse-checking.
        # is_reportable_ip rejects private/loopback/reserved/multicast/x.x.x.0 —
        # the same gate extraction uses — so a junk quad can't produce a bogus
        # "threat origin" on the map.
        public_ips = [ip for ip in ips if is_reportable_ip(ip)]

        if not public_ips and enrich_domain:
            try:
                resolved_ip = socket.gethostbyname(enrich_domain)
                if is_reportable_ip(resolved_ip):
                    public_ips.append(resolved_ip)
                    iocs["ips"].append(resolved_ip)
            except Exception:
                pass

        if public_ips:
            futures["geoip"] = loop.run_in_executor(_osint_executor, get_geoip, public_ips[0])
        if scan_target_url and vt_key:
            futures["vt_url"] = loop.run_in_executor(_osint_executor, get_url_report, scan_target_url, vt_key)
        if scan_target_url and us_key:
            futures["urlscan"] = loop.run_in_executor(_osint_executor, urlscan_scan, scan_target_url, us_key)
        if not submitted_url and vt_key:
            # allow_vt_upload=False keeps this to a hash lookup. An unknown hash
            # then stays unknown rather than being resolved by publishing the
            # file to a third party.
            futures["vt_file"] = loop.run_in_executor(
                _osint_executor, get_file_report, job.file_hash, vt_key, file_path,
                allow_vt_upload,
            )

        # ── New: abuse.ch threat intelligence (no key required) ──────────────
        futures["malwarebazaar"] = loop.run_in_executor(
            _osint_executor, mb_check_hash, job.file_hash
        )
        # Archive members get their own hash lookups. MalwareBazaar indexes
        # samples, not the wrappers they travel in, so a zipped sample never
        # matches on the container's hash however well-known it is. Bounded —
        # see _select_inner_intel_targets.
        inner_intel_targets = _select_inner_intel_targets(archive_scan, MAX_INNER_INTEL_LOOKUPS)
        for idx, target in enumerate(inner_intel_targets):
            futures[f"mb_inner_{idx}"] = loop.run_in_executor(
                _osint_executor, mb_check_hash, target["sha256"]
            )
        if iocs.get("urls"):
            futures["urlhaus"] = loop.run_in_executor(
                _osint_executor, uh_check_urls, iocs.get("urls", [])
            )
        futures["threatfox"] = loop.run_in_executor(
            _osint_executor, tf_check_iocs,
            iocs.get("ips", []), iocs.get("domains", []),
            iocs.get("urls", []), job.file_hash
        )
        ab_key = os.environ.get("ABUSEIPDB_API_KEY")
        if public_ips and ab_key:
            futures["abuseipdb"] = loop.run_in_executor(
                _osint_executor, ab_check_ips, public_ips, ab_key
            )

        # Await all concurrently
        async def _gather_osint():
            results = {}
            for key, fut in futures.items():
                try:
                    results[key] = await fut
                except Exception as e:
                    print(f"OSINT task '{key}' failed: {e}")
                    results[key] = {"error": str(e)}
            return results

        osint_results = loop.run_until_complete(_gather_osint())
        loop.close()

        # Merge results into osint_data
        if "whois" in osint_results:
            osint_data["whois"] = osint_results["whois"]
        if "dns" in osint_results:
            osint_data["dns"] = osint_results["dns"]
        if "geoip" in osint_results:
            osint_data["geoip"] = osint_results["geoip"]
        if "vt_url" in osint_results:
            vt_result = osint_results["vt_url"]
            if "error" not in vt_result:
                osint_data["virustotal"] = vt_result
        if "urlscan" in osint_results:
            osint_data["urlscan"] = osint_results["urlscan"]
        if "vt_file" in osint_results:
            vt_file_result = osint_results["vt_file"]
            if "error" not in vt_file_result and "status" not in vt_file_result:
                osint_data["virustotal"] = vt_file_result

        # New threat intel feeds
        for key in ("malwarebazaar", "threatfox", "urlhaus", "abuseipdb"):
            if key in osint_results and "error" not in (osint_results[key] or {}):
                osint_data[key] = osint_results[key]

        # An archive is a wrapper, so a sample confirmed inside it is evidence
        # about the thing the user actually submitted — promote the first hit to
        # the artifact's own MalwareBazaar result, which is what scoring reads.
        # Only when the container itself is unknown: a direct hit is stronger.
        if not (osint_data.get("malwarebazaar") or {}).get("found"):
            for idx, target in enumerate(inner_intel_targets):
                res = osint_results.get(f"mb_inner_{idx}") or {}
                if res.get("found"):
                    hit = dict(res)
                    hit["matched_file"] = target["name"]
                    hit["matched_sha256"] = target["sha256"]
                    osint_data["malwarebazaar"] = hit
                    print(f"MalwareBazaar hit on archive member '{target['name']}'")
                    break

        # ── Safe-domain intel suppression ─────────────────────────────────────
        # A deliberately-submitted URL is kept in `iocs` by _strip_safe_indicators
        # (via `keep`) so the report can still geolocate it, graph it and render
        # the URLScan screenshot. But that also means an allow-listed domain
        # reaches ThreatFox/URLhaus, where a junk entry (malware configs routinely
        # reference google.com for connectivity checks) returns a 100%-confidence
        # "hit" worth +70 — enough to flag google.com as Malicious on its own,
        # and the weak-IOC cap in scoring.py deliberately does not apply to
        # submitted URLs. Drop the intel MATCH only; all enrichment is untouched.
        # Narrowed deliberately: only a BARE reference to a reputable domain (or
        # namespace boilerplate) is noise. A hit on a path-bearing URL such as
        # github.com/x/releases/download/loader.exe is a report about a specific
        # file a stranger uploaded, not about GitHub — discarding those meant a
        # confirmed URLhaus detection was thrown away because of where the
        # payload happened to be hosted.
        for key, ioc_field in (("threatfox", "matched_ioc"), ("urlhaus", "matched_url")):
            hit = osint_data.get(key) or {}
            if not hit.get("found"):
                continue
            indicator = hit.get(ioc_field) or ""
            if _is_suppressible_indicator(indicator):
                print(f"Safe-domain intel suppressed: {key} match on bare reputable/boilerplate '{indicator}'")
                osint_data[key] = {"found": False, "suppressed_safe_domain": indicator}

        # ── Resource-chain enrichment (second wave) ───────────────────────────
        # A page is its domain plus everything it loads. Reputation was only ever
        # asked about the domain, so a clean wrapper serving a malicious
        # third-party script scored zero while the offending host sat in the
        # report as an unread chip.
        #
        # This has to be a second wave: the chain is not known until URLScan
        # returns, and URLScan is itself one of the first-wave futures. The extra
        # latency is small next to the scan that produced the list.
        #
        # Budgets are the whole design constraint. VirusTotal's free tier allows
        # 4 requests/minute and the first wave already spent one or two, so the
        # lookups go to the structurally most interesting hosts and stop. abuse.ch
        # (ThreatFox/URLhaus) has no comparable ceiling, so the full host list
        # goes there.
        resource_chain = {"hosts": [], "third_party_domains": 0, "skipped": True}
        if osint_data.get("urlscan"):
            resource_chain = analyze_resource_chain(osint_data["urlscan"], scan_target_url or "")

        if resource_chain.get("hosts"):
            rc_futures, rc_hosts = {}, resource_chain["hosts"]
            vt_targets = (
                select_resource_lookups(resource_chain, RESOURCE_VT_BUDGET) if vt_key else []
            )
            for host in vt_targets:
                rc_futures[("vt", host)] = _osint_executor.submit(
                    get_url_report, f"https://{host}/", vt_key
                )
            intel_domains = [h["host"] for h in rc_hosts][:MAX_RESOURCE_INTEL_HOSTS]
            intel_urls = (osint_data["urlscan"].get("resource_urls") or [])[:MAX_RESOURCE_INTEL_HOSTS]
            if intel_domains:
                rc_futures[("tf", "*")] = _osint_executor.submit(
                    tf_check_iocs, [], intel_domains, [], None
                )
            if intel_urls:
                rc_futures[("uh", "*")] = _osint_executor.submit(uh_check_urls, intel_urls)

            rc_results = {}
            for key, fut in rc_futures.items():
                try:
                    rc_results[key] = fut.result(timeout=45)
                except Exception as e:
                    print(f"Resource-chain lookup {key} failed: {e}")
                    rc_results[key] = {"error": str(e)}

            # Attach each verdict to the host it describes, so the report can name
            # the offending third party instead of just moving the total.
            for entry in rc_hosts:
                vt = rc_results.get(("vt", entry["host"]))
                if isinstance(vt, dict) and "error" not in vt and "stats" in vt:
                    entry["virustotal"] = vt["stats"]
                entry["checked"] = entry["host"] in vt_targets

            for key, field in ((("tf", "*"), "matched_ioc"), (("uh", "*"), "matched_url")):
                hit = rc_results.get(key) or {}
                if not isinstance(hit, dict) or not hit.get("found"):
                    continue
                indicator = hit.get(field) or ""
                if _is_suppressible_indicator(indicator):
                    print(f"Resource-chain intel suppressed: bare reputable indicator '{indicator}'")
                    continue
                resource_chain.setdefault("intel_hits", []).append(
                    {"source": "threatfox" if key[0] == "tf" else "urlhaus", **hit}
                )

        osint_data["resource_chain"] = resource_chain

        # ── Partial-intel detection ───────────────────────────────────────────
        # VirusTotal is the verdict-critical source: a completed VT lookup can add
        # +100 (or halve the heuristic score), so a VT lookup that was ATTEMPTED
        # but did NOT complete (timeout / rate-limit / still-queued) must not be
        # scored as a clean 0. Mark the scan 'partial' (surfaced in the report and
        # excluded from the 24h cache) so it is re-tried next time instead of
        # freezing a possibly-wrong answer. Scoped to VT — the documented
        # verdict-swinger — to keep caching effective for the common case.
        def _intel_incomplete(res) -> bool:
            if not isinstance(res, dict):
                return False
            if "error" in res:
                return True
            # 'rate_limited' is distinct from 'queued' — the analysis may well be
            # finished and we were merely throttled off it — but both mean no
            # verdict was obtained, which is what makes a scan partial.
            return (res.get("vt_status") or res.get("status")) in (
                "queued", "pending", "error", "rate_limited",
            )

        # Scoped to the lookup that describes THE ARTIFACT: vt_file for an upload,
        # vt_url for a submitted URL. A VT lookup on a URL merely *embedded* in a
        # file describes an indicator, not the thing submitted — the same
        # distinction artifact_total draws in scoring.
        #
        # Conflating them had a sharp edge. A binary's string table yields hosts
        # that never resolve (adjacent symbols run together, certificate blobs
        # leave trailing bytes), so that lookup routinely fails on a perfectly
        # ordinary executable. Marking the whole scan partial then vetoed the
        # benign-consensus dampening — and a signed installer that 62 VirusTotal
        # engines agreed was clean scored 73/100 because one junk string pulled
        # out of it did not resolve.
        _verdict_critical = ("vt_url",) if submitted_url else ("vt_file",)
        # VT was configured and we still got no verdict out of it: rate limited,
        # errored, still queued. We tried and failed, so the scan is partial and a
        # would-be Clear becomes Inconclusive.
        intel_partial = any(
            key in futures and _intel_incomplete(osint_results.get(key))
            for key in _verdict_critical
        )
        # Distinct case: no VT_API_KEY at all, so the lookup was never attempted.
        # This used to be invisible — `key in futures` above made an unconfigured
        # deployment the one kind of missing intel that did NOT mark a scan
        # partial, so it answered Clear to everything.
        #
        # It is deliberately NOT treated as `intel_partial`. Such a deployment
        # still runs YARA, static analysis and every format analyser, and calling
        # all of that Inconclusive would teach users to ignore the verdict
        # entirely — a worse outcome than a verdict clearly labelled as reached
        # without reputation data. It is disclosed instead, via the same `partial`
        # banner that already exists for incomplete intel.
        intel_unconfigured = any(key not in futures for key in _verdict_critical)

        # ── 3. Build analysis_data for scoring ───────────────────────────────
        analysis_data = {
            "file_hash": job.file_hash,
            # Member hashes go to the scorer so the internal blocklist can match a
            # known sample that merely arrived wrapped in an archive.
            "archive_hashes": archive_scan["hash_candidates"],
            "submitted_url": submitted_url,
            "intel_partial": intel_partial,
            "intel_unconfigured": intel_unconfigured,
            # The submitter chose hash-lookup-only and the hash was unknown, so
            # no reputation verdict exists. Their call, but it shapes the report.
            "vt_upload_declined": bool(
                (osint_results.get("vt_file") or {}).get("upload_declined")
                if isinstance(osint_results.get("vt_file"), dict) else False
            ),
            # Members that exist but could not be examined. Scoring turns a
            # would-be "Clear" into "Inconclusive" on the strength of this: a
            # scan that never saw the files cannot vouch for them.
            "unexaminable": archive_scan.get("encrypted") or [],
            # Same consequence, different cause: the format itself cannot be
            # opened here. Kept separate so the report states which it was.
            "unsupported_container": archive_scan.get("unsupported_container"),
            # Members that extracted but could not then be read — almost always
            # antivirus quarantining them between extraction and analysis, which
            # is evidence about the member rather than a tooling glitch.
            "unreadable_members": archive_scan.get("unreadable") or [],
            # We stopped unpacking at the file-count or decompressed-size cap, so
            # everything past that point was never examined. This used to be
            # attached to the scorer's OUTPUT further down, long after the
            # verdict existed, so a padded archive came back Clear.
            "archive_truncated": archive_scan.get("truncated"),
            # The artifact itself could not be read, so nothing was analysed.
            "artifact_unreadable": artifact_unreadable,
            "static": {
                "suspicious_sections": pe_info.get("suspicious_sections", []),
                "pe_sections":         pe_info.get("pe_sections", []),
                "is_pe":               pe_info.get("is_pe", False),
                "imphash":             pe_info.get("imphash"),
                "file_entropy":        pe_info.get("file_entropy", 0.0),
                "magic_type":          pe_info.get("magic_type", "Unknown"),
                "type_mismatch":       pe_info.get("type_mismatch", False),
                "suspicious_strings":  pe_info.get("suspicious_strings", []),
            },
            "osint":    {**osint_data, "yara": yara_result},
            # The same URL that was sent for external scanning, so the report's
            # heuristics and its VirusTotal/URLScan results describe one link
            # rather than two different ones. scan_target_url is risk-ranked, so
            # in a multi-link document this is the most dangerous link found,
            # not whichever happened to sort first.
            "url":      analyze_url(scan_target_url) if scan_target_url else {},
            "iocs":     iocs,
            "apk":      apk_info,
            "document": doc_info,
            "lnk":      lnk_info,
            "html":     html_info,
            "extension": extension_info,
            "script":   script_info,
        }

        # ── 4. Attribution Scoring ───────────────────────────────────────────
        score_data = calculate_score(analysis_data)

        # ── 5. Infrastructure Clustering (cross-job, via inverted index) ─────
        # Look up only PRIOR jobs sharing this job's indicators (O(k·log n)),
        # then record this job's indicators for future scans to match against.
        prior_lookup = lookup_prior_jobs(db, job_id, score_data)
        cluster_result = cluster_iocs(job_id, score_data, prior_lookup)
        score_data["clusters"] = cluster_result
        index_job_indicators(db, job_id, score_data)

        # ── 6. Merge file metadata into results ──────────────────────────────
        # Done BEFORE generate_report() so the saved HTML/PDF report sees the
        # same enriched data the frontend does (pe_sections, apk_info,
        # document_info, archive_contents, scan duration, etc.).
        score_data["file_hash"] = job.file_hash
        score_data["original_filename"] = original_filename
        score_data["scan_duration_seconds"] = round(time.time() - scan_started_at, 2)
        if submitted_url:
            score_data["submitted_url"] = submitted_url
        score_data["imphash"]   = pe_info.get("imphash")
        score_data["is_pe"]     = pe_info.get("is_pe", False)
        score_data["pe_sections"] = pe_info.get("pe_sections", [])
        if archive_contents:
            score_data["archive_contents"] = archive_contents
        # Deliberately OUTSIDE the block above. These say "part of this archive
        # was not examined", and the worst case for that is an archive where
        # NOTHING was examined — which leaves archive_contents empty and, while
        # they were gated on it, silently dropped the warning in exactly the
        # case that most needed it. A password-protected archive extracts no
        # members at all, so it never once produced a caveat.
        if archive_scan.get("truncated"):
            score_data["archive_truncated"] = archive_scan["truncated"]
        if archive_scan.get("unreadable"):
            score_data["archive_unreadable"] = archive_scan["unreadable"]
        if archive_scan.get("encrypted"):
            score_data["archive_encrypted"] = archive_scan["encrypted"]
        if archive_scan.get("unsupported_container"):
            score_data["archive_unsupported"] = archive_scan["unsupported_container"]
        if apk_info.get("is_apk"):
            score_data["apk_info"] = apk_info
        if doc_info and doc_info.get("doc_type") not in (None, "unknown"):
            score_data["document_info"] = doc_info
        if yara_result.get("yara_matches"):
            score_data["yara_matches"] = yara_result["yara_matches"]

        # ── 7. Report Generation ─────────────────────────────────────────────
        raw_meta = {
            "file_hash":         job.file_hash,
            "original_filename": original_filename,
            "is_pe":             pe_info.get("is_pe", False),
            "imphash":           pe_info.get("imphash"),
            "suspicious_sections": pe_info.get("suspicious_sections", []),
        }
        generate_report(job_id, score_data, raw_meta)

        job.results = score_data
        job.status  = "Completed"
        db.commit()

    except Exception as e:
        print(f"Job {job_id} failed: {e}")
        job.status = "Failed"
        db.commit()
    finally:
        db.close()


# ── Upload ────────────────────────────────────────────────────────────────────

@app.post("/upload")
async def upload_file(
    request: Request,
    background_tasks: BackgroundTasks,
    file: UploadFile = File(...),
    # Opt out of publishing an unknown file to VirusTotal. Uploading is how an
    # unrecognised sample gets a reputation verdict at all, so it stays on by
    # default — but anything uploaded enters VT's corpus and is downloadable by
    # its paying subscribers, which is not a trade the submitter of a private
    # document should make unknowingly. Declining costs the VT verdict, and the
    # scan says so rather than quietly returning less.
    allow_vt_upload: bool = Form(True),
):
    _enforce_rate_limit(request)
    _maintain_vault()
    content = await file.read(MAX_UPLOAD_BYTES + 1)
    if len(content) > MAX_UPLOAD_BYTES:
        raise HTTPException(status_code=413, detail=f"File exceeds maximum allowed size of {MAX_UPLOAD_BYTES // 1024 // 1024} MB.")
    file_hash = hashlib.sha256(content).hexdigest()

    file_path = os.path.join(VAULT_DIR, file_hash)
    with open(file_path, "wb") as f:
        f.write(content)

    job_id = str(uuid.uuid4())
    db = SessionLocal()
    new_job = ScanJob(job_id=job_id, file_hash=file_hash, status="Submitted")
    db.add(new_job)
    db.commit()
    db.close()

    safe_name = sanitize_filename(file.filename) if file.filename else "unknown"
    background_tasks.add_task(process_scan_job, job_id, file_path, safe_name,
                              allow_vt_upload=allow_vt_upload)

    return {"job_id": job_id, "status": "Submitted"}


# ── URL Submit ────────────────────────────────────────────────────────────────

class UrlSubmission(BaseModel):
    url: str

# Bare hostname like "example.com" (no scheme, no path) — RFC 1035-ish labels.
_DOMAIN_RE = re.compile(
    r"^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+$"
)

@app.post("/submit-url")
async def submit_url(request: Request, background_tasks: BackgroundTasks, body: UrlSubmission):
    """Accepts a raw URL string, saves it as a vault artifact, and runs the full analysis pipeline."""
    _enforce_rate_limit(request)
    _maintain_vault()
    url = body.url.strip()
    if not url:
        raise HTTPException(status_code=400, detail="URL cannot be empty")
    if len(url) > MAX_URL_LENGTH:
        raise HTTPException(status_code=400, detail=f"URL exceeds maximum length of {MAX_URL_LENGTH} characters.")
    # Accept a full http(s) URL or a bare domain (the pipeline handles both);
    # reject other schemes (file://, javascript:, ...) and arbitrary text.
    if not (url.startswith("http://") or url.startswith("https://") or _DOMAIN_RE.match(url)):
        raise HTTPException(status_code=400, detail="Submit a full http:// or https:// URL, or a plain domain name.")

    # Normalize so trivial variants (case, default port, trailing '/') map to the
    # same vault artifact and therefore the same cached verdict.
    url = _normalize_url(url)
    content = url.encode("utf-8")
    file_hash = hashlib.sha256(content).hexdigest()

    file_path = os.path.join(VAULT_DIR, file_hash)
    with open(file_path, "wb") as f:
        f.write(content)

    job_id = str(uuid.uuid4())
    db = SessionLocal()
    new_job = ScanJob(job_id=job_id, file_hash=file_hash, status="Submitted")
    db.add(new_job)
    db.commit()
    db.close()

    background_tasks.add_task(process_scan_job, job_id, file_path, url, submitted_url=url)

    return {"job_id": job_id, "status": "Submitted"}


# ── Status ────────────────────────────────────────────────────────────────────

@app.get("/status/{job_id}")
async def get_status(job_id: str):
    db = SessionLocal()
    try:
        job = db.query(ScanJob).filter(ScanJob.job_id == job_id).first()
        if not job:
            raise HTTPException(status_code=404, detail="Job not found")
        return {"job_id": job.job_id, "status": job.status, "results": job.results}
    finally:
        db.close()


# ── Image proxy ──────────────────────────────────────────────────────────────
# The frontend's PDF export screenshots the rendered report with html2canvas,
# which can't read pixels from a cross-origin image (e.g. the URLScan
# screenshot, hosted on urlscan.io) unless that server opts in with CORS
# headers — urlscan.io doesn't. Proxying it through our own origin sidesteps
# that: server-to-server fetches aren't subject to CORS at all. Locked to a
# small allowlist of known screenshot hosts so this can't become an open
# proxy for arbitrary URLs (SSRF).
PROXY_ALLOWED_HOSTS = {"urlscan.io"}

# A screenshot is a few hundred KB. Anything beyond this is not one, and
# resp.content would otherwise pull the whole body into memory.
PROXY_MAX_BYTES = 8 * 1024 * 1024


@app.get("/proxy/image")
def proxy_image(url: str):
    parsed = urlparse(url)
    if parsed.scheme != "https" or parsed.hostname not in PROXY_ALLOWED_HOSTS:
        raise HTTPException(status_code=400, detail="URL not allowed")
    try:
        # allow_redirects=False is the point of this endpoint's safety. The check
        # above validates the URL the caller supplied; requests follows redirects
        # by default, so every hop after the first was unvalidated — an open
        # redirect on the allowed host would have turned this into a proxy for
        # 169.254.169.254 (cloud metadata), localhost, or anything else the
        # server can reach. urlscan's screenshot URLs are direct, so refusing
        # redirects outright is both safe and sufficient; if that ever changes
        # the image visibly fails instead of quietly becoming SSRF.
        resp = requests.get(url, timeout=10, allow_redirects=False, stream=True)
        if resp.is_redirect or resp.is_permanent_redirect:
            resp.close()
            raise HTTPException(status_code=400, detail="Redirects are not followed")
        resp.raise_for_status()

        # Read with a ceiling rather than resp.content, which is unbounded.
        chunks, total = [], 0
        for chunk in resp.iter_content(64 * 1024):
            total += len(chunk)
            if total > PROXY_MAX_BYTES:
                resp.close()
                raise HTTPException(status_code=413, detail="Image too large")
            chunks.append(chunk)
        resp.close()
        body = b"".join(chunks)
    except HTTPException:
        raise
    except requests.RequestException:
        raise HTTPException(status_code=502, detail="Could not fetch image")

    # Never echo back an arbitrary content-type: the response is served from our
    # own origin, so "text/html" here would be stored XSS on the app's domain.
    ctype = (resp.headers.get("content-type") or "image/png").split(";")[0].strip().lower()
    if not ctype.startswith("image/"):
        ctype = "application/octet-stream"
    return Response(content=body, media_type=ctype)


# ── HTML Report ───────────────────────────────────────────────────────────────

def _load_report_html(job_id: str) -> str:
    """Shared by the HTML and PDF report endpoints below."""
    db = SessionLocal()
    try:
        job = db.query(ScanJob).filter(ScanJob.job_id == job_id).first()
    finally:
        db.close()

    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    if job.status != "Completed":
        raise HTTPException(status_code=202, detail=f"Job is not yet complete (status: {job.status})")

    report_path = get_report_path(job_id)
    if not os.path.exists(report_path):
        # Regenerate on-demand if the file was lost (e.g. container restart)
        raw_meta = {"file_hash": job.file_hash, "original_filename": "unknown"}
        generate_report(job_id, job.results, raw_meta)

    with open(report_path, "r", encoding="utf-8") as f:
        return f.read()


@app.get("/report/{job_id}", response_class=HTMLResponse)
async def get_report_html(job_id: str):
    """Serves the full HTML forensic report for a completed job."""
    html = _load_report_html(job_id)
    # Defense-in-depth: the report renders strings extracted from hostile files.
    # Template autoescaping is the primary control; CSP blocks anything that slips through.
    # script-src/style-src are scoped to the exact Leaflet CDN host (for the
    # Threat Origin map) — not 'unsafe-inline' or a wildcard, so nothing an
    # attacker-controlled filename/string could smuggle in is able to execute.
    return HTMLResponse(
        content=html,
        headers={
            "Content-Security-Policy": (
                "default-src 'none'; "
                "style-src 'unsafe-inline' https://unpkg.com; "
                "script-src https://unpkg.com; "
                "img-src data: https://*.basemaps.cartocdn.com"
            ),
            "X-Content-Type-Options": "nosniff",
        },
    )


# Where the PDF endpoint below gets its browser. Two sources, one Playwright API:
#
#   unset  → launch a local Chromium (what `playwright install chromium` puts on
#            a dev machine).
#   set    → connect over CDP to a hosted Chromium (Browserless), e.g.
#            wss://production-sfo.browserless.io/chromium?token=...
#
# The remote path is what makes PDF export work in the cloud at all. The free
# Render instance has neither the disk for a Chromium binary nor the RAM to run
# one, so it launches nothing — and the packaged Android app cannot fall back to
# rendering the PDF itself (no print handler in its WebView). "No browser on the
# server" therefore means no PDF export for every phone user, not a missing
# nicety on one box. Renting a browser over the network keeps the instance as
# light as it is today.
BROWSER_WS_ENDPOINT = os.environ.get("BROWSERLESS_WS_URL", "").strip()
BROWSER_CONNECT_TIMEOUT_MS = 30_000


@app.get("/report/{job_id}/pdf")
async def get_report_pdf(job_id: str):
    """
    Renders the same HTML report to a real PDF using headless Chromium
    (Playwright) server-side. This is deliberately not done client-side: the
    packaged app's Android WebView has no native print handler, and screenshot
    -based approaches kept hitting cross-origin canvas restrictions. Driving a
    real, full browser engine here sidesteps both — same engine that already
    prints correctly when a person does it manually from a real Chrome tab.

    The browser is launched locally or rented over the network depending on
    BROWSERLESS_WS_URL — see the constant above. Everything after the connection
    is identical on both paths.
    """
    html = _load_report_html(job_id)
    try:
        from playwright.async_api import async_playwright
    except ImportError:
        raise HTTPException(status_code=501, detail="PDF export requires the 'playwright' package (pip install playwright && playwright install chromium)")

    async with async_playwright() as p:
        if BROWSER_WS_ENDPOINT:
            try:
                browser = await p.chromium.connect_over_cdp(BROWSER_WS_ENDPOINT, timeout=BROWSER_CONNECT_TIMEOUT_MS)
            except Exception as e:
                # Deliberately NOT the 501 below. This deployment IS configured
                # for PDF export; the rented browser just did not answer (bad
                # token, exhausted quota, service down, network). Reporting that
                # as "Chromium not installed" would send whoever debugs it off
                # installing a browser on a box that is never meant to host one.
                raise HTTPException(status_code=502, detail=f"PDF export failed: could not reach the remote browser ({type(e).__name__})")
        else:
            try:
                browser = await p.chromium.launch()
            except Exception:
                # No browser available from either source: nothing installed
                # locally and no remote endpoint configured.
                raise HTTPException(status_code=501, detail="PDF export unavailable in this deployment (no headless Chromium — run `playwright install chromium`, or set BROWSERLESS_WS_URL to a hosted browser)")
        try:
            # A CDP-attached browser already has a default context; new_page()
            # would ask the remote end for a second, incognito one. Reusing what
            # is there works on both paths — a freshly launched browser simply
            # has no contexts yet.
            context = browser.contexts[0] if browser.contexts else await browser.new_context()
            page = await context.new_page()
            await page.set_content(html, wait_until="networkidle")
            pdf_bytes = await page.pdf(format="Letter", print_background=True, margin={"top": "0.4in", "bottom": "0.4in", "left": "0.4in", "right": "0.4in"})
        except Exception as e:
            # Rendering over the wire fails in ways a local launch rarely does
            # (the report waits on network-idle, and remote fonts are fetched
            # from the rented browser's network). Surface it as a gateway error
            # rather than an unhandled 500 stack trace.
            raise HTTPException(status_code=502, detail=f"PDF rendering failed ({type(e).__name__})")
        finally:
            await browser.close()

    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="MalScan_Report_{job_id[:8]}.pdf"'},
    )


# ── JSON Report (for frontend graph) ─────────────────────────────────────────

@app.get("/report/{job_id}/json")
async def get_report_json(job_id: str):
    """
    Returns the full structured results JSON for a completed job.
    Includes graph_nodes, graph_edges, clusters — used by the frontend
    to render the live infrastructure graph widget.
    """
    db = SessionLocal()
    try:
        job = db.query(ScanJob).filter(ScanJob.job_id == job_id).first()
    finally:
        db.close()

    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    if job.status != "Completed":
        raise HTTPException(status_code=202, detail=f"Job not yet complete (status: {job.status})")

    return job.results
