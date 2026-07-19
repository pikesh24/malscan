"""
backend/app/main.py

FastAPI application: file-upload and URL-submission endpoints, the scan
pipeline (process_scan_job), and the status / report endpoints.
"""

import hashlib, os, re, uuid, sys, time, zipfile, tempfile, shutil
import asyncio
from collections import defaultdict, deque
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urlparse
import requests

# ── Safety limits ─────────────────────────────────────────────────────────────
MAX_UPLOAD_BYTES      = 50  * 1024 * 1024   # 50 MB hard cap
MAX_DECOMPRESSED_BYTES = 200 * 1024 * 1024  # 200 MB total decompressed
MAX_ZIP_FILE_COUNT    = 500                  # files inside a ZIP
MAX_URL_LENGTH        = 2048                 # /submit-url input cap
RATE_LIMIT_MAX        = 30                   # submissions per window per client IP
RATE_LIMIT_WINDOW_S   = 60
from dotenv import load_dotenv
from fastapi import BackgroundTasks, FastAPI, UploadFile, File, HTTPException, Request
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
    from analysis_engine.static_analyzer import extract_iocs, analyze_pe, analyze_suspicious_strings
    from analysis_engine.osint_enricher import get_whois, get_dns_records, get_geoip
    from analysis_engine.url_processor import analyze_url
    from analysis_engine.vt_client import get_url_report, get_file_report
    from analysis_engine.urlscan_client import scan_url as urlscan_scan
    from analysis_engine.apk_analyzer import analyze_apk
    from analysis_engine.document_analyzer import analyze_document
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
cleanup_vault(VAULT_DIR, days_old=30)

# ── Rate limiting (in-memory, per client IP) ──────────────────────────────────
_submission_log: dict = defaultdict(deque)

def _enforce_rate_limit(request: Request) -> None:
    """Sliding-window limiter for submission endpoints. Raises 429 when exceeded."""
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

# ── URL Allowlist — skip these safe domains for URLScan / analysis ────────────
SAFE_DOMAIN_PATTERNS = {
    "microsoft.com", "google.com", "googleapis.com", "gstatic.com",
    "w3.org", "xmlsoap.org", "openxmlformats.org", "xml.org",
    "apache.org", "java.sun.com", "sun.com", "oracle.com",
    "mozilla.org", "mozilla.com", "webkit.org",
    "github.com", "githubusercontent.com",
    "localhost", "127.0.0.1", "0.0.0.0", "::1",
    "schemas.microsoft.com", "purl.org", "dublincore.org",
    "apple.com", "adobe.com", "verisign.com",
    # RFC 2606 reserved documentation/placeholder domains — never real
    # infrastructure, but low-quality threat-intel feeds sometimes tag them
    # anyway (e.g. an unconfigured malware-config default gets submitted as
    # an IOC by mistake). Any hit against these is definitionally noise.
    # NOTE: this list deletes a domain from the report entirely (no IOC, no
    # geolocation, no URLScan) — only ever add genuinely meaningless
    # boilerplate here (reserved names, XML/schema namespaces). Real third-
    # party infrastructure (jetbrains.com, crbug.com, analytics/ad SDKs) is
    # deliberately NOT listed: it isn't a threat, but it's real context the
    # report should still show and enrich.
    "example.com", "example.net", "example.org", "example.edu",
    # Android manifest/schema XML namespace — the schemas.android.com
    # equivalent of schemas.microsoft.com above; every Android app embeds it.
    "schemas.android.com",
}

def _is_safe_host(host: str) -> bool:
    """Returns True if a hostname belongs to a known-safe / metadata-namespace domain."""
    host = (host or "").lower().split(":")[0]
    return any(host == s or host.endswith("." + s) for s in SAFE_DOMAIN_PATTERNS)

def _is_safe_url(url: str) -> bool:
    """Returns True if the URL belongs to a known-safe domain."""
    try:
        from urllib.parse import urlparse
        return _is_safe_host(urlparse(url).netloc)
    except Exception:
        return False

def _strip_safe_indicators(iocs: dict, keep: str = None) -> None:
    """Drop known-safe / metadata-namespace indicators from `iocs` in place.

    Every PDF/Office document embeds boilerplate XML-namespace URLs (e.g.
    http://www.w3.org/... and http://ns.adobe.com/...). Left in, these benign
    identifiers get sent to ThreatFox/URLhaus (where a low-confidence match can
    flag the file), resolved to a hosting IP (a misleading "threat origin"), and
    scored as "not HTTPS" URL anomalies. This removes them before any of that.
    `keep` (the deliberately-submitted URL/domain) is always preserved.
    """
    keep_set = {keep} if keep else set()
    iocs["urls"]    = [u for u in (iocs.get("urls") or [])    if u in keep_set or not _is_safe_url(u)]
    iocs["domains"] = [d for d in (iocs.get("domains") or []) if d in keep_set or not _is_safe_host(d)]

def _pick_best_url(urls: list) -> str | None:
    """Returns the first URL that isn't from a known-safe domain, or None."""
    for url in (urls or []):
        if not _is_safe_url(url):
            return url
    return None

_osint_executor = ThreadPoolExecutor(max_workers=8, thread_name_prefix="osint")
init_db()

# One-time backfill of the indicator index from existing completed jobs
# (idempotent — no-op once populated, and a no-op on a fresh/test DB).
_bf_db = SessionLocal()
try:
    backfill_indicator_index(_bf_db)
finally:
    _bf_db.close()


def process_scan_job(job_id: str, file_path: str, original_filename: str = "unknown", submitted_url: str = None):
    db = SessionLocal()
    job = db.query(ScanJob).filter(ScanJob.job_id == job_id).first()
    if not job:
        db.close()
        return

    try:
        job.status = "Processing"
        db.commit()

        # ── 1. Static Analysis ───────────────────────────────────────────────
        # Read the artifact once and reuse the bytes across analyzers, instead of
        # re-reading a (up to 50 MB) file from disk for each pass.
        try:
            with open(file_path, "rb") as f:
                raw_bytes = f.read()
        except Exception:
            raw_bytes = None
        iocs    = extract_iocs(file_path, data=raw_bytes)
        pe_info = analyze_pe(file_path, data=raw_bytes)
        apk_info = {}
        archive_contents = []

        # ── 1b. ZIP Extraction (Zip-Slip safe) ────────────────────────────────
        is_zip = zipfile.is_zipfile(file_path)
        if is_zip and not original_filename.lower().endswith(".apk"):
            extract_dir = None
            try:
                extract_dir = tempfile.mkdtemp(prefix="malscan_zip_")
                with zipfile.ZipFile(file_path, "r") as zf:
                    members = zf.infolist()

                    # ── ZIP bomb: too many files ──────────────────────────────
                    if len(members) > MAX_ZIP_FILE_COUNT:
                        print(f"ZIP bomb blocked: {len(members)} files exceeds limit of {MAX_ZIP_FILE_COUNT}")
                        members = members[:MAX_ZIP_FILE_COUNT]

                    total_decompressed = 0
                    for member in members:
                        # ── ZIP bomb: decompressed size limit ─────────────────
                        total_decompressed += member.file_size
                        if total_decompressed > MAX_DECOMPRESSED_BYTES:
                            print(f"ZIP bomb blocked: decompressed size exceeds {MAX_DECOMPRESSED_BYTES // 1024 // 1024} MB")
                            break

                        # ── Zip Slip protection ───────────────────────────────
                        # commonpath avoids the prefix-sibling bug of a bare
                        # startswith (e.g. "/x/dir" vs "/x/dir_evil") and an
                        # absolute/other-drive member path (ValueError → outside).
                        real_extract_dir = os.path.realpath(extract_dir)
                        member_path = os.path.realpath(os.path.join(extract_dir, member.filename))
                        try:
                            inside = os.path.commonpath([real_extract_dir, member_path]) == real_extract_dir
                        except ValueError:
                            inside = False
                        if not inside:
                            print(f"Zip Slip blocked: {member.filename}")
                            continue
                        if member.is_dir():
                            os.makedirs(member_path, exist_ok=True)
                            continue
                        os.makedirs(os.path.dirname(member_path), exist_ok=True)
                        with zf.open(member) as src, open(member_path, "wb") as dst:
                            dst.write(src.read())

                    for root, dirs, files in os.walk(extract_dir):
                        for fname in files:
                            inner_path = os.path.join(root, fname)
                            inner_iocs = extract_iocs(inner_path)
                            inner_pe   = analyze_pe(inner_path)
                            for k in ("ips", "domains", "urls"):
                                iocs[k] = list(set(iocs.get(k, []) + inner_iocs.get(k, [])))
                            pe_info["suspicious_sections"].extend(inner_pe.get("suspicious_sections", []))
                            if inner_pe.get("is_pe"):
                                pe_info["is_pe"] = True
                                pe_info["imphash"] = pe_info.get("imphash") or inner_pe.get("imphash")
                            archive_contents.append({
                                "name": fname,
                                "is_pe": inner_pe.get("is_pe", False),
                                "ioc_count": len(inner_iocs.get("urls", [])) + len(inner_iocs.get("ips", [])),
                            })
            except Exception as ze:
                print(f"ZIP extraction error: {ze}")
            finally:
                # Always clean up temp extraction directory
                if extract_dir and os.path.exists(extract_dir):
                    shutil.rmtree(extract_dir, ignore_errors=True)

        # ── 1c. APK Analysis ─────────────────────────────────────────────────
        if original_filename.lower().endswith(".apk"):
            apk_info = analyze_apk(file_path)
            for k in ("ips", "urls"):
                apk_key = f"dex_{k}"
                iocs[k] = list(set(iocs.get(k, []) + apk_info.get(apk_key, [])))

        # ── 1d. Document Analysis (PDF / Office / OLE) ───────────────────────
        doc_info = analyze_document(file_path, original_filename)

        # ── 1e. Suspicious string patterns ───────────────────────────────────
        string_info = analyze_suspicious_strings(file_path, data=raw_bytes)
        pe_info["suspicious_strings"] = string_info.get("suspicious_strings", [])

        # ── 1f. YARA scan ────────────────────────────────────────────────────
        yara_result = yara_scan_file(file_path)

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
        urls = iocs["urls"]
        domains = iocs["domains"]

        ips = iocs.get("ips", [])
        vt_key = os.environ.get("VT_API_KEY")
        us_key = os.environ.get("URLSCAN_API_KEY")

        # Pick the best (non-safe) URL for external scanning
        scan_target_url = submitted_url or _pick_best_url(iocs.get("urls", []))

        # Build a list of futures to run concurrently
        futures = {}
        if domains:
            futures["whois"] = loop.run_in_executor(_osint_executor, get_whois, domains[0])
            futures["dns"]   = loop.run_in_executor(_osint_executor, get_dns_records, domains[0])
        import ipaddress
        import socket
        public_ips = []
        for ip in ips:
            try:
                if not ipaddress.ip_address(ip).is_private:
                    public_ips.append(ip)
            except ValueError:
                pass

        if not public_ips and domains:
            try:
                resolved_ip = socket.gethostbyname(domains[0])
                if not ipaddress.ip_address(resolved_ip).is_private:
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
            futures["vt_file"] = loop.run_in_executor(
                _osint_executor, get_file_report, job.file_hash, vt_key, file_path
            )

        # ── New: abuse.ch threat intelligence (no key required) ──────────────
        futures["malwarebazaar"] = loop.run_in_executor(
            _osint_executor, mb_check_hash, job.file_hash
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

        # ── 3. Build analysis_data for scoring ───────────────────────────────
        analysis_data = {
            "file_hash": job.file_hash,
            "static": {
                "suspicious_sections": pe_info.get("suspicious_sections", []),
                "is_pe":               pe_info.get("is_pe", False),
                "imphash":             pe_info.get("imphash"),
                "file_entropy":        pe_info.get("file_entropy", 0.0),
                "magic_type":          pe_info.get("magic_type", "Unknown"),
                "type_mismatch":       pe_info.get("type_mismatch", False),
                "suspicious_strings":  pe_info.get("suspicious_strings", []),
            },
            "osint":    {**osint_data, "yara": yara_result},
            "url":      analyze_url(_pick_best_url(iocs.get("urls", [])) or (iocs["urls"][0] if iocs.get("urls") else "")) if iocs.get("urls") else {},
            "iocs":     iocs,
            "apk":      apk_info,
            "document": doc_info,
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

        # ── 6. Report Generation ─────────────────────────────────────────────
        raw_meta = {
            "file_hash":         job.file_hash,
            "original_filename": original_filename,
            "is_pe":             pe_info.get("is_pe", False),
            "imphash":           pe_info.get("imphash"),
            "suspicious_sections": pe_info.get("suspicious_sections", []),
        }
        generate_report(job_id, score_data, raw_meta)

        # Merge file metadata into results so frontend can display them
        score_data["file_hash"] = job.file_hash
        score_data["original_filename"] = original_filename
        if submitted_url:
            score_data["submitted_url"] = submitted_url
        score_data["imphash"]   = pe_info.get("imphash")
        if archive_contents:
            score_data["archive_contents"] = archive_contents
        if apk_info.get("is_apk"):
            score_data["apk_info"] = apk_info
        if doc_info and doc_info.get("doc_type") not in (None, "unknown"):
            score_data["document_info"] = doc_info
        if yara_result.get("yara_matches"):
            score_data["yara_matches"] = yara_result["yara_matches"]

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
async def upload_file(request: Request, background_tasks: BackgroundTasks, file: UploadFile = File(...)):
    _enforce_rate_limit(request)
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
    background_tasks.add_task(process_scan_job, job_id, file_path, safe_name)

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
    url = body.url.strip()
    if not url:
        raise HTTPException(status_code=400, detail="URL cannot be empty")
    if len(url) > MAX_URL_LENGTH:
        raise HTTPException(status_code=400, detail=f"URL exceeds maximum length of {MAX_URL_LENGTH} characters.")
    # Accept a full http(s) URL or a bare domain (the pipeline handles both);
    # reject other schemes (file://, javascript:, ...) and arbitrary text.
    if not (url.startswith("http://") or url.startswith("https://") or _DOMAIN_RE.match(url)):
        raise HTTPException(status_code=400, detail="Submit a full http:// or https:// URL, or a plain domain name.")

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

@app.get("/proxy/image")
def proxy_image(url: str):
    parsed = urlparse(url)
    if parsed.scheme != "https" or parsed.hostname not in PROXY_ALLOWED_HOSTS:
        raise HTTPException(status_code=400, detail="URL not allowed")
    try:
        resp = requests.get(url, timeout=10)
        resp.raise_for_status()
    except requests.RequestException:
        raise HTTPException(status_code=502, detail="Could not fetch image")
    return Response(content=resp.content, media_type=resp.headers.get("content-type", "image/png"))


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
    return HTMLResponse(
        content=html,
        headers={
            "Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'; img-src data:",
            "X-Content-Type-Options": "nosniff",
        },
    )


@app.get("/report/{job_id}/pdf")
async def get_report_pdf(job_id: str):
    """
    Renders the same HTML report to a real PDF using headless Chromium
    (Playwright) server-side. This is deliberately not done client-side: the
    packaged app's Android WebView has no native print handler, and screenshot
    -based approaches kept hitting cross-origin canvas restrictions. Driving a
    real, full browser engine here sidesteps both — same engine that already
    prints correctly when a person does it manually from a real Chrome tab.
    """
    html = _load_report_html(job_id)
    try:
        from playwright.async_api import async_playwright
    except ImportError:
        raise HTTPException(status_code=501, detail="PDF export requires the 'playwright' package (pip install playwright && playwright install chromium)")

    async with async_playwright() as p:
        try:
            browser = await p.chromium.launch()
        except Exception:
            # Chromium itself isn't installed (e.g. cloud deploys skip the heavy
            # `playwright install chromium` step) — same remedy as a missing package.
            raise HTTPException(status_code=501, detail="PDF export unavailable in this deployment (headless Chromium not installed — run: playwright install chromium)")
        try:
            page = await browser.new_page()
            await page.set_content(html, wait_until="networkidle")
            pdf_bytes = await page.pdf(format="Letter", print_background=True, margin={"top": "0.4in", "bottom": "0.4in", "left": "0.4in", "right": "0.4in"})
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
