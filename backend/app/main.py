"""
backend/app/main.py
Team Member 2 — Backend & Integration Engineer (wiring updated by TM4)

Changes made by Team Member 4:
  - Pass iocs into analysis_data so scoring.py can use them
  - Call cluster_iocs() after scoring and merge result into score_data
  - Call generate_report() after job completes
  - Add GET /report/{job_id} endpoint to serve the HTML report
  - Add GET /report/{job_id}/json endpoint for frontend graph data
  - Remove hardcoded dummy fallback data
  - Store original_filename in job for the report
"""

import hashlib, os, uuid, sys, time
from dotenv import load_dotenv
from fastapi import BackgroundTasks, FastAPI, UploadFile, File, HTTPException, Body
from pydantic import BaseModel
from fastapi.responses import HTMLResponse
from .database import SessionLocal, init_db
from .models import ScanJob

# Load .env from backend directory
load_dotenv(os.path.join(os.path.dirname(__file__), '..', '.env'))

parent_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '../../'))
if parent_dir not in sys.path:
    sys.path.insert(0, parent_dir)

try:
    from analysis_engine.static_analyzer import extract_iocs, analyze_pe
    from analysis_engine.osint_enricher import get_whois, get_dns_records, get_geoip
    from analysis_engine.url_processor import analyze_url
    from analysis_engine.vt_client import get_url_report
    from analysis_engine.urlscan_client import scan_url as urlscan_scan
    from attribution_module.scoring import calculate_score
    from attribution_module.clustering import cluster_iocs
    from attribution_module.reporter import generate_report, get_report_path
except ImportError as e:
    print(f"Warning: Module import failed: {e}")

app = FastAPI()
VAULT_DIR = "app/vault"
os.makedirs(VAULT_DIR, exist_ok=True)
init_db()


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
        iocs    = extract_iocs(file_path)
        pe_info = analyze_pe(file_path)

        # ── 2. OSINT Enrichment ──────────────────────────────────────────────
        osint_data = {}

        # WHOIS — use first extracted domain if available
        domains = iocs.get("domains", [])
        if domains:
            osint_data["whois"] = get_whois(domains[0])
            osint_data["dns"]   = get_dns_records(domains[0])

        # GeoIP — use first extracted IP if available
        ips = iocs.get("ips", [])
        if ips:
            osint_data["geoip"] = get_geoip(ips[0])

        # ── VirusTotal + URLScan.io Integration ─────────────────────────────
        # Determine the primary URL to scan (submitted URL or first extracted)
        scan_target_url = submitted_url or (iocs.get("urls", [None])[0] if iocs.get("urls") else None)

        if scan_target_url:
            vt_key = os.environ.get("VT_API_KEY")
            if vt_key:
                vt_result = get_url_report(scan_target_url, vt_key)
                if "error" not in vt_result:
                    osint_data["virustotal"] = vt_result

            us_key = os.environ.get("URLSCAN_API_KEY")
            if us_key:
                us_result = urlscan_scan(scan_target_url, us_key)
                osint_data["urlscan"] = us_result  # Pass to frontend even on error

        # ── 3. Build analysis_data for scoring ───────────────────────────────
        analysis_data = {
            "file_hash": job.file_hash,   # <-- enables known-hash detection
            "static": {
                "suspicious_sections": pe_info.get("suspicious_sections", []),
                "is_pe":    pe_info.get("is_pe", False),
                "imphash":  pe_info.get("imphash"),
            },
            "osint": osint_data,
            "url":   analyze_url(iocs["urls"][0]) if iocs.get("urls") else {},
            "iocs":  iocs,
        }

        # ── 4. Attribution Scoring ───────────────────────────────────────────
        score_data = calculate_score(analysis_data)

        # ── 5. Infrastructure Clustering (cross-job) ─────────────────────────
        all_completed_jobs = (
            db.query(ScanJob)
              .filter(ScanJob.status == "Completed")
              .all()
        )
        cluster_result = cluster_iocs(job_id, score_data, all_completed_jobs)
        score_data["clusters"] = cluster_result

        # ── 6. Report Generation ─────────────────────────────────────────────
        raw_meta = {
            "file_hash":         job.file_hash,
            "original_filename": original_filename,
            "is_pe":             pe_info.get("is_pe", False),
            "imphash":           pe_info.get("imphash"),
            "suspicious_sections": pe_info.get("suspicious_sections", []),
        }
        generate_report(job_id, score_data, raw_meta)

        # ── 7. Simulate processing delay for UI realism ──────────────────────
        time.sleep(3)

        # Merge file metadata into results so frontend can display them
        score_data["file_hash"] = job.file_hash
        score_data["imphash"]   = pe_info.get("imphash")

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
async def upload_file(background_tasks: BackgroundTasks, file: UploadFile = File(...)):
    content = await file.read()
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

    background_tasks.add_task(process_scan_job, job_id, file_path, file.filename or "unknown")

    return {"job_id": job_id, "status": "Submitted"}


# ── URL Submit ────────────────────────────────────────────────────────────────

class UrlSubmission(BaseModel):
    url: str

@app.post("/submit-url")
async def submit_url(background_tasks: BackgroundTasks, body: UrlSubmission):
    """Accepts a raw URL string, saves it as a vault artifact, and runs the full analysis pipeline."""
    url = body.url.strip()
    if not url:
        raise HTTPException(status_code=400, detail="URL cannot be empty")

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


# ── HTML Report ───────────────────────────────────────────────────────────────

@app.get("/report/{job_id}", response_class=HTMLResponse)
async def get_report_html(job_id: str):
    """Serves the full HTML forensic report for a completed job."""
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
        html = f.read()

    return HTMLResponse(content=html)


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
