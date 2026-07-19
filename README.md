# MALSCAN

A malware / threat-intelligence scanning platform. Upload a file or submit a URL and get back a full forensic report: static analysis (IOCs, PE metadata, entropy, YARA), OSINT enrichment (VirusTotal, URLScan, AbuseIPDB, MalwareBazaar, ThreatFox, URLhaus, WHOIS, DNS, GeoIP), a 0–100 threat score with verdict/attribution, and an infrastructure graph linking related scans.

- **`backend/`** — FastAPI service (API, analysis engine, scoring/attribution engine)
- **`frontend/`** — Next.js web app, also packaged as a native Android APK via Capacitor

A live backend is deployed on Render at `https://malscan-api.onrender.com` (free tier — see [docs/RUNNING.md](docs/RUNNING.md#cloud-backend-render) for cold-start/limits notes).

## Quick start

```powershell
# Backend
cd backend
pip install -r requirements.txt -r analysis_engine/requirements.txt -r attribution_module/requirements.txt
uvicorn app.main:app --reload --port 8001

# Frontend (new terminal)
cd frontend
npm install
npm run dev   # http://localhost:3000
```

See **[docs/RUNNING.md](docs/RUNNING.md)** for full setup (API keys, tests, building the Android APK, deploying to Render/Vercel).

For AI-assisted development in this repo, see [CLAUDE.md](CLAUDE.md).
