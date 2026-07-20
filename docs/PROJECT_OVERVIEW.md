# MALSCAN — Project Overview (for design/theme discussion)

## What this project is

MALSCAN is a malware and threat-intelligence scanning platform, built as a school/portfolio
project. A user uploads a file (or submits a URL) and the system produces a full forensic
report:

- **Static analysis** — IOCs (indicators of compromise), PE metadata, entropy analysis, YARA
  rule matches
- **OSINT enrichment** — pulls data from VirusTotal, URLScan, AbuseIPDB, MalwareBazaar,
  ThreatFox, URLhaus, WHOIS, DNS, and GeoIP
- **Scoring & attribution** — a 0–100 threat score with a verdict and likely attribution
- **Infrastructure graph** — links related scans together (shared IPs, domains, hashes, etc.)

## Architecture

- **`backend/`** — FastAPI service. Contains the analysis engine (static analysis, OSINT
  clients per data source) and the attribution module (scoring, clustering, chart generation
  for reports).
- **`frontend/`** — Next.js web app. Also packaged as a native Android APK via Capacitor, so
  it needs to work well both as a responsive website and as a mobile app.

A live backend is deployed on Render; the frontend can run standalone or wrapped as the APK.

## Key screens (what a redesign touches)

- **Landing / upload page** (`app/page.tsx`) — drag-and-drop file upload + URL submission entry
  point. This is the first impression of the tool.
- **Report page** (`app/report/page.tsx`) — the actual deliverable: charts and visualizations
  including an entropy chart, a geo map of infrastructure, a relationship graph widget, a risk
  radar, and a VirusTotal-results donut chart, plus a score composition breakdown.
- **Settings page** (`app/settings/page.tsx`)

## Current visual identity

Right now the UI leans **stark / editorial / "brutalist security tool"**:

- Off-white background (`#F5F5F3`) with near-black text (`#121212`)
- A single loud accent color — safety orange (`#FF3B00`) — used for CTAs, highlights, and hover
  states
- Heavy uppercase, wide letter-spacing, monospace labels (`font-mono`, `tracking-widest`) —
  reads like a terminal/dossier aesthetic
- Huge oversized display type on the landing page ("VISUALIZED.")
- Hard 2px black borders instead of soft shadows/rounded cards
- Subtle grain/texture overlay images for a "scanned document" feel

This is a deliberate, opinionated look — not a generic template — which is worth stating
explicitly when comparing against new theme options, since some redesigns (e.g. very soft
SaaS-dashboard styles) would be a real personality change, not just a coat of paint.

## Why this doc exists

The project is being brought back to a professor for feedback. Structured, data-heavy reports
with lots of charts are what he's specifically asked for so far ("more graphs"), but his
reactions are hard to read — he doesn't give strong positive or negative signals either way.
The plan is to generate a few alternative visual themes (e.g. via Claude / Google Stitch) and
bring concrete options to the next meeting, rather than guessing at one redesign and hoping it
lands.

When evaluating theme options against this project, prioritize:

1. **Legibility of dense data** — the report page is charts + tables + IOC lists; a theme has
   to hold up under real data density, not just a hero section.
2. **"Security tool" credibility** — themes that read as playful/consumer-grade may undercut the
   malware-analysis subject matter.
3. **Consistency across surfaces** — same theme needs to work on the upload page, the dense
   report page, and the Android APK wrapper.
