"""
attribution_module/reporter.py

generate_report(job_id, score_data, raw_data) is called by main.py
once a job reaches "Completed" status.

Also exposes get_report_path(job_id) so the /report/{job_id} API
endpoint can serve the saved HTML file, and get_report_pdf() (main.py)
renders this same HTML to a PDF with headless Chromium.

Styled to match the live web report (frontend/app/report/) — light
canvas, orange accent, Geist Sans/Mono — laid out as a numbered dossier
so a reader can scan verdict -> evidence -> recommendation in order.
"""

import os
import logging
from datetime import datetime

from jinja2 import Template
from markupsafe import Markup

from attribution_module.report_charts import (
    render_gauge,
    render_radar,
    render_score_bars,
    render_entropy_chart,
    render_vt_donut,
    render_infra_graph,
    render_geo_map,
)

logger = logging.getLogger(__name__)

REPORTS_DIR = os.path.join(os.path.dirname(__file__), "..", "reports")


# ── Narrative helpers ────────────────────────────────────────────────────────
# Plain strings (not Markup) — Jinja's autoescaping handles these when they're
# dropped into {{ }}, same as any other value derived from the artifact.

def _technical_summary(score_data: dict, raw_data: dict) -> str:
    """One dense sentence for the 'for the technical reader' callout, built
    only from fields the pipeline actually computed — never fabricated."""
    parts = []

    is_pe = score_data.get("is_pe") or raw_data.get("is_pe")
    if is_pe:
        pe_sections = score_data.get("pe_sections") or []
        packed = [s for s in pe_sections if (s.get("entropy") or 0) > 7.0]
        detail = "PE32 Windows executable"
        if packed:
            names = ", ".join(s.get("name", "?") for s in packed[:3])
            detail += f" with {len(packed)} high-entropy section(s) ({names}) consistent with packing/encryption"
        imphash = score_data.get("imphash") or raw_data.get("imphash")
        if imphash:
            detail += f", imphash {imphash[:16]}…"
        parts.append(detail)

    doc_info = score_data.get("document_info") or {}
    doc_flags = []
    if doc_info.get("has_macros"):
        doc_flags.append("embedded macros")
    if doc_info.get("has_javascript"):
        doc_flags.append("embedded JavaScript")
    if doc_info.get("has_auto_action") or doc_info.get("has_launch_action"):
        doc_flags.append("auto-run/launch actions")
    if doc_flags:
        parts.append(f"{(doc_info.get('doc_type') or 'document').upper()} document containing " + ", ".join(doc_flags))

    apk_info = score_data.get("apk_info") or {}
    if apk_info.get("is_apk"):
        dangerous = apk_info.get("dangerous_permissions") or []
        parts.append(f"Android APK requesting {len(dangerous)} dangerous permission(s)" if dangerous else "Android APK")

    vt = (score_data.get("osint_summary") or {}).get("virustotal")
    if vt:
        total = sum(vt.get(k, 0) for k in ("malicious", "suspicious", "harmless", "undetected"))
        if total:
            parts.append(f"{vt.get('malicious', 0)}/{total} VirusTotal vendors flag this as malicious")

    family = score_data.get("family")
    if family and family != "Unknown":
        parts.append(f"tentatively classified as {family}")

    if not parts:
        return "No structural anomalies were identified during static analysis."
    summary = "; ".join(parts)
    return summary[:1].upper() + summary[1:] + "."


def _recommendations(verdict: str, is_url: bool) -> list:
    if verdict == "Inconclusive":
        return [
            "This scan could not be completed — VirusTotal did not respond, so this is NOT a clean result.",
            "Re-scan before making any trust decision; the earlier lookup usually succeeds on a retry.",
            "Until then, treat the artifact as unverified: do not run or visit it outside a disposable sandbox.",
            "If repeated scans stay inconclusive, check the backend's VirusTotal API key and rate-limit status.",
        ]
    if verdict == "Malicious":
        return [
            "Do not open, run, or interact with this artifact on a device or account you care about.",
            "Isolate it — a disposable sandbox or an air-gapped VM only, if further inspection is required.",
            "If it has already run or been visited, disconnect the affected device from the network and begin incident response.",
            "Rotate any credentials entered on or near this artifact, and check for unfamiliar startup entries, scheduled tasks, or browser extensions.",
        ]
    if verdict == "Suspicious":
        return [
            "Treat this as unverified, not safe — the signals here are inconclusive rather than a clean bill of health.",
            "Avoid running or visiting it outside a disposable sandbox or a VM with networking disabled.",
            "Prefer the official source for this URL/domain instead." if is_url else "Prefer an official, signed distribution of this software instead.",
            "Re-scan after a few days — vendor reputation, domain age, and hosting signals can change quickly.",
        ]
    return [
        "No indicators of compromise were found, but a clean scan is not an absolute guarantee — stay alert to unexpected behavior.",
        "Keep the source application and operating system up to date.",
        "If this artifact's behavior changes after use (unexpected pop-ups, new processes, network activity), re-submit it for a fresh scan.",
    ]


def _artifact_type(score_data: dict, raw_data: dict) -> tuple:
    """Returns (type label, subtext) for the at-a-glance strip — derived only
    from fields we actually populated, no guessed file internals."""
    if score_data.get("is_pe") or raw_data.get("is_pe"):
        return "Windows PE Executable", "native binary"
    apk_info = score_data.get("apk_info") or {}
    if apk_info.get("is_apk"):
        return "Android APK", apk_info.get("package") or "package archive"
    doc_info = score_data.get("document_info") or {}
    doc_type = doc_info.get("doc_type")
    if doc_type == "pdf":
        return "PDF Document", f"{doc_info.get('page_count')} page(s)" if doc_info.get("page_count") else "portable document"
    if doc_type == "ooxml":
        return "Office Document", "OOXML (docx/xlsx/pptx)"
    if doc_type == "ole":
        return "Office Document", "legacy OLE format"
    if score_data.get("archive_contents"):
        return "Archive", f"{len(score_data['archive_contents'])} file(s)"
    if score_data.get("submitted_url"):
        return "URL / Web Target", "remote resource"
    return "Generic File", "no PE/document structure detected"


# ── HTML template ────────────────────────────────────────────────────────────

REPORT_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>MalScan Report {{ job_id }}</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Geist:wght@400;500;600;700&family=Geist+Mono:wght@400;500;600;700&display=swap" rel="stylesheet">
<style>
  *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
  :root {
    --bg:      #F5F5F3;
    --surface: #ffffff;
    --ink:     #121212;
    --muted:   #6b7280;
    --muted-2: #9ca3af;
    --border:  #e5e7eb;
    --accent:  #FF3B00;
    --green:   #22c55e;
    --amber:   #f59e0b;
    --red:     #ef4444;
    --panel:   #0d1117;
    --panel-border: #1f2937;
    --sans: 'Geist', ui-sans-serif, system-ui, -apple-system, sans-serif;
    --mono: 'Geist Mono', ui-monospace, monospace;
  }
  body { background: var(--bg); color: var(--ink); font-family: var(--sans); font-size: 12.5px; line-height: 1.6; padding: 34px 38px; }
  .avoid { break-inside: avoid; }
  .mono { font-family: var(--mono); }

  /* ---- masthead ---- */
  header.masthead { display: flex; justify-content: space-between; align-items: flex-end; gap: 24px; border-bottom: 3px solid var(--ink); padding-bottom: 14px; }
  .brand { display: flex; align-items: center; gap: 9px; }
  .brand-mark { width: 15px; height: 15px; background: var(--accent); transform: rotate(45deg); display: inline-block; }
  .brand-name { font-family: var(--mono); font-weight: 700; font-size: 25px; letter-spacing: -0.01em; }
  .brand-tag { font-family: var(--mono); font-size: 9px; letter-spacing: 0.14em; text-transform: uppercase; color: var(--muted); margin-top: 5px; }
  .meta-grid { display: grid; grid-template-columns: max-content max-content; gap: 3px 18px; font-family: var(--mono); font-size: 9.5px; text-align: right; white-space: nowrap; }
  .meta-grid .k { color: var(--muted-2); letter-spacing: 0.06em; }
  .meta-grid .v { font-weight: 600; }

  /* ---- section headers ---- */
  .sec { margin-top: 32px; }
  .sec-head { display: flex; align-items: baseline; gap: 10px; margin-bottom: 14px; }
  .sec-num { font-family: var(--mono); font-weight: 700; font-size: 11px; color: var(--accent); }
  .sec-title { font-family: var(--mono); font-weight: 600; font-size: 11.5px; letter-spacing: 0.13em; text-transform: uppercase; }
  .sec-rule { flex: 1; height: 1px; background: var(--border); }

  /* ---- hero verdict ---- */
  .hero { display: grid; grid-template-columns: 1fr 210px; gap: 26px; align-items: center; margin-top: 22px; }
  .hero-label { font-family: var(--mono); font-size: 9.5px; letter-spacing: 0.16em; text-transform: uppercase; color: var(--muted); }
  .hero-verdict { font-family: var(--mono); font-weight: 700; font-size: 46px; line-height: 1; letter-spacing: -0.02em; margin: 6px 0 12px; }
  .hero-body { font-size: 13.5px; line-height: 1.6; max-width: 60ch; }
  .tech-callout { margin-top: 14px; padding: 9px 12px; background: #f4f1ea; border-left: 3px solid #cbbfa8; font-family: var(--mono); font-size: 9.5px; line-height: 1.6; color: #4a453f; }
  .tech-callout .tag { color: var(--muted); letter-spacing: 0.07em; }

  /* ---- at-a-glance ---- */
  .glance { display: grid; grid-template-columns: repeat(4,1fr); border: 1px solid var(--border); border-radius: 6px; overflow: hidden; }
  .glance > div { padding: 11px 13px; border-right: 1px solid var(--border); }
  .glance > div:last-child { border-right: none; }
  .glance .k { font-family: var(--mono); font-size: 8px; letter-spacing: 0.1em; text-transform: uppercase; color: var(--muted-2); }
  .glance .v { font-family: var(--mono); font-weight: 600; font-size: 12.5px; margin-top: 5px; }
  .glance .s { font-size: 9.5px; color: var(--muted); margin-top: 2px; }

  /* ---- generic card ---- */
  .card { background: var(--surface); border: 1px solid var(--border); border-radius: 8px; padding: 16px 18px; }
  .card-title { font-family: var(--mono); font-size: 9px; letter-spacing: 0.1em; text-transform: uppercase; color: var(--muted); margin-bottom: 10px; }

  /* ---- two-col layouts ---- */
  .cols-2 { display: grid; grid-template-columns: 1fr 1fr; gap: 20px; align-items: start; }
  .cols-radar { display: grid; grid-template-columns: 230px 1fr; gap: 24px; align-items: start; }
  .cols-origin { display: grid; grid-template-columns: 190px 1fr; gap: 20px; align-items: start; }

  /* ---- kv table ---- */
  .kv { width: 100%; border-collapse: collapse; }
  .kv td { padding: 7px 0; font-size: 11.5px; vertical-align: top; border-bottom: 1px solid var(--border); }
  .kv tr:last-child td { border-bottom: none; }
  .kv td:first-child { color: var(--muted); font-family: var(--mono); font-size: 9.5px; text-transform: uppercase; letter-spacing: 0.04em; white-space: nowrap; padding-right: 14px; width: 120px; }
  .kv td:last-child { word-break: break-all; }
  .kv-box { border: 1px solid var(--border); border-radius: 6px; overflow: hidden; }
  .kv-box .kv td { padding: 10px 13px; }
  .kv-box .kv td:first-child { padding-right: 0; width: auto; display: block; }

  /* ---- ioc table ---- */
  table.ioc { width: 100%; border-collapse: collapse; font-family: var(--mono); font-size: 9px; }
  table.ioc th { text-align: left; font-weight: 500; color: var(--muted-2); padding: 0 8px 6px 0; border-bottom: 1px solid var(--border); text-transform: uppercase; letter-spacing: 0.04em; }
  table.ioc td { padding: 6px 8px 6px 0; border-bottom: 1px solid #f2eee5; vertical-align: top; }
  table.ioc td.type { color: var(--muted); white-space: nowrap; }
  table.ioc td.val { word-break: break-all; color: #374151; }
  table.ioc td.note { color: var(--muted); font-family: var(--sans); font-size: 9.5px; }

  /* ---- chips ---- */
  .chip { display: inline-block; font-family: var(--mono); font-size: 9px; padding: 4px 9px; background: #f7ecd9; border: 1px solid #e6cfa5; color: #8a4f0a; white-space: nowrap; border-radius: 4px; margin: 0 5px 5px 0; }
  .chip-neutral { background: #f3f4f6; border-color: var(--border); color: #4b5563; }
  .chip-danger { background: #fef2f2; border-color: #fecaca; color: #b91c1c; }

  /* ---- verdict color utility classes (bound at render time) ---- */
  .vclear   { color: var(--green); }
  .vsus     { color: var(--amber); }
  .vmal     { color: var(--accent); }
  /* Inconclusive = "we could not check", deliberately slate/neutral so it reads
     as neither safe (green) nor confirmed-bad (red). */
  .vinc     { color: #64748b; }

  /* ---- callout / recommendations ---- */
  .callout { margin-top: 8px; background: #f7ecd9; border: 1px solid #e6cfa5; border-left: 5px solid #b26a12; border-radius: 4px; padding: 18px 20px; }
  .callout-head { display: flex; align-items: center; gap: 9px; margin-bottom: 10px; }
  .callout-head .dot { width: 12px; height: 12px; background: #b26a12; transform: rotate(45deg); display: inline-block; }
  .callout-head span { font-family: var(--mono); font-weight: 700; font-size: 13px; letter-spacing: 0.06em; text-transform: uppercase; color: #8a4f0a; }
  .callout ol { margin: 0; padding-left: 19px; font-size: 11.5px; line-height: 1.6; color: #3a352f; }
  .callout ol li { margin-bottom: 7px; }

  .no-data { color: var(--muted-2); font-size: 11px; font-style: italic; }
  .full-width { grid-column: 1 / -1; }

  footer.page-footer { margin-top: 30px; padding-top: 12px; border-top: 1px solid var(--border); font-family: var(--mono); font-size: 9px; color: var(--muted-2); display: flex; justify-content: space-between; }
</style>
</head>
<body>

<header class="masthead">
  <div>
    <div class="brand">
      <span class="brand-mark"></span>
      <span class="brand-name">MALSCAN</span>
    </div>
    <div class="brand-tag">Static + Reputation Malware Analysis</div>
  </div>
  <div class="meta-grid">
    <span class="k">REPORT ID</span><span class="v">{{ job_id[:13] }}</span>
    <span class="k">GENERATED</span><span class="v">{{ generated_at }}</span>
    {% if score_data.get('scan_duration_seconds') is not none %}
    <span class="k">SCAN DURATION</span><span class="v">{{ "%.2f"|format(score_data.get('scan_duration_seconds')) }}s</span>
    {% endif %}
    <span class="k">SUBJECT</span><span class="v" style="max-width:320px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;">{{ target }}</span>
  </div>
</header>

{% set sec = namespace(n=0) %}

<!-- ============ HERO VERDICT ============ -->
<section class="avoid hero">
  <div>
    <div class="hero-label">Verdict</div>
    <div class="hero-verdict {{ verdict_class }}">{{ score_data.get('verdict') or 'Clear' }}</div>
    <p class="hero-body">{{ verdict_sentence }}</p>
    <div style="margin-top:12px;">
      <div class="mono" style="font-size:8.5px;letter-spacing:0.1em;text-transform:uppercase;color:var(--muted-2);margin-bottom:5px;">Executive Summary</div>
      <ul style="list-style:none;font-size:10.5px;line-height:1.65;color:#4b5563;">
        {% for reason in (score_data.get('reasons') or []) %}
        <li style="display:flex;gap:7px;"><span style="color:var(--accent);flex-shrink:0;">&rsaquo;</span> {{ reason }}</li>
        {% else %}
        <li style="display:flex;gap:7px;"><span style="color:var(--green);flex-shrink:0;">&rsaquo;</span> No anomalies or threat indicators were identified during analysis.</li>
        {% endfor %}
      </ul>
    </div>
    <div class="tech-callout"><span class="tag">FOR THE TECHNICAL READER &rarr;</span> {{ technical_summary }}</div>
  </div>
  <div class="avoid" style="text-align:center;">
    {{ gauge }}
    <div class="mono" style="font-size:8.5px;letter-spacing:0.1em;text-transform:uppercase;color:var(--muted-2);margin-top:2px;">Threat score &middot; 0&ndash;100</div>
  </div>
</section>

<!-- ============ AT A GLANCE ============ -->
<section class="sec">
  <div class="glance">
    <div>
      <div class="k">Family</div>
      <div class="v">{{ score_data.get('family') or 'Unknown' }}</div>
    </div>
    <div>
      <div class="k">Attribution</div>
      <div class="v">{{ score_data.get('attribution') or 'Unattributed' }}</div>
    </div>
    <div>
      <div class="k">Artifact Type</div>
      <div class="v">{{ artifact_type }}</div>
      <div class="s">{{ artifact_subtext }}</div>
    </div>
    <div>
      <div class="k">VirusTotal</div>
      {% if vt_stats %}
      <div class="v">{{ vt_stats.get('malicious',0) }}/{{ vt_total }} engines</div>
      <div class="s">flagged malicious</div>
      {% else %}
      <div class="v">Not Queried</div>
      <div class="s">no VT data for this scan</div>
      {% endif %}
    </div>
  </div>
</section>

<!-- ============ RISK BREAKDOWN ============ -->
{% set sec.n = sec.n + 1 %}
<section class="sec">
  <div class="sec-head">
    <span class="sec-num">{{ "%02d"|format(sec.n) }}</span>
    <span class="sec-title">Risk Breakdown</span>
    <span class="sec-rule"></span>
  </div>
  <div class="cols-radar">
    <div class="avoid">
      <div class="card-title">Risk Profile</div>
      {{ radar }}
    </div>
    <div>
      <div class="card-title">Score Composition &mdash; how the {{ score_data.get('score', 0) }} was reached</div>
      {{ score_bars }}
      <div style="display:flex;justify-content:space-between;align-items:baseline;border-top:2px solid var(--ink);padding-top:9px;margin-top:14px;">
        <span class="mono" style="font-weight:600;font-size:10.5px;letter-spacing:0.05em;text-transform:uppercase;">Total Threat Score</span>
        <span class="mono {{ verdict_class }}" style="font-weight:700;font-size:17px;">{{ score_data.get('score', 0) }} / 100</span>
      </div>
    </div>
  </div>
</section>

<!-- ============ FILE EXAMINATION ============ -->
{% if vt_stats or entropy %}
{% set sec.n = sec.n + 1 %}
<section class="sec">
  <div class="sec-head">
    <span class="sec-num">{{ "%02d"|format(sec.n) }}</span>
    <span class="sec-title">File Examination</span>
    <span class="sec-rule"></span>
  </div>

  {% if vt_stats %}
  <p style="margin-bottom:10px;font-size:12.5px;">
    <strong class="mono vmal" style="font-size:13.5px;">{{ vt_stats.get('malicious',0) }} of {{ vt_total }}</strong>
    antivirus vendors flagged this {{ 'URL' if score_data.get('submitted_url') else 'file' }} on VirusTotal.
  </p>
  <div class="cols-2 avoid" style="margin-bottom:{{ '22px' if entropy else '0' }};">
    <div>{{ vt_donut }}</div>
    <div>
      {% if vt_detections %}
      <div class="card-title" style="margin-bottom:8px;">Vendor detections</div>
      <div>
        {% for d in vt_detections %}
        <span class="chip">{{ d.vendor }} &middot; {{ d.result }}</span>
        {% endfor %}
      </div>
      {% else %}
      <p class="no-data">No individual vendor detection names were returned for this lookup.</p>
      {% endif %}
    </div>
  </div>
  {% endif %}

  {% if entropy %}
  <div class="card avoid">
    <div class="card-title">Entropy by PE section</div>
    {{ entropy }}
    <p style="font-size:10.5px;color:var(--muted);margin-top:8px;line-height:1.55;border-top:1px solid var(--border);padding-top:9px;">
      <strong style="color:var(--ink);">What this means:</strong> entropy measures how random a section's bytes are, on a 0&ndash;8 scale.
      Values above ~7.0 (dashed line, red bars) usually mean the code is <em>compressed or encrypted</em> &mdash; a common way malware hides
      its real logic from static scanners. Packing isn't malicious by itself, but it is a strong reason to treat the file with caution.
    </p>
  </div>
  {% endif %}
</section>
{% endif %}

<!-- ============ DOCUMENT ANALYSIS ============ -->
{% set doc_info = score_data.get('document_info') %}
{% if doc_info and doc_info.get('suspicious_flags') %}
{% set sec.n = sec.n + 1 %}
<section class="sec">
  <div class="sec-head">
    <span class="sec-num">{{ "%02d"|format(sec.n) }}</span>
    <span class="sec-title">Document Analysis &mdash; {{ (doc_info.get('doc_type') or 'document')|upper }}</span>
    <span class="sec-rule"></span>
  </div>
  <div class="card avoid">
    <ul style="list-style:none;">
      {% for flag in doc_info.get('suspicious_flags') %}
      <li style="font-size:11.5px;padding:6px 0;border-bottom:1px solid var(--border);display:flex;gap:9px;">
        <span style="color:var(--accent);flex-shrink:0;">&rsaquo;</span> {{ flag }}
      </li>
      {% endfor %}
    </ul>
  </div>
</section>
{% endif %}

<!-- ============ APK ANALYSIS ============ -->
{% set apk_info = score_data.get('apk_info') %}
{% if apk_info and apk_info.get('is_apk') %}
{% set sec.n = sec.n + 1 %}
<section class="sec">
  <div class="sec-head">
    <span class="sec-num">{{ "%02d"|format(sec.n) }}</span>
    <span class="sec-title">Android APK Analysis</span>
    <span class="sec-rule"></span>
  </div>
  <div class="card avoid">
    <table class="kv" style="margin-bottom:12px;">
      {% if apk_info.get('package') %}<tr><td>Package</td><td class="mono">{{ apk_info.get('package') }}</td></tr>{% endif %}
      {% if apk_info.get('app_label') %}<tr><td>App Name</td><td>{{ apk_info.get('app_label') }}</td></tr>{% endif %}
    </table>
    {% if apk_info.get('dangerous_permissions') %}
    <div class="card-title" style="color:var(--accent);">Dangerous Permissions ({{ apk_info.get('dangerous_permissions')|length }})</div>
    <div style="margin-bottom:10px;">
      {% for p in apk_info.get('dangerous_permissions') %}
      <span class="chip chip-danger">{{ p.replace('android.permission.','') }}</span>
      {% endfor %}
    </div>
    {% endif %}
    {% if apk_info.get('permissions') %}
    <div class="card-title">All Permissions ({{ apk_info.get('permissions')|length }})</div>
    <div>
      {% for p in apk_info.get('permissions') %}
      <span class="chip chip-neutral">{{ p.replace('android.permission.','') }}</span>
      {% endfor %}
    </div>
    {% endif %}
  </div>
</section>
{% endif %}

<!-- ============ ARCHIVE CONTENTS ============ -->
{% if score_data.get('archive_contents') %}
{% set sec.n = sec.n + 1 %}
<section class="sec">
  <div class="sec-head">
    <span class="sec-num">{{ "%02d"|format(sec.n) }}</span>
    <span class="sec-title">Archive Contents ({{ score_data.get('archive_contents')|length }} files)</span>
    <span class="sec-rule"></span>
  </div>
  <div class="card avoid">
    {% for f in score_data.get('archive_contents') %}
    <div style="display:flex;justify-content:space-between;align-items:center;font-family:var(--mono);font-size:10px;padding:7px 0;border-bottom:1px solid var(--border);">
      <span style="word-break:break-all;">{{ f.get('name') }}</span>
      <span style="white-space:nowrap;margin-left:10px;">
        {% if f.get('is_pe') %}<span class="chip chip-neutral">PE</span>{% endif %}
        {% if f.get('ioc_count') %}<span class="vmal" style="font-weight:700;">{{ f.get('ioc_count') }} IOCs</span>{% endif %}
      </span>
    </div>
    {% endfor %}
  </div>
</section>
{% endif %}

<!-- ============ WHERE THIS CAME FROM ============ -->
{% set sec.n = sec.n + 1 %}
<section class="sec">
  <div class="sec-head">
    <span class="sec-num">{{ "%02d"|format(sec.n) }}</span>
    <span class="sec-title">Where This Came From</span>
    <span class="sec-rule"></span>
  </div>

  {% set o = osint or {} %}
  <div class="cols-origin avoid" style="margin-bottom:20px;">
    <div class="kv-box">
      <table class="kv">
        <tr><td>ISP</td><td>{{ o.get('hosting') or 'N/A' }}</td></tr>
        <tr><td>ASN</td><td>{{ o.get('asn') or 'N/A' }}</td></tr>
        <tr><td>Country</td><td>{{ o.get('country') or 'N/A' }}{% if o.get('country_code') %} ({{ o.get('country_code') }}){% endif %}</td></tr>
        <tr><td>Registrar</td><td>{{ o.get('registrar') or 'N/A' }}</td></tr>
      </table>
    </div>
    <div class="card">
      <div class="card-title">Infrastructure Graph</div>
      {{ infra_graph }}
    </div>
  </div>

  <div class="card avoid" style="padding:0;overflow:hidden;">
    <div style="padding:12px 16px;border-bottom:1px solid var(--panel-border);background:var(--panel);">
      <div class="mono" style="font-size:9.5px;letter-spacing:0.1em;text-transform:uppercase;color:#d1d5db;">Threat Origin &mdash; Geographic Map</div>
    </div>
    {{ geo_map }}
  </div>
</section>

<!-- ============ CROSS-JOB CORRELATION ============ -->
{% if clusters and clusters.get('cluster_count') %}
{% set sec.n = sec.n + 1 %}
<section class="sec">
  <div class="sec-head">
    <span class="sec-num">{{ "%02d"|format(sec.n) }}</span>
    <span class="sec-title">Cross-Job Correlation</span>
    <span class="sec-rule"></span>
  </div>
  <div class="card avoid">
    {% for signal in (clusters.get('risk_signals') or []) %}
    <div style="background:rgba(255,59,0,0.05);border:1px solid rgba(255,59,0,0.2);border-radius:4px;padding:9px 13px;margin-bottom:8px;font-size:11.5px;">
      <strong>&rsaquo; Infrastructure Link Detected</strong>
      <p style="color:#7c7c7c;margin-top:4px;font-size:10.5px;">{{ signal }}</p>
    </div>
    {% endfor %}
    {% for ip, jobs in (clusters.get('shared_ips') or {}).items() %}
    <div style="background:rgba(255,59,0,0.05);border:1px solid rgba(255,59,0,0.2);border-radius:4px;padding:9px 13px;margin-bottom:8px;font-size:11.5px;">
      <strong>Shared IP: {{ ip }}</strong>
      <p style="color:#7c7c7c;margin-top:4px;font-size:10.5px;">Seen in jobs: {{ jobs|join(", ") }}</p>
    </div>
    {% endfor %}
    {% for asn, jobs in (clusters.get('shared_asns') or {}).items() %}
    <div style="background:rgba(255,59,0,0.05);border:1px solid rgba(255,59,0,0.2);border-radius:4px;padding:9px 13px;margin-bottom:8px;font-size:11.5px;">
      <strong>Shared ASN: {{ asn }}</strong>
      <p style="color:#7c7c7c;margin-top:4px;font-size:10.5px;">Seen in jobs: {{ jobs|join(", ") }}</p>
    </div>
    {% endfor %}
  </div>
</section>
{% endif %}

<!-- ============ APPENDIX ============ -->
{% set sec.n = sec.n + 1 %}
<section class="sec">
  <div class="sec-head">
    <span class="sec-num" style="color:var(--muted-2);">{{ "%02d"|format(sec.n) }}</span>
    <span class="sec-title" style="color:var(--muted);">Appendix &mdash; Technical Detail</span>
    <span class="sec-rule"></span>
  </div>
  <div class="cols-2">
    <div class="avoid">
      <div class="card-title">Hashes</div>
      <table class="kv" style="margin-bottom:14px;">
        <tr><td>SHA-256</td><td class="mono" style="font-size:9.5px;">{{ raw_data.get('file_hash') or score_data.get('file_hash') or 'N/A' }}</td></tr>
        {% if score_data.get('imphash') %}<tr><td>Imphash</td><td class="mono" style="font-size:9.5px;">{{ score_data.get('imphash') }}</td></tr>{% endif %}
      </table>
      {% if osint %}
      <div class="card-title">Raw OSINT Metadata</div>
      <table class="kv">
        <tr><td>Registrar</td><td>{{ osint.get('registrar') or 'N/A' }}</td></tr>
        <tr><td>Domain Age</td><td>{% if osint.get('domain_age_days') is not none %}{{ osint.get('domain_age_days') }} days{% else %}Unknown{% endif %}</td></tr>
        <tr><td>DNS A Records</td><td class="mono" style="font-size:10px;">{{ (osint.get('dns_a_records') or [])|join(", ") or "None resolved" }}</td></tr>
      </table>
      {% endif %}
    </div>
    <div>
      <div class="card-title">Indicators of Compromise</div>
      {% if iocs %}
      <table class="ioc">
        <thead><tr><th>Type</th><th>Indicator</th><th>Note</th></tr></thead>
        <tbody>
          {% for row in iocs %}
          <tr>
            <td class="type">{{ row.type }}</td>
            <td class="val">{{ row.value }}</td>
            <td class="note">{{ row.note }}</td>
          </tr>
          {% endfor %}
        </tbody>
      </table>
      {% else %}
      <p class="no-data">No indicators of compromise were extracted from this artifact.</p>
      {% endif %}
    </div>
  </div>
</section>

<!-- ============ WHAT TO DO NEXT ============ -->
<section class="sec avoid">
  <div class="callout">
    <div class="callout-head"><span class="dot"></span><span>What To Do Next</span></div>
    <ol>
      {% for item in recommendations %}
      <li>{{ item }}</li>
      {% endfor %}
    </ol>
  </div>
</section>

<footer class="page-footer">
  <span>MalScan &mdash; Automated Threat Intelligence &amp; Attribution Engine</span>
  <span>Report ID: {{ job_id }} &middot; Investigative use only, not a substitute for professional analysis</span>
</footer>

</body>
</html>"""


# ── Public API ────────────────────────────────────────────────────────────────

def get_report_path(job_id: str) -> str:
    """Returns the expected filesystem path for a job's HTML report."""
    return os.path.join(REPORTS_DIR, f"report_{job_id}.html")


def generate_report(job_id: str, score_data: dict, raw_data: dict) -> str:
    """
    Renders and saves an HTML forensic report for the given job.
    Called by backend/app/main.py when a job completes.

    Args:
        job_id:     The unique job identifier.
        score_data: The full dict returned by calculate_score().
        raw_data:   Any extra artifact metadata (file_hash, original_filename, etc.)

    Returns:
        The absolute path to the saved HTML report file.
    """
    os.makedirs(REPORTS_DIR, exist_ok=True)

    score_data = score_data or {}
    raw_data = raw_data or {}
    osint = score_data.get("osint_summary") or None
    indicators = score_data.get("indicators") or {}
    clusters = score_data.get("clusters") or None
    verdict = score_data.get("verdict") or "Clear"

    target = (
        score_data.get("submitted_url")
        or score_data.get("original_filename")
        or raw_data.get("original_filename")
        or (indicators.get("urls") or [None])[0]
        or (indicators.get("domains") or [None])[0]
        or (score_data.get("file_hash") and f"File: {score_data['file_hash']}")
        or "Unknown Target"
    )

    # Unknown verdicts fall back to "vinc" (neutral), never "vclear" — an
    # unrecognised state must not be painted as a clean bill of health.
    verdict_class = {
        "Clear": "vclear", "Suspicious": "vsus",
        "Malicious": "vmal", "Inconclusive": "vinc",
    }.get(verdict, "vinc")
    verdict_sentence = {
        "Clear": "No indicators of compromise were identified. This artifact appears safe based on the checks performed.",
        "Suspicious": "This artifact shows some warning signs. It isn't confirmed malicious — but treat it with caution.",
        "Malicious": "This artifact matches known-bad patterns with high confidence. Do not open, run, or trust it.",
        "Inconclusive": "This scan did not complete — VirusTotal, the verdict-critical source, was unavailable. No indicators were found, but that is not the same as safe. Re-scan before trusting this artifact.",
    }.get(verdict, "")

    vt_stats = osint.get("virustotal") if osint else None
    vt_detections = (osint.get("virustotal_detections") or []) if osint else []
    vt_total = sum(vt_stats.get(k, 0) for k in ("malicious", "suspicious", "harmless", "undetected")) if vt_stats else 0

    artifact_type, artifact_subtext = _artifact_type(score_data, raw_data)

    iocs = []
    target_value = score_data.get("submitted_url") or score_data.get("original_filename") or raw_data.get("original_filename")
    for ip in indicators.get("ips") or []:
        iocs.append({"type": "IPv4", "value": ip, "note": "Submitted target" if ip == target_value else "Extracted indicator"})
    for domain in indicators.get("domains") or []:
        iocs.append({"type": "Domain", "value": domain, "note": "Submitted target" if domain == target_value else "Extracted indicator"})
    for url in indicators.get("urls") or []:
        iocs.append({"type": "URL", "value": url, "note": "Submitted target" if url == target_value else "Extracted indicator"})

    context = dict(
        job_id=job_id,
        score_data=score_data,
        raw_data=raw_data,
        generated_at=datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC"),
        target=target,
        verdict_class=verdict_class,
        verdict_sentence=verdict_sentence,
        technical_summary=_technical_summary(score_data, raw_data),
        artifact_type=artifact_type,
        artifact_subtext=artifact_subtext,
        osint=osint,
        clusters=clusters,
        iocs=iocs,
        vt_stats=vt_stats,
        vt_detections=vt_detections,
        vt_total=vt_total,
        recommendations=_recommendations(verdict, bool(score_data.get("submitted_url"))),
        gauge=render_gauge(score_data.get("score", 0), verdict),
        radar=render_radar(score_data.get("risk_profile") or []),
        score_bars=render_score_bars(score_data.get("score_breakdown") or []),
        entropy=render_entropy_chart(score_data.get("pe_sections") or []) if score_data.get("is_pe") and score_data.get("pe_sections") else Markup(""),
        vt_donut=render_vt_donut(vt_stats) if vt_stats else Markup(""),
        infra_graph=render_infra_graph(score_data.get("graph_nodes") or [], score_data.get("graph_edges") or [], target),
        geo_map=render_geo_map(
            (osint or {}).get("lat"), (osint or {}).get("lon"),
            city=(osint or {}).get("city"), region=(osint or {}).get("region"),
            country=(osint or {}).get("country"), country_code=(osint or {}).get("country_code"),
            isp=(osint or {}).get("hosting"), asn=(osint or {}).get("asn"),
            ip=(indicators.get("ips") or [None])[0],
        ),
    )

    # autoescape is mandatory: filenames, URLs, page titles etc. come straight
    # out of hostile files — without it the report is a stored-XSS vector.
    # The chart fragments above are pre-escaped Markup, built by report_charts.py.
    template = Template(REPORT_TEMPLATE, autoescape=True)
    html = template.render(**context)

    report_path = get_report_path(job_id)
    with open(report_path, "w", encoding="utf-8") as f:
        f.write(html)

    logger.info(f"Report saved: {report_path}")
    return report_path
