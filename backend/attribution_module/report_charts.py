"""
attribution_module/report_charts.py

Server-side SVG/HTML chart fragments for the PDF forensic report
(attribution_module/reporter.py). These mirror the look of the live web
report's chart components (frontend/app/report/*.tsx) so the exported PDF
and the in-app report read as the same product.

Every function returns a markupsafe.Markup instance (pre-escaped HTML/SVG)
so it can be dropped straight into the Jinja template without being
double-escaped. Any value that ultimately came from an untrusted artifact
(a filename, a section name, an extracted domain/IP...) is run through
markupsafe.escape() before being interpolated — the report renders strings
pulled out of hostile files, so this is a required control, not a nicety.
"""

import math
from collections import defaultdict, deque
from markupsafe import Markup, escape

MONO = "'Geist Mono',ui-monospace,monospace"

VERDICT_COLOR = {"Clear": "#22c55e", "Suspicious": "#f59e0b", "Malicious": "#FF3B00"}
RISK_COLOR = {"high": "#ef4444", "medium": "#f59e0b", "neutral": "#64748b"}
TYPE_ABBR = {"artifact": "FILE", "ip": "IP", "domain": "DOM", "asn": "ASN", "country": "CC", "registrar": "REG"}
TYPE_LABEL = {"ip": "IP Address", "domain": "Domain", "asn": "ASN", "country": "Country", "registrar": "Registrar"}
RELATIONSHIP_LABEL = {
    "connects_to": "connects to",
    "references": "references",
    "hosted_in_asn": "hosted in",
    "located_in": "located in",
    "registered_with": "registered with",
}


# ── Threat gauge (banded arc, 0-100) ────────────────────────────────────────
# Band cutoffs (35 / 70) match calculate_score()'s verdict thresholds exactly,
# so the gauge is never internally inconsistent with the printed verdict.

def render_gauge(score: int, verdict: str) -> Markup:
    score = max(0, min(100, int(score or 0)))
    cx, cy, r, sw = 110, 106, 78, 13

    def pt(v, rad):
        a = math.radians(180 - v / 100 * 180)
        return cx + rad * math.cos(a), cy - rad * math.sin(a)

    def arc(s, e, color):
        x1, y1 = pt(s, r)
        x2, y2 = pt(e, r)
        return f'<path d="M{x1:.1f} {y1:.1f} A {r} {r} 0 0 1 {x2:.1f} {y2:.1f}" fill="none" stroke="{color}" stroke-width="{sw}"/>'

    bands = arc(0, 35, "#22c55e") + arc(35, 70, "#f59e0b") + arc(70, 100, "#FF3B00")
    mx, my = pt(score, r)
    color = VERDICT_COLOR.get(verdict, "#6b7280")

    svg = f"""<svg viewBox="0 0 220 148" width="100%" style="max-width:210px">
      {bands}
      <circle cx="{mx:.1f}" cy="{my:.1f}" r="7.5" fill="#ffffff" stroke="#121212" stroke-width="2"/>
      <circle cx="{mx:.1f}" cy="{my:.1f}" r="3" fill="{color}"/>
      <text x="{cx}" y="{cy - 6}" text-anchor="middle" font-family="{MONO}" font-weight="700" font-size="38" fill="{color}">{score}</text>
      <text x="{cx}" y="{cy + 13}" text-anchor="middle" font-family="{MONO}" font-size="10" fill="#9ca3af">/ 100</text>
      <text x="30" y="{cy + 22}" text-anchor="middle" font-family="{MONO}" font-size="8" font-weight="600" fill="#22c55e">CLEAR</text>
      <text x="190" y="{cy + 22}" text-anchor="middle" font-family="{MONO}" font-size="8" font-weight="600" fill="#FF3B00">MALICIOUS</text>
    </svg>"""
    return Markup(svg)


# ── Risk profile radar ──────────────────────────────────────────────────────
# Deliberately a plain straight-edged polygon, not a smoothed spline: a
# Catmull-Rom curve through points with very different radii (the common
# case here — one dominant axis, the rest near the floor) can overshoot
# past its control points and self-intersect, rendering as a jumbled
# star instead of a shape. A straight polygon through radial points is
# mathematically guaranteed never to self-intersect, at the cost of
# slightly less "soft" corners — reliability over polish here.

def render_radar(axes: list) -> Markup:
    if not axes:
        return Markup("")
    n = len(axes)
    cx, cy, r = 150, 145, 100
    floor = 0.14

    def point(i, radius):
        angle = -math.pi / 2 + i * (2 * math.pi / n)
        return cx + radius * math.cos(angle), cy + radius * math.sin(angle)

    def value_radius(v):
        v = max(0, min(100, v)) / 100
        return (floor + v * (1 - floor)) * r

    rings = ""
    for level in (0.25, 0.5, 0.75, 1.0):
        pts = " ".join(f"{x:.1f},{y:.1f}" for x, y in (point(i, level * r) for i in range(n)))
        rings += f'<polygon points="{pts}" fill="none" stroke="#e7e9ec" stroke-width="1"/>'

    axis_lines = ""
    for i in range(n):
        x, y = point(i, r)
        axis_lines += f'<line x1="{cx}" y1="{cy}" x2="{x:.1f}" y2="{y:.1f}" stroke="#e7e9ec" stroke-width="1"/>'

    value_points = [point(i, value_radius(a.get("value", 0))) for i, a in enumerate(axes)]
    poly_pts = " ".join(f"{x:.1f},{y:.1f}" for x, y in value_points)
    value_poly = f'<polygon points="{poly_pts}" fill="#FF3B00" fill-opacity="0.18" stroke="#FF3B00" stroke-width="2.5" stroke-linejoin="round"/>'
    dots = "".join(f'<circle cx="{x:.1f}" cy="{y:.1f}" r="4" fill="#FF3B00" stroke="#ffffff" stroke-width="1.5"/>' for x, y in value_points)

    labels = ""
    for i, a in enumerate(axes):
        lx, ly = point(i, r + 40)
        words = str(a.get("label", "")).split(" ")
        y0 = ly - (len(words) - 1) * 5
        tspans = "".join(f'<tspan x="{lx:.1f}" dy="{0 if wi == 0 else 10}">{escape(w)}</tspan>' for wi, w in enumerate(words))
        labels += f'<text x="{lx:.1f}" y="{y0:.1f}" text-anchor="middle" font-family="{MONO}" font-size="9" font-weight="600" fill="#4b5563">{tspans}</text>'

    svg = f'<svg viewBox="0 0 300 300" width="100%" style="max-width:280px">{rings}{axis_lines}{value_poly}{dots}{labels}</svg>'
    return Markup(svg)


# ── Score composition bars ──────────────────────────────────────────────────

def render_score_bars(breakdown: list) -> Markup:
    if not breakdown:
        return Markup(
            '<div style="font-size:11px;color:#6b7280;">No individual risk factors contributed to this score '
            "— the artifact came back clean on every check.</div>"
        )
    max_abs = max((abs(b.get("points", 0)) for b in breakdown), default=1) or 1
    rows = []
    for b in breakdown:
        label = escape(str(b.get("label", "")))
        points = b.get("points", 0)
        positive = points >= 0
        width_pct = (abs(points) / max_abs) * 100
        color = "#FF3B00" if positive else "#22c55e"
        sign = "+" if positive else ""
        rows.append(
            f'<div class="avoid" style="margin-bottom:10px;">'
            f'<div style="display:flex;justify-content:space-between;gap:10px;font-size:10.5px;margin-bottom:3px;">'
            f'<span style="color:#374151;">{label}</span>'
            f'<span style="font-family:{MONO};font-weight:700;color:{color};white-space:nowrap;">{sign}{points}</span>'
            f"</div>"
            f'<div style="height:6px;background:#eee9df;border-radius:3px;overflow:hidden;">'
            f'<div style="height:100%;width:{width_pct:.1f}%;background:{color};"></div>'
            f"</div></div>"
        )
    return Markup("".join(rows))


# ── PE section entropy chart ────────────────────────────────────────────────

def render_entropy_chart(sections: list) -> Markup:
    if not sections:
        return Markup("")
    W, H = 460, 190
    pad_l, pad_r, pad_t, pad_b = 26, 10, 12, 24
    max_v, threshold = 8.0, 7.0
    n = len(sections)
    iw, ih = W - pad_l - pad_r, H - pad_t - pad_b
    slot = iw / n
    bw = min(slot * 0.5, 42)

    def y_for(v):
        return pad_t + (1 - v / max_v) * ih

    els = []
    for t in (0, 2, 4, 6, 8):
        y = y_for(t)
        els.append(f'<line x1="{pad_l}" y1="{y:.1f}" x2="{W - pad_r}" y2="{y:.1f}" stroke="#eee9df" stroke-width="1"/>')
        els.append(f'<text x="{pad_l - 5}" y="{y + 3:.1f}" text-anchor="end" font-family="{MONO}" font-size="8" fill="#a1a1aa">{t}</text>')

    for i, s in enumerate(sections):
        name = escape(str(s.get("name") or "?"))
        v = float(s.get("entropy", 0) or 0)
        x = pad_l + slot * i + (slot - bw) / 2
        y = y_for(v)
        packed = v > threshold
        color = "#ef4444" if packed else "#94a3b8"
        bar_h = (pad_t + ih) - y
        els.append(f'<rect x="{x:.1f}" y="{y:.1f}" width="{bw:.1f}" height="{bar_h:.1f}" rx="2" fill="{color}"/>')
        els.append(f'<text x="{x + bw / 2:.1f}" y="{y - 4:.1f}" text-anchor="middle" font-family="{MONO}" font-size="8.5" font-weight="600" fill="{color}">{v:.1f}</text>')
        els.append(f'<text x="{x + bw / 2:.1f}" y="{H - 8}" text-anchor="middle" font-family="{MONO}" font-size="8" fill="#6b7280">{name}</text>')

    ty = y_for(threshold)
    els.append(f'<line x1="{pad_l}" y1="{ty:.1f}" x2="{W - pad_r}" y2="{ty:.1f}" stroke="#f59e0b" stroke-width="1.2" stroke-dasharray="4 3"/>')
    els.append(f'<rect x="{pad_l + 3}" y="{ty - 13:.1f}" width="96" height="12" fill="#ffffff" opacity="0.9"/>')
    els.append(f'<text x="{pad_l + 6}" y="{ty - 4:.1f}" font-family="{MONO}" font-size="8" font-weight="600" fill="#b45309">packed &#8805; 7.0</text>')

    return Markup(f'<svg viewBox="0 0 {W} {H}" width="100%">{"".join(els)}</svg>')


# ── VirusTotal vendor-consensus donut ────────────────────────────────────────

def render_vt_donut(stats: dict) -> Markup:
    if not stats:
        return Markup("")
    mal, sus = stats.get("malicious", 0) or 0, stats.get("suspicious", 0) or 0
    harm, und = stats.get("harmless", 0) or 0, stats.get("undetected", 0) or 0
    total = mal + sus + harm + und
    if total == 0:
        return Markup("")
    R = 54
    C = 2 * math.pi * R
    segments = [(mal, "#ef4444"), (sus, "#f59e0b"), (harm, "#22c55e"), (und, "#d1d5db")]
    circles = [f'<circle cx="70" cy="70" r="{R}" fill="none" stroke="#f3f4f6" stroke-width="16"/>']
    cumulative = 0.0
    for value, color in segments:
        if value <= 0:
            continue
        frac = value / total
        dash = frac * C
        offset = -cumulative * C
        cumulative += frac
        circles.append(
            f'<circle cx="70" cy="70" r="{R}" fill="none" stroke="{color}" stroke-width="16" '
            f'stroke-dasharray="{max(dash - 2, 0):.2f} {C - dash + 2:.2f}" stroke-dashoffset="{offset:.2f}" stroke-linecap="round"/>'
        )
    return Markup(f'<svg viewBox="0 0 140 140" width="104" height="104" style="transform:rotate(-90deg)">{"".join(circles)}</svg>')


# ── Infrastructure entity graph (server-rendered GraphWidget equivalent) ────
# Same top-down BFS-tree layout as frontend/app/report/GraphWidget.tsx, just
# rendered as a static SVG instead of a draggable client-side one.

def render_infra_graph(nodes: list, edges: list, origin_label: str = None) -> Markup:
    nodes = nodes or []
    edges = edges or []
    if len(nodes) <= 1:
        return Markup(
            f'<div style="padding:28px 10px;text-align:center;color:#9ca3af;font-family:{MONO};'
            f'font-size:10px;text-transform:uppercase;letter-spacing:0.05em;">'
            f"No infrastructure relationships were extracted for this artifact.</div>"
        )

    VIEW, CX, MARGIN, ROW_TOP, ROW_BOTTOM = 400, 200, 36, 55, 345
    node_by_id = {n["id"]: n for n in nodes}

    children = defaultdict(list)
    for e in edges:
        children[e["source"]].append(e["target"])

    depth = {"artifact": 0}
    queue = deque(["artifact"])
    while queue:
        nid = queue.popleft()
        for cid in children.get(nid, []):
            if cid not in depth:
                depth[cid] = depth[nid] + 1
                queue.append(cid)

    levels = defaultdict(list)
    for n in nodes:
        levels[depth.get(n["id"], 1)].append(n["id"])
    max_depth = max(levels.keys()) if levels else 0
    row_gap = (ROW_BOTTOM - ROW_TOP) / max_depth if max_depth > 0 else 0

    positions, row_size_of, chars_of = {}, {}, {}
    for d, ids in levels.items():
        y = ROW_TOP + row_gap * d
        n = len(ids)
        if n > 7:
            # Too many same-depth siblings (e.g. 8 IPs + 6 domains all one
            # hop from the artifact) to fit legibly on one line — split into
            # two interleaved sub-rows so each has at most ceil(n/2), which
            # roughly halves the horizontal crowding instead of overlapping.
            half = math.ceil(n / 2)
            for sub_ids, sub_y in ((ids[:half], y - 13), (ids[half:], y + 13)):
                rn = len(sub_ids)
                chars = 11 if rn <= 6 else 8
                for i, nid in enumerate(sub_ids):
                    x = MARGIN + (i + 0.5) * (VIEW - 2 * MARGIN) / rn
                    positions[nid] = (x, sub_y)
                    row_size_of[nid] = rn
                    chars_of[nid] = chars
        else:
            chars = 15 if n <= 3 else 11 if n <= 6 else 8
            for i, nid in enumerate(ids):
                x = CX if n == 1 else MARGIN + (i + 0.5) * (VIEW - 2 * MARGIN) / n
                positions[nid] = (x, y)
                row_size_of[nid] = n
                chars_of[nid] = chars

    def node_radius(ntype, row_size):
        if ntype == "artifact":
            return 22
        if row_size > 6:
            return 12
        if row_size > 4:
            return 14
        return 16

    def truncated_label(nid, raw):
        max_chars = chars_of.get(nid, 15)
        raw = raw or ""
        if len(raw) > max_chars:
            raw = raw[: max_chars - 1] + "…"
        return escape(raw)

    edge_svg = []
    for e in edges:
        s, t = positions.get(e["source"]), positions.get(e["target"])
        if not s or not t:
            continue
        sx, sy = s
        tx, ty = t
        rs = node_radius(node_by_id.get(e["source"], {}).get("type", ""), row_size_of.get(e["source"], 1))
        rt = node_radius(node_by_id.get(e["target"], {}).get("type", ""), row_size_of.get(e["target"], 1))
        dx, dy = tx - sx, ty - sy
        dist = math.hypot(dx, dy) or 1
        ux, uy = dx / dist, dy / dist
        x1, y1 = sx + ux * (rs + 2), sy + uy * (rs + 2)
        x2, y2 = tx - ux * (rt + 8), ty - uy * (rt + 8)
        rel = escape(RELATIONSHIP_LABEL.get(e.get("relationship"), e.get("relationship", "")))
        mx, my = (x1 + x2) / 2, (y1 + y2) / 2
        edge_svg.append(
            f'<line x1="{x1:.1f}" y1="{y1:.1f}" x2="{x2:.1f}" y2="{y2:.1f}" stroke="#9aa3af" stroke-width="1.5" marker-end="url(#graph-arrow)" opacity="0.85"/>'
            f'<rect x="{mx - 30:.1f}" y="{my - 8:.1f}" width="60" height="13" fill="#ffffff" opacity="0.85"/>'
            f'<text x="{mx:.1f}" y="{my + 2:.1f}" text-anchor="middle" font-family="{MONO}" font-size="7" fill="#6b7280">{rel}</text>'
        )

    node_svg = []
    for n in nodes:
        pos = positions.get(n["id"])
        if not pos:
            continue
        x, y = pos
        ntype = n.get("type", "")
        r = node_radius(ntype, row_size_of.get(n["id"], 1))
        color = "#FF3B00" if n["id"] == "artifact" else RISK_COLOR.get(n.get("risk", "neutral"), RISK_COLOR["neutral"])
        abbr = TYPE_ABBR.get(ntype, "?")
        raw_label = origin_label if (n["id"] == "artifact" and origin_label) else n.get("label", "")
        label = truncated_label(n["id"], raw_label)
        node_svg.append(
            f'<g transform="translate({x:.1f},{y:.1f})">'
            f'<circle r="{r}" fill="#ffffff" stroke="{color}" stroke-width="2.5"/>'
            f'<text text-anchor="middle" dy="3" font-family="{MONO}" font-size="{9 if r >= 16 else 7}" font-weight="700" fill="{color}">{abbr}</text>'
            f'<text y="{r + 13}" text-anchor="middle" font-family="{MONO}" font-size="9" fill="#4b5563">{label}</text>'
            f"</g>"
        )

    legend = "".join(
        f'<span style="display:inline-flex;align-items:center;gap:4px;margin:0 8px;">'
        f'<span style="width:7px;height:7px;border-radius:50%;background:{color};display:inline-block;"></span>{label}</span>'
        for label, color in [("High Risk", "#ef4444"), ("Medium Risk", "#f59e0b"), ("Neutral", "#64748b")]
    )

    return Markup(
        f'<div style="padding:4px 2px;">'
        f'<svg viewBox="0 0 {VIEW} {VIEW}" width="100%" style="max-width:340px;display:block;margin:0 auto;">'
        f'<defs><marker id="graph-arrow" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">'
        f'<path d="M0,0 L10,5 L0,10 z" fill="#9aa3af"/></marker></defs>'
        f'{"".join(edge_svg)}{"".join(node_svg)}'
        f"</svg>"
        f'<div style="text-align:center;margin-top:10px;font-family:{MONO};font-size:8px;color:#6b7280;text-transform:uppercase;letter-spacing:0.05em;">{legend}</div>'
        f"</div>"
    )


# ── Threat-origin geo map ───────────────────────────────────────────────────
# A real Leaflet map (same CartoDB Voyager tiles as the live web report's
# frontend/app/report/GeoMap.tsx), not a hand-drawn abstraction — Playwright
# drives real Chromium with real network access at PDF-render time, so there
# is no reason to fake it. Leaflet/tiles load via <link>/<script> in the page
# <head> (reporter.py); this function only emits the map container + a queued
# init call (processed on window 'load' — see reporter.py) plus the HTML HUD
# overlay, which stays plain escaped text exactly like before.

_geo_map_counter = 0


def _geo_stat(label: str, value: str) -> str:
    return (
        f'<div><div style="font-size:7.5px;color:#6b7280;text-transform:uppercase;letter-spacing:0.08em;margin-bottom:3px;">{label}</div>'
        f'<div style="font-size:10.5px;color:#d1d5db;font-family:{MONO};word-break:break-all;">{value}</div></div>'
    )


def render_geo_map(lat, lon, city=None, region=None, country=None, country_code=None, isp=None, asn=None, ip=None) -> Markup:
    if lat is None or lon is None:
        return Markup(
            f'<div style="height:120px;display:flex;align-items:center;justify-content:center;background:#0d1117;'
            f'color:#6b7280;font-family:{MONO};font-size:10.5px;letter-spacing:0.1em;text-transform:uppercase;">'
            f"No geolocation data available</div>"
        )

    lat, lon = float(lat), float(lon)

    global _geo_map_counter
    _geo_map_counter += 1
    map_id = f"geomap-{_geo_map_counter}"

    location_label = escape(", ".join(v for v in (city, region, country) if v) or "Unknown")
    cc = escape(country_code) if country_code else ""

    # lat/lon are floats from our own GeoIP lookup, never artifact-derived
    # strings — safe to interpolate directly into the script, unlike every
    # other value here (which stay in escaped HTML, never inside <script>).
    svg = (
        f'<div id="{map_id}" style="height:230px;background:#0d1117;"></div>'
        f'<script>(window.__geomapQueue = window.__geomapQueue || []).push(["{map_id}", {lat}, {lon}]);</script>'
    )

    # Leaflet's own panes use z-index up to 700 internally — the HUD divs
    # need an explicit z-index of their own or they can lose that stack.
    hud_top = (
        f'<div style="position:absolute;z-index:1000;top:10px;left:10px;background:rgba(13,17,23,0.85);border:1px solid #1f2937;padding:8px 11px;font-family:{MONO};">'
        f'<div style="font-size:8px;letter-spacing:0.15em;color:#FF3B00;font-weight:700;">&#9673; THREAT ORIGIN</div>'
        f'<div style="font-size:9.5px;color:#d1d5db;margin-top:3px;">{location_label}</div>'
        + (f'<div style="font-size:8.5px;color:#6b7280;margin-top:1px;">{cc}</div>' if cc else "")
        + "</div>"
    )
    hud_bottom = (
        f'<div style="position:absolute;z-index:1000;bottom:10px;right:10px;background:rgba(13,17,23,0.85);border:1px solid #1f2937;'
        f'padding:6px 11px;font-family:{MONO};font-size:9px;color:#9ca3af;">{lat:.4f}&#176;, {lon:.4f}&#176;</div>'
    )

    info_bar = (
        '<div style="display:grid;grid-template-columns:repeat(4,1fr);gap:12px;background:#0d1117;'
        'border-top:1px solid #1f2937;padding:13px 15px;">'
        + _geo_stat("Location", location_label)
        + _geo_stat("ISP", escape(isp) if isp else "N/A")
        + _geo_stat("ASN", escape(asn) if asn else "N/A")
        + _geo_stat("IP Address", escape(ip) if ip else "N/A")
        + "</div>"
    )

    return Markup(f'<div style="position:relative;">{svg}{hud_top}{hud_bottom}</div>{info_bar}')
