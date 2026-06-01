"""
reporting/html_report.py — Standalone HTML report generator.

Generates a single self-contained HTML file with:
  - Summary statistics dashboard
  - Filterable findings table (by severity, plugin, port)
  - Subdomain inventory with live status
  - Open ports table
  - Embedded screenshot thumbnails (base64 if < 500KB, linked otherwise)
  - Scan execution timeline

Requires: jinja2 (pip install jinja2)
Falls back to a minimal HTML report if jinja2 is not installed.
"""

from __future__ import annotations

import base64
import json
import logging
from pathlib import Path

from ..core.models import FindingSeverity, ScanSession
from ..core.output_layout import OutputLayout

logger = logging.getLogger("z3r0.html_report")

# ─── Inline CSS + JS (no external dependencies in generated HTML) ─────────────

_INLINE_STYLES = """
:root {
  --bg: #0d1117; --bg2: #161b22; --bg3: #21262d;
  --border: #30363d; --text: #c9d1d9; --muted: #8b949e;
  --critical: #f85149; --high: #ff7b72; --medium: #e3b341;
  --low: #58a6ff; --info: #8b949e;
  --green: #3fb950; --accent: #58a6ff;
}
* { box-sizing: border-box; margin: 0; padding: 0; }
body { background: var(--bg); color: var(--text); font-family: 'Segoe UI', system-ui, sans-serif; font-size: 14px; }
.container { max-width: 1400px; margin: 0 auto; padding: 24px; }
h1 { font-size: 24px; font-weight: 700; color: var(--accent); margin-bottom: 4px; }
h2 { font-size: 16px; font-weight: 600; color: var(--text); margin: 24px 0 12px; border-bottom: 1px solid var(--border); padding-bottom: 8px; }
.meta { color: var(--muted); font-size: 12px; margin-bottom: 24px; }
.cards { display: grid; grid-template-columns: repeat(auto-fit, minmax(140px, 1fr)); gap: 12px; margin-bottom: 24px; }
.card { background: var(--bg2); border: 1px solid var(--border); border-radius: 8px; padding: 16px; text-align: center; }
.card .count { font-size: 32px; font-weight: 700; }
.card .label { font-size: 12px; color: var(--muted); margin-top: 4px; }
.critical .count { color: var(--critical); }
.high     .count { color: var(--high); }
.medium   .count { color: var(--medium); }
.low      .count { color: var(--low); }
.info     .count { color: var(--info); }
.total    .count { color: var(--green); }
table { width: 100%; border-collapse: collapse; background: var(--bg2); border-radius: 8px; overflow: hidden; }
th { background: var(--bg3); padding: 10px 12px; text-align: left; font-size: 12px; font-weight: 600; color: var(--muted); text-transform: uppercase; letter-spacing: 0.05em; border-bottom: 1px solid var(--border); }
td { padding: 10px 12px; border-bottom: 1px solid var(--border); vertical-align: top; }
tr:last-child td { border-bottom: none; }
tr:hover td { background: var(--bg3); }
.badge { display: inline-block; padding: 2px 8px; border-radius: 12px; font-size: 11px; font-weight: 600; text-transform: uppercase; letter-spacing: 0.05em; }
.badge-critical { background: rgba(248,81,73,.2); color: var(--critical); }
.badge-high     { background: rgba(255,123,114,.2); color: var(--high); }
.badge-medium   { background: rgba(227,179,65,.2); color: var(--medium); }
.badge-low      { background: rgba(88,166,255,.2); color: var(--low); }
.badge-info     { background: rgba(139,148,158,.15); color: var(--info); }
.filters { display: flex; gap: 8px; margin-bottom: 12px; flex-wrap: wrap; }
.filter-btn { background: var(--bg3); border: 1px solid var(--border); color: var(--text); padding: 4px 12px; border-radius: 16px; cursor: pointer; font-size: 12px; transition: all 0.15s; }
.filter-btn:hover, .filter-btn.active { background: var(--accent); border-color: var(--accent); color: #fff; }
input[type=search] { background: var(--bg3); border: 1px solid var(--border); color: var(--text); padding: 6px 12px; border-radius: 6px; font-size: 13px; width: 300px; outline: none; }
input[type=search]:focus { border-color: var(--accent); }
.toolbar { display: flex; gap: 12px; align-items: center; margin-bottom: 12px; flex-wrap: wrap; }
.desc-text { color: var(--muted); font-size: 12px; white-space: pre-wrap; max-width: 600px; }
.pill-live { background: rgba(63,185,80,.2); color: var(--green); padding: 2px 6px; border-radius: 4px; font-size: 11px; }
.pill-dead { background: rgba(248,81,73,.1); color: var(--critical); padding: 2px 6px; border-radius: 4px; font-size: 11px; }
.screenshot-thumb { max-width: 120px; max-height: 80px; border-radius: 4px; border: 1px solid var(--border); cursor: pointer; }
.modal { display:none; position:fixed; top:0; left:0; width:100%; height:100%; background:rgba(0,0,0,.8); z-index:999; align-items:center; justify-content:center; }
.modal.open { display:flex; }
.modal img { max-width:90vw; max-height:90vh; border-radius:8px; }
.modal-close { position:fixed; top:16px; right:20px; color:#fff; font-size:24px; cursor:pointer; background:none; border:none; }
code { background: var(--bg3); padding: 1px 5px; border-radius: 3px; font-size: 12px; font-family: monospace; color: var(--accent); }
.port-chip { display:inline-block; background:var(--bg3); border:1px solid var(--border); border-radius:4px; padding:1px 6px; font-size:11px; font-family:monospace; margin:1px; }
"""

_INLINE_JS = """
function filterTable(tableId, col, value) {
  const table = document.getElementById(tableId);
  const btns  = document.querySelectorAll(`[data-table="${tableId}"][data-col="${col}"]`);
  btns.forEach(b => b.classList.toggle('active', b.dataset.value === value || (value === 'all' && b.dataset.value === 'all')));
  const rows  = table.querySelectorAll('tbody tr');
  rows.forEach(row => {
    const cell = row.cells[col];
    const show = value === 'all' || (cell && cell.textContent.toLowerCase().includes(value.toLowerCase()));
    row.style.display = show ? '' : 'none';
  });
}

function searchTable(tableId, inputId) {
  const q    = document.getElementById(inputId).value.toLowerCase();
  const rows = document.getElementById(tableId).querySelectorAll('tbody tr');
  rows.forEach(row => {
    row.style.display = row.textContent.toLowerCase().includes(q) ? '' : 'none';
  });
}

function openModal(src) {
  const m = document.getElementById('modal');
  document.getElementById('modal-img').src = src;
  m.classList.add('open');
}
document.addEventListener('keydown', e => {
  if (e.key === 'Escape') document.getElementById('modal').classList.remove('open');
});

// Sort table by column
function sortTable(tableId, col) {
  const table = document.getElementById(tableId);
  const tbody = table.querySelector('tbody');
  const rows  = Array.from(tbody.querySelectorAll('tr'));
  const asc   = table.dataset.sortCol == col && table.dataset.sortDir === 'asc';
  rows.sort((a, b) => {
    const av = a.cells[col]?.textContent.trim() || '';
    const bv = b.cells[col]?.textContent.trim() || '';
    return asc ? bv.localeCompare(av) : av.localeCompare(bv);
  });
  table.dataset.sortCol = col;
  table.dataset.sortDir = asc ? 'desc' : 'asc';
  rows.forEach(r => tbody.appendChild(r));
}
"""


def _sev_badge(sev: str) -> str:
    return f'<span class="badge badge-{sev}">{sev}</span>'


def _embed_screenshot(path: str) -> str:
    """Return base64 img tag if file small enough, else file:// link."""
    try:
        p = Path(path)
        if p.exists() and p.stat().st_size < 512_000:
            data = base64.b64encode(p.read_bytes()).decode()
            ext  = p.suffix.lstrip(".") or "png"
            return (
                f'<img class="screenshot-thumb" '
                f'src="data:image/{ext};base64,{data}" '
                f'onclick="openModal(this.src)" alt="screenshot">'
            )
    except Exception:
        pass
    return ""


def generate_html_report(session: ScanSession) -> str:
    """Render the full HTML report and return the content as a string."""
    layout  = OutputLayout.from_session(session)
    counts  = session.finding_counts
    target  = session.target.host
    started = session.started_at.strftime("%Y-%m-%d %H:%M UTC")
    dur_str = ""
    if session.completed_at and session.started_at:
        secs = int((session.completed_at - session.started_at).total_seconds())
        dur_str = f"{secs // 60}m {secs % 60}s"

    # ── Summary cards ─────────────────────────────────────────────────────────
    cards_html = ""
    for sev in ["critical", "high", "medium", "low", "info"]:
        n = counts.get(sev, 0)
        cards_html += f'<div class="card {sev}"><div class="count">{n}</div><div class="label">{sev.upper()}</div></div>\n'
    cards_html += f'<div class="card total"><div class="count">{sum(counts.values())}</div><div class="label">TOTAL</div></div>\n'
    cards_html += f'<div class="card"><div class="count">{len(session.open_ports)}</div><div class="label">OPEN PORTS</div></div>\n'
    cards_html += f'<div class="card"><div class="count">{len(session.subdomains)}</div><div class="label">SUBDOMAINS</div></div>\n'
    cards_html += f'<div class="card"><div class="count">{len(session.live_subdomains)}</div><div class="label">LIVE HOSTS</div></div>\n'

    # ── Findings table ────────────────────────────────────────────────────────
    sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    sorted_findings = sorted(
        session.findings,
        key=lambda f: (sev_order.get(f.severity.value, 9), f.title)
    )

    findings_rows = ""
    for f in sorted_findings:
        sev    = f.severity.value
        port   = str(f.port) if f.port else "—"
        cves   = " ".join(f'<code>{c}</code>' for c in f.cve_ids[:3])
        cvss   = f'<code>{f.cvss:.1f}</code>' if f.cvss else ""
        desc   = (f.description[:300] + "…" if len(f.description) > 300 else f.description).replace("<", "&lt;").replace(">", "&gt;")
        findings_rows += f"""
        <tr>
          <td>{_sev_badge(sev)}</td>
          <td><code>{f.plugin}</code></td>
          <td><strong>{f.title[:100].replace("<","&lt;")}</strong></td>
          <td><code>{f.target[:50]}</code></td>
          <td>{port}</td>
          <td class="desc-text">{desc}</td>
          <td>{cves} {cvss}</td>
        </tr>"""

    filter_btns = '<button class="filter-btn active" data-table="findings-table" data-col="0" data-value="all" onclick="filterTable(\'findings-table\',0,\'all\')">All</button>'
    for sev in ["critical", "high", "medium", "low", "info"]:
        n = counts.get(sev, 0)
        if n:
            filter_btns += f'<button class="filter-btn" data-table="findings-table" data-col="0" data-value="{sev}" onclick="filterTable(\'findings-table\',0,\'{sev}\')">{sev.capitalize()} ({n})</button>'

    # ── Ports table ───────────────────────────────────────────────────────────
    ports_rows = ""
    for p in sorted(session.open_ports, key=lambda x: x.port):
        ports_rows += f"""
        <tr>
          <td><span class="port-chip">{p.port}/{p.protocol.value}</span></td>
          <td>{p.service}</td>
          <td>{p.product}</td>
          <td><code>{p.version}</code></td>
        </tr>"""

    # ── Subdomains table ──────────────────────────────────────────────────────
    sub_rows = ""
    for s in sorted(session.subdomains, key=lambda x: x.hostname):
        live_badge = '<span class="pill-live">LIVE</span>' if s.is_live else '<span class="pill-dead">DEAD</span>'
        status     = str(s.http_status) if s.http_status else "—"
        tech       = ", ".join(s.technologies[:5]) if s.technologies else "—"
        screenshot = _embed_screenshot(s.screenshot_path) if s.screenshot_path else ""
        sub_rows += f"""
        <tr>
          <td><code>{s.hostname}</code></td>
          <td>{live_badge}</td>
          <td>{status}</td>
          <td>{s.resolved_ip or "—"}</td>
          <td>{s.source}</td>
          <td>{tech}</td>
          <td>{screenshot}</td>
        </tr>"""

    # ── Tasks table ───────────────────────────────────────────────────────────
    task_rows = ""
    for t in session.tasks:
        dur    = f"{t.duration_seconds:.1f}s" if t.duration_seconds else "—"
        status_color = {
            "done": "var(--green)", "failed": "var(--critical)",
            "skipped": "var(--muted)", "running": "var(--medium)",
            "pending": "var(--muted)",
        }.get(t.status.value, "var(--muted)")
        task_rows += f"""
        <tr>
          <td><code>{t.plugin}</code></td>
          <td>{t.port or "—"}</td>
          <td><span style="color:{status_color}">{t.status.value}</span></td>
          <td>{dur}</td>
          <td>{len(t.findings)}</td>
          <td style="color:var(--critical);font-size:11px">{(t.error or "")[:80]}</td>
        </tr>"""

    # ── Assemble ──────────────────────────────────────────────────────────────
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Z3R0 Recon Report — {target}</title>
<style>{_INLINE_STYLES}</style>
</head>
<body>
<div id="modal" class="modal" onclick="this.classList.remove('open')">
  <button class="modal-close" onclick="document.getElementById('modal').classList.remove('open')">✕</button>
  <img id="modal-img" src="" alt="screenshot">
</div>
<div class="container">
  <h1>Z3R0 Recon Report</h1>
  <div class="meta">
    Target: <strong>{target}</strong> &nbsp;|&nbsp;
    Session: <code>{session.session_id[:8]}</code> &nbsp;|&nbsp;
    Date: {started}
    {f"&nbsp;|&nbsp; Duration: {dur_str}" if dur_str else ""}
    &nbsp;|&nbsp; Operator: {session.operator}
    &nbsp;|&nbsp; Authorized: {"✅" if session.authorized else "❌"}
  </div>

  <h2>Summary</h2>
  <div class="cards">{cards_html}</div>

  <h2>Findings</h2>
  <div class="toolbar">
    <div class="filters">{filter_btns}</div>
    <input type="search" id="findings-search" placeholder="Search findings…" oninput="searchTable('findings-table','findings-search')">
  </div>
  <table id="findings-table">
    <thead>
      <tr>
        <th onclick="sortTable('findings-table',0)" style="cursor:pointer">Severity ↕</th>
        <th onclick="sortTable('findings-table',1)" style="cursor:pointer">Plugin ↕</th>
        <th onclick="sortTable('findings-table',2)" style="cursor:pointer">Title ↕</th>
        <th>Target</th>
        <th>Port</th>
        <th>Description</th>
        <th>CVEs / CVSS</th>
      </tr>
    </thead>
    <tbody>{findings_rows}</tbody>
  </table>

  <h2>Open Ports ({len(session.open_ports)})</h2>
  <table id="ports-table">
    <thead><tr><th>Port</th><th>Service</th><th>Product</th><th>Version</th></tr></thead>
    <tbody>{ports_rows}</tbody>
  </table>

  <h2>Subdomains ({len(session.subdomains)})</h2>
  <div class="toolbar">
    <input type="search" id="sub-search" placeholder="Search subdomains…" oninput="searchTable('sub-table','sub-search')">
  </div>
  <table id="sub-table">
    <thead><tr><th>Hostname</th><th>Live</th><th>HTTP</th><th>IP</th><th>Source</th><th>Technologies</th><th>Screenshot</th></tr></thead>
    <tbody>{sub_rows if sub_rows else "<tr><td colspan='7' style='color:var(--muted);text-align:center'>No subdomains enumerated</td></tr>"}</tbody>
  </table>

  <h2>Scan Execution</h2>
  <table id="tasks-table">
    <thead><tr><th>Plugin</th><th>Port</th><th>Status</th><th>Duration</th><th>Findings</th><th>Error</th></tr></thead>
    <tbody>{task_rows}</tbody>
  </table>
</div>
<script>{_INLINE_JS}</script>
</body>
</html>"""
