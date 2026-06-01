"""
reporting/engine.py — Report engine.

Reads from ScanSession.findings (structured Finding objects) and
generates useful reports. Unlike the original which enumerated
what *ran*, this reports what was *found*.

Key improvements:
- Findings sorted by severity (critical → info)
- CVE IDs surfaced prominently
- WAF detection, technology inventory, and discovered paths aggregated
- JSON export for machine consumption (CI/CD, ticketing system import)
- Markdown report suitable for pentest deliverables
"""

from __future__ import annotations

import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Optional

from ..core.models import Finding, FindingSeverity, ScanSession
from ..core.output_layout import OutputLayout
from .html_report import generate_html_report

logger = logging.getLogger("z3r0.reporting")


# Severity ordering for report sorting
_SEVERITY_ORDER = {
    FindingSeverity.CRITICAL: 0,
    FindingSeverity.HIGH:     1,
    FindingSeverity.MEDIUM:   2,
    FindingSeverity.LOW:      3,
    FindingSeverity.INFO:     4,
}

_SEVERITY_EMOJI = {
    FindingSeverity.CRITICAL: "🔴",
    FindingSeverity.HIGH:     "🟠",
    FindingSeverity.MEDIUM:   "🟡",
    FindingSeverity.LOW:      "🔵",
    FindingSeverity.INFO:     "⚪",
}


def generate_reports(session: ScanSession) -> dict[str, str]:
    """
    Generate all report formats for a completed session.
    Returns a dict of {label: full_path}.
    """
    layout = OutputLayout.from_session(session)
    paths  = {}

    md_path = layout.markdown_report
    md_path.write_text(_render_markdown(session), encoding="utf-8")
    paths["markdown"] = str(md_path)

    json_path = layout.json_report
    json_path.write_text(_render_json(session), encoding="utf-8")
    paths["json"] = str(json_path)

    # HTML report
    try:
        html_path = layout.html_report
        html_path.write_text(generate_html_report(session), encoding="utf-8")
        paths["html"] = str(html_path)
    except Exception as e:
        logger.warning(f"HTML report generation failed: {e}")

    return paths


def _sorted_findings(findings: list[Finding]) -> list[Finding]:
    return sorted(findings, key=lambda f: _SEVERITY_ORDER.get(f.severity, 99))


def _render_markdown(session: ScanSession) -> str:
    target    = session.target.host
    now       = datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")
    findings  = _sorted_findings(session.findings)
    counts    = session.finding_counts

    # ─── Duration ─────────────────────────────────────────────────────────────
    duration = ""
    if session.completed_at and session.started_at:
        secs = (session.completed_at - session.started_at).total_seconds()
        duration = f"**Duration:** {secs:.0f}s  \n"

    # ─── Summary section ──────────────────────────────────────────────────────
    summary_rows = "\n".join(
        f"| {sev.capitalize()} | {counts.get(sev, 0)} |"
        for sev in ["critical", "high", "medium", "low", "info"]
    )

    # ─── Port table ───────────────────────────────────────────────────────────
    port_rows = "\n".join(
        f"| {p.port}/{p.protocol.value} | {p.service} | {p.version_string} |"
        for p in session.open_ports
    ) or "| — | — | — |"

    # ─── Subdomains section ───────────────────────────────────────────────────
    sub_section = ""
    if session.subdomains:
        live = session.live_subdomains
        sub_rows = "\n".join(
            f"| `{s.hostname}` | {'✅ Live' if s.is_live else '❌'} | "
            f"{s.http_status or '—'} | {s.source} |"
            for s in sorted(session.subdomains, key=lambda x: x.hostname)[:50]
        )
        overflow = (
            f"\n*...and {len(session.subdomains)-50} more — see reports/findings.json*"
            if len(session.subdomains) > 50 else ""
        )
        sub_section = f"""
## Subdomains ({len(session.subdomains)} discovered, {len(live)} live)

| Hostname | Live | HTTP | Source |
|----------|------|------|--------|
{sub_rows}{overflow}

---
"""

    # ─── Finding blocks ───────────────────────────────────────────────────────
    finding_sections = ""
    for f in findings:
        emoji    = _SEVERITY_EMOJI.get(f.severity, "⚪")
        port_str = f" (port {f.port})" if f.port else ""
        cve_str  = ""
        if f.cve_ids:
            cve_str = "\n\n**CVEs:** " + ", ".join(f"`{c}`" for c in f.cve_ids)
        cvss_str = f" | CVSS: {f.cvss}" if f.cvss else ""
        evidence_str = ""
        if f.evidence:
            evidence_str = "\n\n**Evidence:**\n" + "\n".join(
                f"- `{e}`" for e in f.evidence if e
            )

        finding_sections += f"""
### {emoji} {f.title}

**Plugin:** `{f.plugin}` | **Severity:** `{f.severity.value.upper()}`{cvss_str}{port_str}

{f.description}
{cve_str}{evidence_str}

---
"""

    # ─── Task summary ─────────────────────────────────────────────────────────
    task_rows = "\n".join(
        f"| `{t.plugin}` | {t.port or '—'} | {t.status.value} | "
        f"{f'{t.duration_seconds:.1f}s' if t.duration_seconds else '—'} |"
        for t in session.tasks
    )

    # ─── Assemble ─────────────────────────────────────────────────────────────
    return f"""# Z3R0 Recon Report

**Target:** `{target}`
**Session:** `{session.session_id}`
**Date:** {now}
**Operator:** {session.operator}
{duration}**Authorized:** {'✅ Yes' if session.authorized else '❌ Not confirmed'}

---

## Finding Summary

| Severity | Count |
|----------|-------|
{summary_rows}

**Total findings:** {len(findings)}

---

## Open Ports

| Port/Protocol | Service | Version |
|--------------|---------|---------|
{port_rows}

---
{sub_section}
## Findings

{finding_sections if finding_sections else '_No findings recorded._'}

---

## Scan Execution

| Plugin | Port | Status | Duration |
|--------|------|--------|----------|
{task_rows or '| — | — | — | — |'}

---

## Recommended Next Steps

- [ ] Investigate all CRITICAL and HIGH findings immediately
- [ ] Review CVE findings for public exploit availability
- [ ] Manually test discovered web paths for authentication bypass, SQLi, XSS
- [ ] Verify database findings — check for accessible data
- [ ] Cross-reference version findings with NVD for patch status

---

*Generated by Z3R0 Recon Framework*
"""


def _render_json(session: ScanSession) -> str:
    return json.dumps({
        "session_id":    session.session_id,
        "target":        session.target.host,
        "started_at":    session.started_at.isoformat(),
        "completed_at":  session.completed_at.isoformat() if session.completed_at else None,
        "operator":      session.operator,
        "authorized":    session.authorized,
        "open_ports": [
            {
                "port":     p.port,
                "protocol": p.protocol.value,
                "service":  p.service,
                "product":  p.product,
                "version":  p.version,
            }
            for p in session.open_ports
        ],
        "subdomains":    [s.to_dict() for s in session.subdomains],
        "finding_counts": session.finding_counts,
        "findings":      [f.to_dict() for f in _sorted_findings(session.findings)],
        "tasks": [
            {
                "id":            t.id,
                "plugin":        t.plugin,
                "port":          t.port,
                "status":        t.status.value,
                "error":         t.error,
                "duration_s":    t.duration_seconds,
                "finding_count": len(t.findings),
            }
            for t in session.tasks
        ],
    }, indent=2, default=str)
