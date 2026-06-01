"""
plugins/nuclei_scan.py — Nuclei vulnerability scanning plugin.

Nuclei runs community-maintained templates against web targets. It is
far more comprehensive than Nikto for modern web vulnerabilities, with
structured JSON output that maps directly to Finding objects.

Severity mapping: nuclei uses critical/high/medium/low/info — identical
to our FindingSeverity enum, so mapping is 1:1.

Install:
    go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
    # Update templates:
    nuclei -update-templates
"""

from __future__ import annotations

import json
import logging
import shutil
from pathlib import Path
from typing import ClassVar

from ..core.models import Finding, FindingSeverity, ScanSession, TaskRecord
from ..core.output_layout import OutputLayout
from ..core.plugin_base import PluginMeta, ReconPlugin

logger = logging.getLogger("z3r0.nuclei")

_SEVERITY_MAP = {
    "critical": FindingSeverity.CRITICAL,
    "high":     FindingSeverity.HIGH,
    "medium":   FindingSeverity.MEDIUM,
    "low":      FindingSeverity.LOW,
    "info":     FindingSeverity.INFO,
    "unknown":  FindingSeverity.INFO,
}


class NucleiPlugin(ReconPlugin):

    meta: ClassVar[PluginMeta] = PluginMeta(
        name="nuclei",
        description="Template-based vulnerability scanning via Nuclei",
        triggers_on_ports=frozenset({80, 443, 8080, 8443, 8000, 8008, 8888, 3000, 5000}),
        requires_binary="nuclei",
        default_timeout=600,
    )

    async def execute(
        self, task: TaskRecord, session: ScanSession
    ) -> list[Finding]:
        url     = task.params.get("url", "")
        port    = task.port or 80
        config  = session.config
        layout  = OutputLayout.from_session(session)
        out_file = layout.nuclei_result(port)

        if not url:
            return []

        if not shutil.which("nuclei"):
            return [Finding(
                plugin=self.meta.name,
                title="nuclei not installed",
                severity=FindingSeverity.INFO,
                target=url, port=port,
                description="Install nuclei: go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
            )]

        cmd = [
            "nuclei",
            "-u", url,
            "-j",                      # JSON output (one object per line)
            "-o", str(out_file),
            "-silent",
            "-no-color",
        ]

        # Template selection: custom dir > default (critical+high+medium)
        if config.nuclei_templates and Path(config.nuclei_templates).exists():
            cmd += ["-t", config.nuclei_templates]
        else:
            # Default: critical, high, medium severity templates only
            cmd += ["-severity", "critical,high,medium,low"]

        # Rate limiting — be a good citizen
        cmd += ["-rate-limit", "50", "-bulk-size", "25"]

        logger.info(f"nuclei: scanning {url}")

        try:
            stdout, stderr, rc = await self.run_subprocess(
                cmd, timeout=self.meta.default_timeout
            )
        except TimeoutError:
            return [Finding(
                plugin=self.meta.name,
                title="nuclei timed out",
                severity=FindingSeverity.INFO,
                target=url, port=port,
                description="Nuclei exceeded timeout — partial results may exist.",
            )]
        except Exception as e:
            return [Finding(
                plugin=self.meta.name,
                title=f"nuclei error: {e}",
                severity=FindingSeverity.INFO,
                target=url, port=port,
                description=str(e),
            )]

        return self._parse_nuclei_json(out_file, url, port)

    def _parse_nuclei_json(
        self, out_file: Path, url: str, port: int
    ) -> list[Finding]:
        findings: list[Finding] = []

        try:
            content = out_file.read_text(encoding="utf-8")
        except FileNotFoundError:
            return []

        for line in content.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                entry = json.loads(line)
            except json.JSONDecodeError:
                continue

            info       = entry.get("info", {})
            sev_str    = info.get("severity", "info").lower()
            severity   = _SEVERITY_MAP.get(sev_str, FindingSeverity.INFO)
            name       = info.get("name", "Unknown")
            description = info.get("description", "")
            matched_at = entry.get("matched-at", url)
            template_id = entry.get("template-id", "")
            cve_ids    = info.get("classification", {}).get("cve-id", [])
            cvss_score = info.get("classification", {}).get("cvss-score")
            tags       = info.get("tags", [])
            references = info.get("reference", [])

            if isinstance(cve_ids, str):
                cve_ids = [cve_ids]
            if isinstance(references, str):
                references = [references]

            evidence = [f"matched-at: {matched_at}"]
            if references:
                evidence += [f"ref: {r}" for r in references[:3]]

            findings.append(Finding(
                plugin=self.meta.name,
                title=f"[{template_id}] {name}",
                severity=severity,
                target=url,
                port=port,
                description=description or f"Nuclei template match: {template_id}",
                evidence=evidence,
                cve_ids=cve_ids if cve_ids else [],
                cvss=float(cvss_score) if cvss_score else None,
                metadata={
                    "template_id": template_id,
                    "matched_at":  matched_at,
                    "tags":        tags,
                    "severity":    sev_str,
                },
            ))

        if not findings:
            findings.append(Finding(
                plugin=self.meta.name,
                title="nuclei: no vulnerabilities found",
                severity=FindingSeverity.INFO,
                target=url, port=port,
                description="Nuclei completed with no template matches.",
            ))

        return findings
