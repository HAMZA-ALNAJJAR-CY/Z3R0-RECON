"""
plugins/masscan_scan.py — Masscan rapid port scanning plugin.

Scans CIDR ranges or target IPs at high packet rates, then feeds
discovered open ports into the existing Nmap service detection phase.

Masscan finds open ports quickly but doesn't do service detection.
The output (IP:port pairs) is handed to NmapPlugin for -sV follow-up.

Install:
    apt install masscan
    # or build from source: https://github.com/robertdavidgraham/masscan

Usage (via CLI):
    python3 -m z3r0_recon -t 10.10.10.0/24 --masscan --masscan-rate 5000
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

logger = logging.getLogger("z3r0.masscan")

# Top 1000 ports as a masscan-compatible range string
_TOP_PORTS = (
    "21,22,23,25,53,80,88,110,111,135,139,143,161,389,443,445,465,587,"
    "636,993,995,1433,1521,1723,3306,3389,5432,5900,6379,8080,8443,8888,"
    "9200,9300,27017"
)


class MasscanPlugin(ReconPlugin):

    meta: ClassVar[PluginMeta] = PluginMeta(
        name="masscan_scan",
        description="Rapid port scanning via masscan for CIDR ranges",
        always_run=False,
        requires_binary="masscan",
        default_timeout=600,
    )

    async def execute(
        self, task: TaskRecord, session: ScanSession
    ) -> list[Finding]:
        target   = task.params.get("cidr") or str(task.target)
        rate     = task.params.get("rate", session.config.masscan_rate)
        ports    = task.params.get("ports", _TOP_PORTS)
        layout   = OutputLayout.from_session(session)
        out_file = layout.masscan_result   # JSON output

        if not shutil.which("masscan"):
            return [Finding(
                plugin=self.meta.name,
                title="masscan not installed",
                severity=FindingSeverity.INFO,
                target=target, port=None,
                description="Install masscan: apt install masscan",
            )]

        cmd = [
            "masscan", target,
            "-p", ports,
            "--rate", str(rate),
            "-oJ", str(out_file),
            "--open",
        ]

        logger.info(f"masscan: scanning {target} at {rate} pps")

        try:
            stdout, stderr, rc = await self.run_subprocess(
                cmd, timeout=self.meta.default_timeout
            )
        except TimeoutError:
            return [Finding(
                plugin=self.meta.name,
                title="masscan timed out",
                severity=FindingSeverity.INFO,
                target=target, port=None,
                description="masscan exceeded timeout — partial results may exist",
            )]
        except Exception as e:
            return [Finding(
                plugin=self.meta.name,
                title=f"masscan error: {e}",
                severity=FindingSeverity.INFO,
                target=target, port=None,
                description=str(e),
            )]

        findings = self._parse_masscan_json(out_file, target, layout)
        return findings

    def _parse_masscan_json(
        self,
        json_path: Path,
        target: str,
        layout: OutputLayout,
    ) -> list[Finding]:
        try:
            text = json_path.read_text(encoding="utf-8")
            # masscan JSON is not valid JSON array — it ends with a trailing comma
            # Fix: strip trailing comma and wrap in []
            text = text.strip()
            if text.endswith(","):
                text = text[:-1]
            if not text.startswith("["):
                text = f"[{text}]"
            results = json.loads(text)
        except (FileNotFoundError, json.JSONDecodeError, Exception) as e:
            logger.error(f"masscan JSON parse failed: {e}")
            return [Finding(
                plugin=self.meta.name,
                title="masscan output parse error",
                severity=FindingSeverity.INFO,
                target=target, port=None,
                description=str(e),
            )]

        if not results:
            return [Finding(
                plugin=self.meta.name,
                title="masscan: no open ports found",
                severity=FindingSeverity.INFO,
                target=target, port=None,
                description="masscan completed with no open ports in range.",
            )]

        # Build open_ports.txt for Nmap follow-up and produce findings
        open_ports_text = []
        findings: list[Finding] = []
        ip_port_map: dict[str, list[int]] = {}

        for entry in results:
            ip = entry.get("ip", "")
            for port_data in entry.get("ports", []):
                port = port_data.get("port", 0)
                proto = port_data.get("proto", "tcp")
                status = port_data.get("status", "")
                if status == "open":
                    open_ports_text.append(f"{ip}:{port}/{proto}")
                    ip_port_map.setdefault(ip, []).append(port)

        layout.masscan_open_ports.write_text(
            "\n".join(open_ports_text), encoding="utf-8"
        )

        # One finding per discovered host
        for ip, ports in ip_port_map.items():
            findings.append(Finding(
                plugin=self.meta.name,
                title=f"masscan: {ip} — {len(ports)} open ports",
                severity=FindingSeverity.INFO,
                target=ip,
                port=None,
                description=f"Open ports: {', '.join(str(p) for p in sorted(ports))}",
                evidence=sorted(f"{ip}:{p}" for p in ports),
                metadata={"ip": ip, "ports": sorted(ports)},
            ))

        findings.insert(0, Finding(
            plugin=self.meta.name,
            title=f"masscan: {len(ip_port_map)} hosts with open ports",
            severity=FindingSeverity.INFO,
            target=target, port=None,
            description=(
                f"Scanned range: {target}\n"
                f"Hosts with open ports: {len(ip_port_map)}\n"
                f"Total open port instances: {len(open_ports_text)}\n"
                f"Results: {layout.masscan_open_ports}"
            ),
            metadata={"hosts": len(ip_port_map), "total_ports": len(open_ports_text)},
        ))

        return findings
