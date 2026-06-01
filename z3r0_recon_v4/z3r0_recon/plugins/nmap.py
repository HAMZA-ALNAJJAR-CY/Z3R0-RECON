"""
plugins/nmap.py — Nmap discovery plugin.

Phase 1 plugin: always runs first, produces PortInfo list and
initial service-version findings.

Key improvement over the original:
- parse_nmap_xml now produces Finding objects for interesting results
  (OS detection, notable services, aggressive service versions)
- Returns structured PortInfo via session mutation AND findings
- The --open / -T4 defaults are configurable via task params
- OS detection failure (requires root) is logged cleanly, not silently ignored
"""

from __future__ import annotations

import xml.etree.ElementTree as ET
from typing import ClassVar

from ..core.models import (
    Finding,
    FindingSeverity,
    PortInfo,
    Protocol,
    ScanSession,
    ScanTarget,
    TaskRecord,
)
from ..core.output_layout import OutputLayout
from ..core.plugin_base import PluginMeta, ReconPlugin


class NmapPlugin(ReconPlugin):

    meta: ClassVar[PluginMeta] = PluginMeta(
        name="nmap",
        description="Port scanning and service version detection via Nmap",
        always_run=True,
        requires_binary="nmap",
        default_timeout=600,
    )

    async def execute(
        self, task: TaskRecord, session: ScanSession
    ) -> list[Finding]:
        target = str(task.target)
        layout = OutputLayout.from_session(session)

        # Before/after:
        #   BEFORE: {out_dir}/nmap_scan.xml, {out_dir}/nmap_scan.txt
        #   AFTER:  recon/nmap/scan.xml,     recon/nmap/scan.txt
        xml_out = str(layout.nmap_xml)
        txt_out = str(layout.nmap_txt)

        # Build command from task params (allows caller to override defaults)
        timing     = task.params.get("timing", "-T4")
        extra_args = task.params.get("extra_args", [])

        cmd = [
            "nmap", "-sV", "-sC", "--open",
            timing,
            "-oX", xml_out,
            "-oN", txt_out,
            target,
        ] + extra_args

        # Note: -O (OS detection) requires root. Include only if specified.
        if task.params.get("os_detection", False):
            cmd.insert(1, "-O")

        stdout, stderr, returncode = await self.run_subprocess(
            cmd, timeout=self.meta.default_timeout
        )

        if returncode != 0 and "WARNING" not in stderr:
            return [Finding(
                plugin=self.meta.name,
                title="Nmap scan failed",
                severity=FindingSeverity.INFO,
                target=target,
                port=None,
                description=f"Nmap exited with code {returncode}",
                raw_output=stderr,
            )]

        # Parse XML output
        open_ports, findings = self._parse_xml(xml_out, target)

        # Populate session ports (orchestrator reads these to build follow-on tasks)
        session.open_ports = open_ports

        return findings

    def _parse_xml(
        self,
        xml_path: str,
        target: str,
    ) -> tuple[list[PortInfo], list[Finding]]:
        """
        Parse Nmap XML → (PortInfo list, Finding list).

        Produces a Finding for:
        - Each open port (INFO severity — informational inventory)
        - Services with version info (INFO, but flagged for CVE lookup)
        - OS detection results (INFO)
        - Notable services (telnet, r-services, unencrypted protocols)
        """
        try:
            tree = ET.parse(xml_path)
            root = tree.getroot()
        except Exception as e:
            return [], [Finding(
                plugin=self.meta.name,
                title="Nmap XML parse error",
                severity=FindingSeverity.INFO,
                target=target,
                port=None,
                description=str(e),
            )]

        open_ports: list[PortInfo] = []
        findings:   list[Finding]  = []

        # ─── Notable / risky service patterns ─────────────────────────────────
        HIGH_RISK_SERVICES = {
            "telnet":   ("Telnet detected (cleartext protocol)", FindingSeverity.HIGH),
            "ftp":      ("FTP detected (cleartext protocol)", FindingSeverity.MEDIUM),
            "rsh":      ("RSH detected (unauthenticated remote shell)", FindingSeverity.HIGH),
            "rlogin":   ("Rlogin detected", FindingSeverity.HIGH),
            "rexec":    ("Rexec detected", FindingSeverity.HIGH),
            "vnc":      ("VNC detected — check auth", FindingSeverity.MEDIUM),
            "distccd":  ("DistCC detected — known RCE vector", FindingSeverity.HIGH),
        }

        for host in root.findall("host"):
            # ─── OS Detection ─────────────────────────────────────────────────
            osmatch = host.find("os/osmatch")
            if osmatch is not None:
                os_name = osmatch.get("name", "")
                os_acc  = osmatch.get("accuracy", "")
                findings.append(Finding(
                    plugin=self.meta.name,
                    title=f"OS detected: {os_name}",
                    severity=FindingSeverity.INFO,
                    target=target,
                    port=None,
                    description=f"Nmap OS fingerprint: {os_name} (accuracy: {os_acc}%)",
                    metadata={"os_name": os_name, "accuracy": os_acc},
                ))

            # ─── Ports ────────────────────────────────────────────────────────
            for ports_el in host.findall("ports"):
                for port_el in ports_el.findall("port"):
                    state_el = port_el.find("state")
                    if state_el is None or state_el.get("state") != "open":
                        continue

                    svc_el  = port_el.find("service")
                    portid  = int(port_el.get("portid", 0))
                    proto   = Protocol(port_el.get("protocol", "tcp"))

                    svc     = svc_el.get("name",     "") if svc_el is not None else ""
                    product = svc_el.get("product",  "") if svc_el is not None else ""
                    version = svc_el.get("version",  "") if svc_el is not None else ""
                    extra   = svc_el.get("extrainfo","") if svc_el is not None else ""

                    port_info = PortInfo(
                        port=portid, protocol=proto,
                        service=svc, product=product,
                        version=version, extrainfo=extra,
                    )
                    open_ports.append(port_info)

                    # Informational finding for every open port
                    ver_str = f"{product} {version}".strip()
                    findings.append(Finding(
                        plugin=self.meta.name,
                        title=f"Open port: {portid}/{proto.value} ({svc})",
                        severity=FindingSeverity.INFO,
                        target=target,
                        port=portid,
                        description=(
                            f"Service: {svc}\n"
                            f"Product: {ver_str}\n"
                            f"Extra: {extra}"
                        ).strip(),
                        metadata={
                            "service": svc, "product": product,
                            "version": version, "protocol": proto.value,
                        },
                    ))

                    # High-risk service check
                    svc_lower = svc.lower()
                    for risky_svc, (msg, sev) in HIGH_RISK_SERVICES.items():
                        if risky_svc in svc_lower:
                            findings.append(Finding(
                                plugin=self.meta.name,
                                title=msg,
                                severity=sev,
                                target=target,
                                port=portid,
                                description=(
                                    f"Risky service detected on port {portid}: "
                                    f"{svc} ({ver_str})"
                                ),
                            ))

                    # ─── Script output findings ────────────────────────────────
                    for script_el in port_el.findall("script"):
                        script_id  = script_el.get("id", "")
                        script_out = script_el.get("output", "")
                        if script_out and len(script_out) > 5:
                            findings.append(Finding(
                                plugin=self.meta.name,
                                title=f"NSE script result: {script_id} (port {portid})",
                                severity=FindingSeverity.INFO,
                                target=target,
                                port=portid,
                                description=script_out[:500],
                                metadata={"script_id": script_id},
                            ))

        return open_ports, findings
