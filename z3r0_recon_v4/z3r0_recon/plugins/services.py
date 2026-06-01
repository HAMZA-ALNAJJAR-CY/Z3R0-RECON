"""
plugins/services.py — Non-web service plugins.

Covers: SMB/enum4linux, FTP, SSH, MySQL, MSSQL, Redis, MongoDB, SNMP, CVE lookup.

Each plugin uses nmap NSE scripts or dedicated tools, parses the output,
and returns structured Finding objects. No flat text fallback.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import ClassVar, Optional

from ..core.models import Finding, FindingSeverity, ScanSession, TaskRecord
from ..core.output_layout import OutputLayout
from ..core.plugin_base import PluginMeta, ReconPlugin


# ─── SMB / enum4linux ─────────────────────────────────────────────────────────

class Enum4linuxPlugin(ReconPlugin):

    meta: ClassVar[PluginMeta] = PluginMeta(
        name="enum4linux",
        description="SMB/NetBIOS enumeration via enum4linux",
        triggers_on_ports=frozenset({139, 445}),
        requires_binary="enum4linux",
        default_timeout=120,
    )

    async def execute(
        self, task: TaskRecord, session: ScanSession
    ) -> list[Finding]:
        target   = str(task.target)
        layout   = OutputLayout.from_session(session)
        out_file = layout.enum4linux_result  # recon/smb/enum4linux.txt

        try:
            stdout, stderr, rc = await self.run_subprocess(
                ["enum4linux", "-a", target],
                timeout=self.meta.default_timeout,
            )
            output = stdout + stderr
        except TimeoutError:
            return [Finding(
                plugin=self.meta.name,
                title="enum4linux timed out",
                severity=FindingSeverity.INFO,
                target=target, port=task.port,
                description="enum4linux exceeded timeout.",
            )]

        self.save_raw_output(output, session, out_file)
        return self._parse(output, target, task.port)

    def _parse(self, output: str, target: str, port: Optional[int]) -> list[Finding]:
        findings = []

        # Null session check
        if "session setup successfully" in output.lower():
            findings.append(Finding(
                plugin=self.meta.name,
                title="SMB null session allowed",
                severity=FindingSeverity.HIGH,
                target=target, port=port,
                description="Null session authentication succeeded — unauthenticated SMB enumeration possible.",
            ))

        # User enumeration
        users = re.findall(r"user:\[(\w+)\]", output)
        if users:
            findings.append(Finding(
                plugin=self.meta.name,
                title=f"SMB users enumerated: {', '.join(users[:10])}",
                severity=FindingSeverity.MEDIUM,
                target=target, port=port,
                description=f"Enumerated {len(users)} user(s) via SMB: {', '.join(users)}",
                evidence=users,
                metadata={"users": users},
            ))

        # Share enumeration
        shares = re.findall(r"Sharename\s+Type\s+Comment\n[-\s]+\n((?:.*\n)*?)(?=\n|\Z)", output)
        share_names = re.findall(r"^\s+(\S+)\s+Disk", output, re.MULTILINE)
        if share_names:
            findings.append(Finding(
                plugin=self.meta.name,
                title=f"SMB shares found: {', '.join(share_names[:5])}",
                severity=FindingSeverity.INFO,
                target=target, port=port,
                description=f"Accessible shares: {', '.join(share_names)}",
                metadata={"shares": share_names},
            ))

        # Password policy
        if "minimum password length" in output.lower():
            min_pass = re.search(r"minimum password length:\s*(\d+)", output, re.IGNORECASE)
            if min_pass and int(min_pass.group(1)) < 8:
                findings.append(Finding(
                    plugin=self.meta.name,
                    title=f"Weak password policy: minimum length {min_pass.group(1)}",
                    severity=FindingSeverity.MEDIUM,
                    target=target, port=port,
                    description=f"SMB password policy minimum length: {min_pass.group(1)} characters",
                ))

        return findings or [Finding(
            plugin=self.meta.name,
            title="enum4linux: no notable findings",
            severity=FindingSeverity.INFO,
            target=target, port=port,
            description="SMB enumeration completed without notable findings.",
        )]


# ─── FTP ──────────────────────────────────────────────────────────────────────

class FtpCheckPlugin(ReconPlugin):

    meta: ClassVar[PluginMeta] = PluginMeta(
        name="ftp_check",
        description="FTP anonymous login check via nmap NSE",
        triggers_on_ports=frozenset({21}),
        requires_binary="nmap",
        default_timeout=60,
    )

    async def execute(
        self, task: TaskRecord, session: ScanSession
    ) -> list[Finding]:
        target   = str(task.target)
        layout   = OutputLayout.from_session(session)
        out_file = layout.ftp_anon_result   # recon/ftp/ftp_anon.txt

        stdout, stderr, _ = await self.run_subprocess([
            "nmap", "-p", "21", "--script", "ftp-anon,ftp-bounce",
            target, "-oN", str(out_file),
        ], timeout=self.meta.default_timeout)

        output = stdout + stderr
        findings = []

        if "anonymous ftp login allowed" in output.lower():
            findings.append(Finding(
                plugin=self.meta.name,
                title="FTP anonymous login allowed",
                severity=FindingSeverity.HIGH,
                target=target, port=21,
                description=(
                    "FTP server allows anonymous login. "
                    "Unauthenticated read (and possibly write) access may be possible."
                ),
                evidence=["ftp-anon NSE: anonymous login allowed"],
            ))

        if "ftp-bounce" in output.lower() and "allowed" in output.lower():
            findings.append(Finding(
                plugin=self.meta.name,
                title="FTP bounce attack possible",
                severity=FindingSeverity.MEDIUM,
                target=target, port=21,
                description="FTP bounce scanning is enabled on this server.",
            ))

        return findings or [Finding(
            plugin=self.meta.name,
            title="FTP: anonymous login not allowed",
            severity=FindingSeverity.INFO,
            target=target, port=21,
            description="FTP anonymous access check completed — not allowed.",
        )]


# ─── SSH ──────────────────────────────────────────────────────────────────────

class SshAuditPlugin(ReconPlugin):

    meta: ClassVar[PluginMeta] = PluginMeta(
        name="ssh_audit",
        description="SSH configuration audit via nmap NSE scripts",
        triggers_on_ports=frozenset({22}),
        requires_binary="nmap",
        default_timeout=60,
    )

    async def execute(
        self, task: TaskRecord, session: ScanSession
    ) -> list[Finding]:
        target   = str(task.target)
        layout   = OutputLayout.from_session(session)
        out_file = layout.ssh_audit_result   # recon/ssh/ssh_audit.txt

        stdout, stderr, _ = await self.run_subprocess([
            "nmap", "-p", "22", "--script",
            "ssh-auth-methods,ssh-hostkey,ssh2-enum-algos",
            target, "-oN", str(out_file),
        ], timeout=self.meta.default_timeout)

        output = stdout + stderr
        findings = []

        # Check for password auth enabled
        if "password" in output.lower() and "publickey" not in output.lower():
            findings.append(Finding(
                plugin=self.meta.name,
                title="SSH password authentication enabled",
                severity=FindingSeverity.MEDIUM,
                target=target, port=22,
                description=(
                    "SSH server allows password authentication. "
                    "Consider enforcing key-only authentication."
                ),
            ))

        # Weak algorithms
        weak_algos = ["arcfour", "des", "3des", "md5", "sha1-96"]
        detected_weak = [a for a in weak_algos if a in output.lower()]
        if detected_weak:
            findings.append(Finding(
                plugin=self.meta.name,
                title=f"SSH weak algorithms: {', '.join(detected_weak)}",
                severity=FindingSeverity.MEDIUM,
                target=target, port=22,
                description=f"Weak SSH algorithms detected: {', '.join(detected_weak)}",
                evidence=detected_weak,
            ))

        # Version-based findings
        version = task.params.get("version", "")
        if version and re.search(r"OpenSSH_[1-6]\.", version):
            findings.append(Finding(
                plugin=self.meta.name,
                title=f"Outdated SSH version: {version}",
                severity=FindingSeverity.MEDIUM,
                target=target, port=22,
                description=f"SSH server is running an older version: {version}",
            ))

        return findings or [Finding(
            plugin=self.meta.name,
            title="SSH audit complete",
            severity=FindingSeverity.INFO,
            target=target, port=22,
            description="SSH audit completed — no notable weaknesses detected.",
        )]


# ─── Database Checks ──────────────────────────────────────────────────────────

class _NmapScriptPlugin(ReconPlugin):
    """Shared base for nmap NSE-based service checks."""

    meta: ClassVar[PluginMeta] = PluginMeta(
        name="_base",
        description="Base for NSE plugins",
        requires_binary="nmap",
        default_timeout=60,
    )

    _port: int = 0
    _scripts: str = ""
    _anon_patterns: list[str] = []

    # Subclasses set this to the service name used for db_result() lookup.
    # e.g. "mysql", "mssql", "redis", "mongo", "snmp"
    _service_name: str = "unknown"

    def _output_path(self, layout: OutputLayout) -> Path:
        """
        Return the output file Path for this plugin.

        Default: recon/db/{service_name}/results.txt
        Override in subclasses that don't fit the db/ convention (e.g. SNMP).
        """
        return layout.db_result(self._service_name)

    async def execute(
        self, task: TaskRecord, session: ScanSession
    ) -> list[Finding]:
        target   = str(task.target)
        layout   = OutputLayout.from_session(session)
        out_file = self._output_path(layout)

        stdout, stderr, _ = await self.run_subprocess([
            "nmap", "-p", str(self._port), "--script", self._scripts,
            target, "-oN", str(out_file),
        ], timeout=self.meta.default_timeout)

        output = stdout + stderr
        self.save_raw_output(output, session, out_file)
        return self._parse_service_output(output, target, task.port)

    def _parse_service_output(
        self, output: str, target: str, port: Optional[int]
    ) -> list[Finding]:
        findings = []
        output_lower = output.lower()

        for pattern in self._anon_patterns:
            if pattern in output_lower:
                findings.append(Finding(
                    plugin=self.meta.name,
                    title=f"Unauthenticated {self.meta.name.upper().replace('_CHECK','')} access",
                    severity=FindingSeverity.CRITICAL,
                    target=target, port=port,
                    description=(
                        f"Service appears accessible without authentication. "
                        f"Matched: '{pattern}'"
                    ),
                    evidence=[pattern],
                ))
                break

        return findings or [Finding(
            plugin=self.meta.name,
            title=f"{self.meta.name} check complete",
            severity=FindingSeverity.INFO,
            target=target, port=port,
            description="Service check completed.",
            raw_output=output[:300],
        )]


class MySQLCheckPlugin(_NmapScriptPlugin):
    meta = PluginMeta(
        name="mysql_check",
        description="MySQL anonymous/empty-password check",
        triggers_on_ports=frozenset({3306}),
        requires_binary="nmap",
        default_timeout=60,
    )
    _port = 3306
    _scripts = "mysql-empty-password,mysql-info,mysql-databases"
    _anon_patterns = ["empty password", "anonymous access", "successfully logged"]
    _service_name = "mysql"


class MSSQLCheckPlugin(_NmapScriptPlugin):
    meta = PluginMeta(
        name="mssql_check",
        description="MSSQL information gathering",
        triggers_on_ports=frozenset({1433}),
        requires_binary="nmap",
        default_timeout=60,
    )
    _port = 1433
    _scripts = "ms-sql-info,ms-sql-empty-password,ms-sql-config"
    _anon_patterns = ["empty password", "login succeeded"]
    _service_name = "mssql"


class RedisCheckPlugin(_NmapScriptPlugin):
    meta = PluginMeta(
        name="redis_check",
        description="Redis unauthenticated access check",
        triggers_on_ports=frozenset({6379}),
        requires_binary="nmap",
        default_timeout=60,
    )
    _port = 6379
    _scripts = "redis-info"
    _anon_patterns = ["connected_clients", "redis_version", "used_memory"]
    _service_name = "redis"


class MongoCheckPlugin(_NmapScriptPlugin):
    meta = PluginMeta(
        name="mongo_check",
        description="MongoDB unauthenticated access check",
        triggers_on_ports=frozenset({27017}),
        requires_binary="nmap",
        default_timeout=60,
    )
    _port = 27017
    _scripts = "mongodb-info,mongodb-databases"
    _anon_patterns = ["databases", "totalsize", "mongodb version"]
    _service_name = "mongo"


class SnmpCheckPlugin(_NmapScriptPlugin):
    meta = PluginMeta(
        name="snmp_check",
        description="SNMP community string enumeration",
        triggers_on_ports=frozenset({161}),
        requires_binary="nmap",
        default_timeout=60,
    )
    _port = 161
    _scripts = "snmp-info,snmp-sysdescr"
    _anon_patterns = ["system description", "snmp sysdescr", "enterprise"]
    _service_name = "snmp"

    def _output_path(self, layout: OutputLayout) -> Path:
        # SNMP lives at recon/snmp/results.txt, not under db/
        return layout.snmp_result

    async def execute(
        self, task: TaskRecord, session: ScanSession
    ) -> list[Finding]:
        # SNMP is UDP — override base to add -sU
        target   = str(task.target)
        layout   = OutputLayout.from_session(session)
        out_file = self._output_path(layout)   # recon/snmp/results.txt

        stdout, stderr, _ = await self.run_subprocess([
            "nmap", "-sU", "-p", "161", "--script", self._scripts,
            target, "-oN", str(out_file),
        ], timeout=self.meta.default_timeout)

        output = stdout + stderr
        self.save_raw_output(output, session, out_file)
        return self._parse_service_output(output, target, task.port)


# ─── CVE Lookup ───────────────────────────────────────────────────────────────

class CveLookupPlugin(ReconPlugin):

    meta: ClassVar[PluginMeta] = PluginMeta(
        name="cve_lookup",
        description="CVE and exploit lookup via searchsploit",
        requires_binary=None,   # Falls back to curl if searchsploit absent
        default_timeout=30,
    )

    async def execute(
        self, task: TaskRecord, session: ScanSession
    ) -> list[Finding]:
        product = task.params.get("product", "")
        version = task.params.get("version", "")
        service = task.params.get("service", "")
        query   = f"{product} {version}".strip()

        if not query or query == " ":
            return []

        import shutil
        if shutil.which("searchsploit"):
            return await self._searchsploit(query, product, task.target, task.port, session)
        else:
            return await self._cve_api(product, version, task.target, task.port)

    @staticmethod
    def _cve_output_path(layout: OutputLayout, port: Optional[int], product: str) -> Path:
        """Route CVE output to the most contextually appropriate directory."""
        _DB_PORTS = {3306: "mysql", 1433: "mssql", 6379: "redis", 27017: "mongo"}
        if port == 22:
            return layout.ssh_cve_result
        if port in _DB_PORTS:
            return layout.db_cve_result(_DB_PORTS[port])
        # Generic fallback: recon/cve/port_{port}_{safe_product}.txt
        safe = re.sub(r"[^\w]", "_", product) or "unknown"
        return layout.cve_result(port or 0, safe)

    async def _searchsploit(
        self,
        query: str,
        product: str,
        target,
        port: Optional[int],
        session: ScanSession,
    ) -> list[Finding]:
        stdout, stderr, _ = await self.run_subprocess(
            ["searchsploit", "--colour", query],
            timeout=self.meta.default_timeout,
        )
        output = stdout

        # BEFORE: cve_{port}_{safe_product}.txt flat in session root
        # AFTER:  routed by port context:
        #   SSH (port 22)     → recon/ssh/cve_lookup.txt
        #   DB ports          → recon/db/{service}/cve_lookup.txt
        #   others            → recon/cve/port_{port}_{service}.txt
        layout   = OutputLayout.from_session(session)
        out_file = self._cve_output_path(layout, port, product)
        self.save_raw_output(output, session, out_file)

        if "No Results" in output or not output.strip():
            return []

        findings = []
        lines = [
            l for l in output.splitlines()
            if l.strip() and "---" not in l and "Path" not in l
            and "Exploit Title" not in l and "Shellcodes" not in l
        ]
        for line in lines[:10]:
            parts = re.split(r"\s{2,}", line.strip())
            title = parts[0] if parts else line[:80]
            path  = parts[-1] if len(parts) > 1 else ""

            severity = FindingSeverity.HIGH
            if "dos" in title.lower() or "denial" in title.lower():
                severity = FindingSeverity.MEDIUM
            if any(kw in title.lower() for kw in ["remote code", "rce", "command exec"]):
                severity = FindingSeverity.CRITICAL

            findings.append(Finding(
                plugin=self.meta.name,
                title=f"Exploit: {title[:80]}",
                severity=severity,
                target=str(target),
                port=port,
                description=f"Searchsploit match for '{query}': {title}",
                evidence=[f"Path: {path}" if path else ""],
                metadata={"query": query, "exploit_path": path},
            ))

        return findings

    async def _cve_api(
        self,
        product: str,
        version: str,
        target,
        port: Optional[int],
    ) -> list[Finding]:
        """Fallback: query circl.lu CVE API via curl."""
        import shutil
        if not shutil.which("curl"):
            return []

        search_term = f"{product} {version}".replace(" ", "+")
        stdout, _, _ = await self.run_subprocess([
            "curl", "-s", f"https://cve.circl.lu/api/search/{search_term}"
        ], timeout=15)

        try:
            data    = json.loads(stdout)
            results = data.get("results", [])[:5]
        except (json.JSONDecodeError, AttributeError):
            return []

        findings = []
        for cve in results:
            cve_id  = cve.get("id", "N/A")
            summary = cve.get("summary", "")[:200]
            cvss    = cve.get("cvss")

            severity = FindingSeverity.INFO
            if cvss:
                if float(cvss) >= 9.0:
                    severity = FindingSeverity.CRITICAL
                elif float(cvss) >= 7.0:
                    severity = FindingSeverity.HIGH
                elif float(cvss) >= 4.0:
                    severity = FindingSeverity.MEDIUM
                else:
                    severity = FindingSeverity.LOW

            findings.append(Finding(
                plugin=self.meta.name,
                title=f"{cve_id} (CVSS: {cvss})",
                severity=severity,
                target=str(target),
                port=port,
                description=summary,
                cve_ids=[cve_id],
                cvss=float(cvss) if cvss else None,
            ))

        return findings
