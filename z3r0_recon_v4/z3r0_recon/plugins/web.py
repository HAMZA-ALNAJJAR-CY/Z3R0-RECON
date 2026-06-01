"""
plugins/web.py — Web-targeting plugins: Nikto, Gobuster, FFUF, WhatWeb, WAFw00f.

All five share the same pattern:
  - Accept URL from task.params["url"]
  - Run async subprocess
  - Parse output into Finding objects
  - Store raw output as audit artifact

Key differences from the original:
  - Findings are returned as structured objects, not flat text files
  - Gobuster and FFUF findings include HTTP status codes and sizes
  - WhatWeb findings extract identified technologies
  - WAFw00f findings include detected WAF product
  - All plugins record raw output in Finding.raw_output for manual review
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import ClassVar, Optional

from ..core.models import Finding, FindingSeverity, ScanSession, TaskRecord
from ..core.output_layout import OutputLayout
from ..core.plugin_base import PluginMeta, ReconPlugin

# ─── Wordlist Resolver ────────────────────────────────────────────────────────

_WORDLIST_CANDIDATES = [
    Path("/opt/SecLists/Discovery/Web-Content/common.txt"),
    Path("/usr/share/seclists/Discovery/Web-Content/common.txt"),
    Path("/usr/share/wordlists/dirb/common.txt"),
    Path("/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt"),
]

def _find_wordlist() -> Optional[str]:
    for path in _WORDLIST_CANDIDATES:
        if path.exists():
            return str(path)
    return None


# ─── Nikto ────────────────────────────────────────────────────────────────────

class NiktoPlugin(ReconPlugin):

    meta: ClassVar[PluginMeta] = PluginMeta(
        name="nikto",
        description="Web server vulnerability scanning via Nikto",
        triggers_on_ports=frozenset({80, 443, 8080, 8443, 8000, 8008, 8888, 3000, 5000}),
        requires_binary="nikto",
        default_timeout=300,
    )

    async def execute(
        self, task: TaskRecord, session: ScanSession
    ) -> list[Finding]:
        url = task.params.get("url", "")
        if not url:
            return []

        # BEFORE: nikto_{mangled_url}.txt flat in session root
        # AFTER:  recon/web/{port}/nikto/results.txt
        port     = task.port or 80
        layout   = OutputLayout.from_session(session)
        out_file = layout.nikto_result(port)   # parent dir already created by layout

        cmd = [
            "nikto", "-h", url,
            "-output", str(out_file),
            "-Format", "txt",
            "-nointeractive",
        ]

        try:
            stdout, stderr, _ = await self.run_subprocess(cmd, timeout=self.meta.default_timeout)
            output = stdout + stderr
        except TimeoutError:
            return [Finding(
                plugin=self.meta.name,
                title="Nikto timed out",
                severity=FindingSeverity.INFO,
                target=url, port=task.port,
                description="Nikto exceeded timeout — partial results may exist in output dir",
            )]

        self.save_raw_output(output, session, out_file)
        return self._parse_nikto_output(output, url, task.port)

    def _parse_nikto_output(
        self, output: str, url: str, port: Optional[int]
    ) -> list[Finding]:
        findings = []
        # Nikto output lines starting with "+ " are findings
        for line in output.splitlines():
            if line.startswith("+ ") and len(line) > 5:
                content = line[2:].strip()
                # Skip header/footer lines
                if any(skip in content for skip in [
                    "Target IP:", "Target Hostname:", "Target Port:",
                    "Start Time:", "End Time:", "1 host(s) tested",
                ]):
                    continue

                # Crude severity heuristic from nikto content
                severity = FindingSeverity.LOW
                if any(kw in content.lower() for kw in [
                    "default credentials", "admin", "sql", "injection",
                    "xss", "rce", "remote code", "upload", "critical",
                ]):
                    severity = FindingSeverity.HIGH
                elif any(kw in content.lower() for kw in [
                    "outdated", "vulnerability", "cve-", "osvdb-",
                    "server leaks", "password", "exposed",
                ]):
                    severity = FindingSeverity.MEDIUM

                findings.append(Finding(
                    plugin=self.meta.name,
                    title=content[:100],
                    severity=severity,
                    target=url,
                    port=port,
                    description=content,
                    raw_output=line,
                    cve_ids=re.findall(r"CVE-\d{4}-\d+", content, re.IGNORECASE),
                ))

        if not findings:
            findings.append(Finding(
                plugin=self.meta.name,
                title="Nikto scan complete — no notable findings",
                severity=FindingSeverity.INFO,
                target=url, port=port,
                description="Nikto completed without flagging notable vulnerabilities.",
            ))
        return findings


# ─── Gobuster ─────────────────────────────────────────────────────────────────

class GobusterPlugin(ReconPlugin):

    meta: ClassVar[PluginMeta] = PluginMeta(
        name="gobuster",
        description="Directory and file brute-forcing via Gobuster",
        triggers_on_ports=frozenset({80, 443, 8080, 8443, 8000, 8008, 8888, 3000, 5000}),
        requires_binary="gobuster",
        default_timeout=300,
    )

    async def execute(
        self, task: TaskRecord, session: ScanSession
    ) -> list[Finding]:
        url = task.params.get("url", "")
        if not url:
            return []

        wl = task.params.get("wordlist") or _find_wordlist()
        if not wl:
            return [Finding(
                plugin=self.meta.name,
                title="Gobuster skipped — no wordlist found",
                severity=FindingSeverity.INFO,
                target=url, port=task.port,
                description=(
                    "Install seclists (sudo apt install seclists) or "
                    "provide --wordlist path"
                ),
            )]

        # BEFORE: gobuster_{mangled_url}.txt flat in session root
        # AFTER:  recon/web/{port}/gobuster/results.txt
        port     = task.port or 80
        layout   = OutputLayout.from_session(session)
        out_file = layout.gobuster_result(port)
        threads  = str(task.params.get("threads", 40))
        extensions = task.params.get("extensions", "php,html,txt,js,json,asp,aspx,bak,zip")

        cmd = [
            "gobuster", "dir",
            "-u", url,
            "-w", wl,
            "-x", extensions,
            "-t", threads,
            "-o", str(out_file),
            "--no-error", "-q",
        ]

        try:
            stdout, stderr, _ = await self.run_subprocess(cmd, timeout=self.meta.default_timeout)
        except TimeoutError:
            return [Finding(
                plugin=self.meta.name,
                title="Gobuster timed out",
                severity=FindingSeverity.INFO,
                target=url, port=task.port,
                description="Gobuster exceeded timeout — partial results in output dir",
            )]

        self.save_raw_output(stdout, session, out_file)
        return self._parse_gobuster_output(stdout, url, task.port)

    def _parse_gobuster_output(
        self, output: str, url: str, port: Optional[int]
    ) -> list[Finding]:
        findings = []
        # Gobuster lines: "/path  (Status: 200) [Size: 1234]"
        pattern = re.compile(r"^(/\S*)\s+\(Status:\s*(\d+)\)(?:\s+\[Size:\s*(\d+)\])?")

        interesting_statuses = {200, 204, 301, 302, 307, 401, 403}
        high_value_paths = re.compile(
            r"(admin|backup|config|\.git|\.env|\.htaccess|wp-admin|"
            r"phpmyadmin|manager|console|dashboard|api|swagger|graphql|"
            r"\.bak|\.sql|\.zip|\.tar|upload|secret)",
            re.IGNORECASE,
        )

        for line in output.splitlines():
            m = pattern.match(line.strip())
            if not m:
                continue
            path, status, size = m.group(1), int(m.group(2)), m.group(3)
            if int(status) not in interesting_statuses:
                continue

            severity = FindingSeverity.INFO
            if high_value_paths.search(path):
                severity = FindingSeverity.MEDIUM
                if status in {200, 204}:
                    severity = FindingSeverity.HIGH

            findings.append(Finding(
                plugin=self.meta.name,
                title=f"Found: {path} [{status}]",
                severity=severity,
                target=url,
                port=port,
                description=f"HTTP {status} response for {url}{path}" + (
                    f" (size: {size} bytes)" if size else ""
                ),
                evidence=[line.strip()],
                metadata={"path": path, "status": status, "size": size},
            ))

        if not findings:
            findings.append(Finding(
                plugin=self.meta.name,
                title="Gobuster: no interesting paths found",
                severity=FindingSeverity.INFO,
                target=url, port=port,
                description="Directory brute-force completed with no notable results.",
            ))
        return findings


# ─── FFUF ─────────────────────────────────────────────────────────────────────

class FfufPlugin(ReconPlugin):

    meta: ClassVar[PluginMeta] = PluginMeta(
        name="ffuf",
        description="Fast web fuzzing via FFUF",
        triggers_on_ports=frozenset({80, 443, 8080, 8443, 8000, 8008, 8888, 3000, 5000}),
        requires_binary="ffuf",
        default_timeout=300,
    )

    async def execute(
        self, task: TaskRecord, session: ScanSession
    ) -> list[Finding]:
        url = task.params.get("url", "")
        if not url:
            return []

        wl = task.params.get("wordlist") or _find_wordlist()
        if not wl:
            return []

        # BEFORE: ffuf_{mangled_url}.json flat in session root
        # AFTER:  recon/web/{port}/ffuf/results.json
        # Critical: ffuf writes its own JSON file via -o. The directory
        # must exist before the subprocess runs — layout._ensure() handles this.
        port     = task.port or 80
        layout   = OutputLayout.from_session(session)
        out_file = layout.ffuf_result(port)

        cmd = [
            "ffuf",
            "-u", f"{url}/FUZZ",
            "-w", wl,
            "-mc", "200,201,204,301,302,307,401,403",
            "-t", str(task.params.get("threads", 40)),
            "-o", str(out_file),
            "-of", "json",
            "-ic", "-s",
        ]

        try:
            stdout, stderr, _ = await self.run_subprocess(cmd, timeout=self.meta.default_timeout)
        except TimeoutError:
            return []

        return self._parse_ffuf_json(out_file, url, task.port)

    def _parse_ffuf_json(
        self, json_path: "str | Path", url: str, port: Optional[int]
    ) -> list[Finding]:
        try:
            with open(json_path) as f:
                data = json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            return []

        findings = []
        results = data.get("results", [])

        for result in results:
            path   = result.get("input", {}).get("FUZZ", "")
            status = result.get("status", 0)
            size   = result.get("length", 0)
            words  = result.get("words", 0)

            findings.append(Finding(
                plugin=self.meta.name,
                title=f"FFUF: {path} [{status}]",
                severity=FindingSeverity.INFO,
                target=url,
                port=port,
                description=f"HTTP {status} | size: {size} | words: {words}",
                metadata={"path": path, "status": status, "size": size},
            ))

        return findings


# ─── WhatWeb ──────────────────────────────────────────────────────────────────

class WhatWebPlugin(ReconPlugin):

    meta: ClassVar[PluginMeta] = PluginMeta(
        name="whatweb",
        description="Web technology fingerprinting via WhatWeb",
        triggers_on_ports=frozenset({80, 443, 8080, 8443, 8000, 8008, 8888, 3000, 5000}),
        requires_binary="whatweb",
        default_timeout=60,
    )

    async def execute(
        self, task: TaskRecord, session: ScanSession
    ) -> list[Finding]:
        url = task.params.get("url", "")
        if not url:
            return []

        # BEFORE: whatweb_{mangled_url}.txt flat in session root
        # AFTER:  recon/web/{port}/whatweb/results.txt
        # WhatWeb writes its own log file via --log-brief. Directory must exist first.
        port     = task.port or 80
        layout   = OutputLayout.from_session(session)
        out_file = layout.whatweb_result(port)

        cmd = ["whatweb", "-a", "3", "--log-brief", str(out_file), url]
        try:
            stdout, stderr, _ = await self.run_subprocess(cmd, timeout=self.meta.default_timeout)
            output = stdout + stderr
        except TimeoutError:
            return []

        return self._parse_whatweb_output(output + self._read_file(out_file), url, task.port)

    def _read_file(self, path: "str | Path") -> str:
        try:
            with open(path) as f:
                return f.read()
        except FileNotFoundError:
            return ""

    def _parse_whatweb_output(
        self, output: str, url: str, port: Optional[int]
    ) -> list[Finding]:
        findings = []
        # WhatWeb brief format: "http://target [200 OK] Technology[version], ..."
        technologies = re.findall(r"([A-Za-z\-\.0-9]+)\[([^\]]+)\]", output)
        if technologies:
            tech_list = [f"{name}: {ver}" for name, ver in technologies if name not in
                         ("OK", "http", "https", "301", "302", "200", "403")]
            if tech_list:
                findings.append(Finding(
                    plugin=self.meta.name,
                    title=f"Technologies identified on {url}",
                    severity=FindingSeverity.INFO,
                    target=url,
                    port=port,
                    description="Identified web technologies:\n" + "\n".join(tech_list),
                    evidence=tech_list,
                    metadata={"technologies": dict(technologies)},
                ))

        # Flag outdated or notable technologies
        old_tech_patterns = re.compile(
            r"(php[/\s]([45]\.|7\.[01234]\.|8\.0\.))|"
            r"(apache[/\s]2\.[01234]\.)|"
            r"(nginx[/\s]1\.(1[0-8]|[0-9])\.)|"
            r"(wordpress[/\s][123456]\.|drupal[/\s][67]\.|joomla)",
            re.IGNORECASE,
        )
        if old_tech_patterns.search(output):
            findings.append(Finding(
                plugin=self.meta.name,
                title="Potentially outdated web technology detected",
                severity=FindingSeverity.MEDIUM,
                target=url,
                port=port,
                description="WhatWeb identified web technology that may be outdated. Review version info.",
                raw_output=output[:500],
            ))

        return findings


# ─── WAFw00f ──────────────────────────────────────────────────────────────────

class Wafw00fPlugin(ReconPlugin):

    meta: ClassVar[PluginMeta] = PluginMeta(
        name="wafw00f",
        description="WAF detection via WAFw00f",
        triggers_on_ports=frozenset({80, 443, 8080, 8443, 8000, 8008, 8888, 3000, 5000}),
        requires_binary="wafw00f",
        default_timeout=60,
    )

    async def execute(
        self, task: TaskRecord, session: ScanSession
    ) -> list[Finding]:
        url = task.params.get("url", "")
        if not url:
            return []

        try:
            stdout, stderr, _ = await self.run_subprocess(
                ["wafw00f", url], timeout=self.meta.default_timeout
            )
            output = stdout + stderr
        except TimeoutError:
            return []

        # BEFORE: waf_{mangled_url}.txt flat in session root
        # AFTER:  recon/web/{port}/wafw00f/results.txt
        port   = task.port or 80
        layout = OutputLayout.from_session(session)
        self.save_raw_output(output, session, layout.wafw00f_result(port))
        return self._parse_wafw00f_output(output, url, task.port)

    def _parse_wafw00f_output(
        self, output: str, url: str, port: Optional[int]
    ) -> list[Finding]:
        # Check for detected WAF
        detected = re.search(
            r"is behind (?:a |an )?(.+?) WAF", output, re.IGNORECASE
        )
        if detected:
            waf_name = detected.group(1).strip()
            return [Finding(
                plugin=self.meta.name,
                title=f"WAF detected: {waf_name}",
                severity=FindingSeverity.INFO,
                target=url,
                port=port,
                description=(
                    f"Web Application Firewall detected: {waf_name}. "
                    "Web application scanning may produce false negatives or be blocked."
                ),
                metadata={"waf": waf_name},
            )]

        no_waf = re.search(r"No WAF detected", output, re.IGNORECASE)
        if no_waf:
            return [Finding(
                plugin=self.meta.name,
                title="No WAF detected",
                severity=FindingSeverity.INFO,
                target=url,
                port=port,
                description="WAFw00f did not detect a Web Application Firewall.",
            )]

        return []
