"""
plugins/httpx_probe.py — Live web server probing (httpx) + screenshots (gowitness).

Two plugins in one file because they are tightly coupled:
  - HttpxProbePlugin: probes hostnames for live HTTP/S services
  - GoWitnessPlugin:  takes screenshots of confirmed live URLs

HttpxProbePlugin updates session.subdomains[*].is_live so the report
can show exactly which subdomains are reachable. GoWitnessPlugin stores
screenshot paths in session.subdomains[*].screenshot_path.

Install:
    go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
    go install github.com/sensepost/gowitness@latest
"""

from __future__ import annotations

import json
import logging
import shutil
from pathlib import Path
from typing import ClassVar

from ..core.models import Finding, FindingSeverity, ScanSession, SubdomainInfo, TaskRecord
from ..core.output_layout import OutputLayout
from ..core.plugin_base import PluginMeta, ReconPlugin

logger = logging.getLogger("z3r0.httpx")


class HttpxProbePlugin(ReconPlugin):

    meta: ClassVar[PluginMeta] = PluginMeta(
        name="httpx_probe",
        description="Probe live web servers on subdomains via httpx",
        always_run=False,
        requires_binary="httpx",
        default_timeout=300,
    )

    async def execute(
        self, task: TaskRecord, session: ScanSession
    ) -> list[Finding]:
        layout = OutputLayout.from_session(session)

        # Build the input: either a single hostname or write the full subdomain
        # list to a file for batch probing (preferred — one httpx call vs N)
        if session.subdomains:
            input_file = layout.httpx_dir / "probe_input.txt"
            hostnames  = [s.hostname for s in session.subdomains]
            input_file.write_text("\n".join(hostnames), encoding="utf-8")
            targets = ["-l", str(input_file)]
        else:
            hostname = task.params.get("hostname", str(task.target))
            targets  = ["-u", hostname]

        out_file = layout.httpx_result

        cmd = [
            "httpx",
            *targets,
            "-json",
            "-o", str(out_file),
            "-silent",
            "-follow-redirects",
            "-status-code",
            "-title",
            "-tech-detect",
            "-threads", "50",
            "-timeout", "10",
        ]

        try:
            stdout, stderr, rc = await self.run_subprocess(
                cmd, timeout=self.meta.default_timeout
            )
        except TimeoutError:
            return [Finding(
                plugin=self.meta.name,
                title="httpx timed out",
                severity=FindingSeverity.INFO,
                target=str(task.target), port=None,
                description="httpx exceeded timeout — partial results may exist.",
            )]
        except Exception as e:
            return [Finding(
                plugin=self.meta.name,
                title=f"httpx error: {e}",
                severity=FindingSeverity.INFO,
                target=str(task.target), port=None,
                description=str(e),
            )]

        return self._parse_httpx_json(out_file, session)

    def _parse_httpx_json(
        self, out_file: Path, session: ScanSession
    ) -> list[Finding]:
        findings: list[Finding] = []
        live_hosts: list[dict]  = []

        # Build a fast lookup for session.subdomains
        sub_map = {s.hostname: s for s in session.subdomains}

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

            url        = entry.get("url", "")
            hostname   = entry.get("input", url)
            status     = entry.get("status-code", 0)
            title      = entry.get("title", "")
            tech       = entry.get("technologies", []) or []
            final_url  = entry.get("final-url", url)

            live_hosts.append({
                "url": url, "hostname": hostname,
                "status": status, "title": title,
                "tech": tech, "final_url": final_url,
            })

            # Update the SubdomainInfo in session
            if hostname in sub_map:
                sub_map[hostname].is_live    = True
                sub_map[hostname].http_status = status
                sub_map[hostname].technologies = tech

            findings.append(Finding(
                plugin=self.meta.name,
                title=f"Live: {hostname} [{status}] {title}",
                severity=FindingSeverity.INFO,
                target=hostname,
                port=None,
                description=(
                    f"URL: {url}\n"
                    f"Status: {status}\n"
                    f"Title: {title}\n"
                    f"Technologies: {', '.join(tech) if tech else 'unknown'}"
                ),
                metadata={
                    "url": url, "status": status,
                    "title": title, "tech": tech,
                    "final_url": final_url,
                },
            ))

        if not findings:
            return [Finding(
                plugin=self.meta.name,
                title="httpx: no live hosts found",
                severity=FindingSeverity.INFO,
                target="all subdomains", port=None,
                description="httpx returned no live web servers.",
            )]

        # Summary finding
        findings.insert(0, Finding(
            plugin=self.meta.name,
            title=f"httpx: {len(live_hosts)} live web servers",
            severity=FindingSeverity.INFO,
            target="subdomains", port=None,
            description="\n".join(f"{h['url']} [{h['status']}]" for h in live_hosts),
            metadata={"live_count": len(live_hosts)},
        ))

        return findings


class GoWitnessPlugin(ReconPlugin):

    meta: ClassVar[PluginMeta] = PluginMeta(
        name="gowitness",
        description="Web screenshot capture via gowitness",
        always_run=False,
        requires_binary="gowitness",
        default_timeout=300,
    )

    async def execute(
        self, task: TaskRecord, session: ScanSession
    ) -> list[Finding]:
        layout    = OutputLayout.from_session(session)
        shot_dir  = layout.screenshots_dir

        # Build target list from live subdomains if available, else single host
        live_subs = session.live_subdomains
        if live_subs:
            url_file = layout.httpx_dir / "live_urls.txt"
            urls     = []
            for sub in live_subs:
                scheme = "https" if (sub.http_status and sub.http_status < 400) else "http"
                urls.append(f"{scheme}://{sub.hostname}")
            url_file.write_text("\n".join(urls), encoding="utf-8")
            targets = ["file", str(url_file)]
        else:
            hostname = task.params.get("hostname", str(task.target))
            targets  = ["single", f"http://{hostname}"]

        db_file = shot_dir / "gowitness.sqlite3"

        cmd = [
            "gowitness", *targets,
            "--screenshot-path", str(shot_dir),
            "--db-path", str(db_file),
            "--timeout", "10",
            "--threads", "4",
        ]

        try:
            stdout, stderr, rc = await self.run_subprocess(
                cmd, timeout=self.meta.default_timeout
            )
        except TimeoutError:
            return [Finding(
                plugin=self.meta.name,
                title="gowitness timed out",
                severity=FindingSeverity.INFO,
                target=str(task.target), port=None,
                description="gowitness exceeded timeout.",
            )]
        except Exception as e:
            return [Finding(
                plugin=self.meta.name,
                title=f"gowitness error: {e}",
                severity=FindingSeverity.INFO,
                target=str(task.target), port=None,
                description=str(e),
            )]

        # Count screenshots
        screenshots = list(shot_dir.glob("*.png")) + list(shot_dir.glob("*.jpg"))

        # Link screenshot paths back to subdomains
        sub_map = {s.hostname: s for s in session.subdomains}
        for shot in screenshots:
            # gowitness names files as sanitized URL — best-effort match
            stem = shot.stem.lower()
            for hostname, sub in sub_map.items():
                if hostname.replace(".", "_") in stem or stem in hostname:
                    sub.screenshot_path = str(shot)
                    break

        return [Finding(
            plugin=self.meta.name,
            title=f"gowitness: {len(screenshots)} screenshots taken",
            severity=FindingSeverity.INFO,
            target=str(task.target), port=None,
            description=f"Screenshots saved to: {shot_dir}",
            metadata={"screenshot_dir": str(shot_dir), "count": len(screenshots)},
        )]
