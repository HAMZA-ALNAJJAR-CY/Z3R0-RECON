"""
plugins/cloud_enum.py — Cloud storage enumeration (AWS S3, Azure, GCP).

Checks for publicly accessible cloud storage buckets derived from
common permutations of the target domain name. No credentials needed —
these tests only check for misconfigured public access.

Techniques:
  - AWS S3: s3scanner CLI + direct HEAD requests
  - Azure:  Storage accounts and app service hostnames
  - GCP:    Cloud Storage bucket name permutations

Install:
    pip install s3scanner aiohttp
    # or: go install github.com/sa7mon/s3scanner@latest

Note: Only tests for PUBLIC access. Does not attempt authentication or
exploit any access — purely informational enumeration.
"""

from __future__ import annotations

import logging
import re
import shutil
from pathlib import Path
from typing import ClassVar

from ..core.models import Finding, FindingSeverity, ScanSession, TaskRecord
from ..core.output_layout import OutputLayout
from ..core.plugin_base import PluginMeta, ReconPlugin

logger = logging.getLogger("z3r0.cloud_enum")


def _domain_permutations(domain: str) -> list[str]:
    """
    Generate common bucket name permutations for a domain.
    e.g. example.com → ["example", "example-dev", "example-backup", ...]
    """
    base = domain.split(".")[0].lower()
    suffixes = [
        "", "-dev", "-staging", "-prod", "-production", "-backup", "-data",
        "-assets", "-static", "-media", "-files", "-uploads", "-logs",
        "-archive", "-test", "-uat", "-api", "-internal", "-private",
        "-public", "-web", "-app", "-cdn", "-images", "-docs",
    ]
    prefixes = ["", "dev-", "staging-", "prod-", "backup-", "data-"]
    perms = set()
    for prefix in prefixes:
        for suffix in suffixes:
            name = f"{prefix}{base}{suffix}"
            if re.match(r"^[a-z0-9][a-z0-9\-]{1,61}[a-z0-9]$", name):
                perms.add(name)
    return sorted(perms)


class CloudEnumPlugin(ReconPlugin):

    meta: ClassVar[PluginMeta] = PluginMeta(
        name="cloud_enum",
        description="Cloud storage enumeration: AWS S3, Azure Blob, GCP Storage",
        always_run=False,
        requires_binary=None,
        default_timeout=300,
    )

    async def execute(
        self, task: TaskRecord, session: ScanSession
    ) -> list[Finding]:
        try:
            import aiohttp
        except ImportError:
            return [Finding(
                plugin=self.meta.name,
                title="aiohttp not installed",
                severity=FindingSeverity.INFO,
                target=str(task.target), port=None,
                description="Install aiohttp: pip install aiohttp",
            )]

        domain = str(task.target)
        layout = OutputLayout.from_session(session)
        perms  = _domain_permutations(domain)
        findings: list[Finding] = []

        logger.info(f"cloud_enum: testing {len(perms)} name permutations for {domain}")

        async with aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=10),
            connector=aiohttp.TCPConnector(limit=50),
        ) as http:
            # Run all three cloud providers concurrently
            import asyncio
            s3_results, az_results, gcp_results = await asyncio.gather(
                self._check_s3(http, perms, domain, layout),
                self._check_azure(http, perms, domain, layout),
                self._check_gcp(http, perms, domain, layout),
                return_exceptions=True,
            )

        for result in [s3_results, az_results, gcp_results]:
            if isinstance(result, list):
                findings.extend(result)
            elif isinstance(result, Exception):
                logger.error(f"cloud_enum error: {result}")

        if not findings:
            findings.append(Finding(
                plugin=self.meta.name,
                title="cloud_enum: no public cloud storage found",
                severity=FindingSeverity.INFO,
                target=domain, port=None,
                description=(
                    f"Tested {len(perms)} name permutations across "
                    "AWS S3, Azure Blob, and GCP Storage. No publicly "
                    "accessible buckets found."
                ),
            ))

        return findings

    # ── AWS S3 ────────────────────────────────────────────────────────────────

    async def _check_s3(
        self, http, perms: list[str], domain: str, layout: OutputLayout
    ) -> list[Finding]:
        # Use s3scanner if available for thorough checking, else HTTP probing
        if shutil.which("s3scanner"):
            return await self._s3scanner(perms, domain, layout)
        return await self._s3_http_check(http, perms, domain, layout)

    async def _s3_http_check(
        self, http, perms: list[str], domain: str, layout: OutputLayout
    ) -> list[Finding]:
        findings: list[Finding] = []
        open_buckets: list[str] = []

        for name in perms:
            url = f"https://{name}.s3.amazonaws.com/"
            try:
                async with http.head(url, allow_redirects=True) as resp:
                    if resp.status == 200:
                        open_buckets.append(name)
                        findings.append(Finding(
                            plugin=self.meta.name,
                            title=f"PUBLIC S3 bucket: {name}",
                            severity=FindingSeverity.HIGH,
                            target=domain, port=None,
                            description=(
                                f"S3 bucket '{name}' is publicly accessible.\n"
                                f"URL: {url}\n"
                                "This may expose sensitive files. Verify permissions."
                            ),
                            evidence=[f"HTTP 200: {url}"],
                            metadata={"bucket": name, "url": url, "provider": "aws"},
                        ))
                    elif resp.status == 403:
                        # Bucket exists but access is denied — still valuable intel
                        findings.append(Finding(
                            plugin=self.meta.name,
                            title=f"S3 bucket exists (access denied): {name}",
                            severity=FindingSeverity.LOW,
                            target=domain, port=None,
                            description=(
                                f"S3 bucket '{name}' exists but returned HTTP 403. "
                                "Bucket is not publicly readable. Worth noting for "
                                "further targeted testing."
                            ),
                            evidence=[f"HTTP 403: {url}"],
                            metadata={"bucket": name, "url": url, "provider": "aws"},
                        ))
            except Exception:
                continue

        if open_buckets:
            layout.s3_result.write_text("\n".join(open_buckets), encoding="utf-8")

        return findings

    async def _s3scanner(
        self, perms: list[str], domain: str, layout: OutputLayout
    ) -> list[Finding]:
        # Write bucket names to file for s3scanner batch mode
        names_file = layout.cloud_dir / "s3_names.txt"
        names_file.write_text("\n".join(perms), encoding="utf-8")

        try:
            stdout, stderr, rc = await self.run_subprocess([
                "s3scanner", "scan",
                "--buckets-file", str(names_file),
                "--out-file", str(layout.s3_result),
            ], timeout=120)
        except Exception as e:
            logger.warning(f"s3scanner failed: {e}")
            return []

        findings: list[Finding] = []
        try:
            content = layout.s3_result.read_text(encoding="utf-8")
            for line in content.splitlines():
                if "open" in line.lower() or "public" in line.lower():
                    findings.append(Finding(
                        plugin=self.meta.name,
                        title=f"s3scanner: public bucket found — {line[:80]}",
                        severity=FindingSeverity.HIGH,
                        target=domain, port=None,
                        description=line,
                        metadata={"provider": "aws", "source": "s3scanner"},
                    ))
        except FileNotFoundError:
            pass

        return findings

    # ── Azure ─────────────────────────────────────────────────────────────────

    async def _check_azure(
        self, http, perms: list[str], domain: str, layout: OutputLayout
    ) -> list[Finding]:
        findings: list[Finding] = []
        found: list[str] = []

        azure_templates = [
            "https://{name}.blob.core.windows.net/",
            "https://{name}.file.core.windows.net/",
            "https://{name}.table.core.windows.net/",
            "https://{name}.azurewebsites.net/",
        ]

        for name in perms[:30]:  # Limit to avoid rate limiting
            for template in azure_templates:
                url = template.format(name=name)
                try:
                    async with http.head(url, allow_redirects=True) as resp:
                        if resp.status in {200, 400, 409}:
                            # 400/409 = service exists, access issues
                            severity = (
                                FindingSeverity.HIGH if resp.status == 200
                                else FindingSeverity.LOW
                            )
                            title = (
                                f"PUBLIC Azure storage: {name}"
                                if resp.status == 200
                                else f"Azure storage exists: {name}"
                            )
                            found.append(url)
                            findings.append(Finding(
                                plugin=self.meta.name,
                                title=title,
                                severity=severity,
                                target=domain, port=None,
                                description=(
                                    f"Azure resource detected at {url}\n"
                                    f"HTTP Status: {resp.status}"
                                ),
                                evidence=[f"HTTP {resp.status}: {url}"],
                                metadata={
                                    "url": url, "provider": "azure",
                                    "resource_name": name,
                                },
                            ))
                except Exception:
                    continue

        if found:
            layout.azure_result.write_text("\n".join(found), encoding="utf-8")

        return findings

    # ── GCP ───────────────────────────────────────────────────────────────────

    async def _check_gcp(
        self, http, perms: list[str], domain: str, layout: OutputLayout
    ) -> list[Finding]:
        findings: list[Finding] = []
        found: list[str] = []

        for name in perms[:30]:
            url = f"https://storage.googleapis.com/{name}/"
            try:
                async with http.head(url, allow_redirects=True) as resp:
                    if resp.status == 200:
                        found.append(url)
                        findings.append(Finding(
                            plugin=self.meta.name,
                            title=f"PUBLIC GCP bucket: {name}",
                            severity=FindingSeverity.HIGH,
                            target=domain, port=None,
                            description=(
                                f"GCP Storage bucket '{name}' is publicly accessible.\n"
                                f"URL: {url}"
                            ),
                            evidence=[f"HTTP 200: {url}"],
                            metadata={"bucket": name, "url": url, "provider": "gcp"},
                        ))
                    elif resp.status == 403:
                        findings.append(Finding(
                            plugin=self.meta.name,
                            title=f"GCP bucket exists (access denied): {name}",
                            severity=FindingSeverity.LOW,
                            target=domain, port=None,
                            description=f"GCP bucket '{name}' exists but is not public.",
                            metadata={"bucket": name, "provider": "gcp"},
                        ))
            except Exception:
                continue

        if found:
            layout.gcp_result.write_text("\n".join(found), encoding="utf-8")

        return findings
