"""
plugins/osint_collector.py — Passive OSINT data collection.

Queries external APIs for historical intelligence about a target:
  - AlienVault OTX: domain pulses, passive DNS, URL list
  - URLScan.io: historical scans, discovered subdomains + endpoints
  - Shodan: open ports, service banners, CVEs (API key required)

All API calls are made with aiohttp for true async I/O — no blocking.
API keys are read from session.config (populated from config.yaml).

Install:
    pip install aiohttp
"""

from __future__ import annotations

import json
import logging
from typing import ClassVar, Optional

from ..core.models import Finding, FindingSeverity, ScanSession, SubdomainInfo, TaskRecord
from ..core.output_layout import OutputLayout
from ..core.plugin_base import PluginMeta, ReconPlugin

logger = logging.getLogger("z3r0.osint")


class OsintCollectorPlugin(ReconPlugin):

    meta: ClassVar[PluginMeta] = PluginMeta(
        name="osint_collector",
        description="Passive OSINT: AlienVault OTX, URLScan.io, Shodan",
        always_run=False,
        requires_binary=None,
        default_timeout=120,
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

        domain   = str(task.target)
        layout   = OutputLayout.from_session(session)
        config   = session.config
        findings: list[Finding] = []

        async with aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=30),
            headers={"User-Agent": "Z3R0-Recon/2.0 Security Research"},
        ) as http:

            # ── OTX ───────────────────────────────────────────────────────────
            otx_findings = await self._query_otx(http, domain, layout, config.otx_key)
            findings.extend(otx_findings)

            # Add discovered subdomains to session
            for f in otx_findings:
                for hostname in f.metadata.get("subdomains", []):
                    if not any(s.hostname == hostname for s in session.subdomains):
                        session.subdomains.append(SubdomainInfo(
                            hostname=hostname, source="otx"
                        ))

            # ── URLScan ───────────────────────────────────────────────────────
            urlscan_findings = await self._query_urlscan(http, domain, layout)
            findings.extend(urlscan_findings)

            for f in urlscan_findings:
                for hostname in f.metadata.get("subdomains", []):
                    if not any(s.hostname == hostname for s in session.subdomains):
                        session.subdomains.append(SubdomainInfo(
                            hostname=hostname, source="urlscan"
                        ))

            # ── Shodan ────────────────────────────────────────────────────────
            if config.shodan_key:
                shodan_findings = await self._query_shodan(
                    http, domain, layout, config.shodan_key
                )
                findings.extend(shodan_findings)
            else:
                logger.info("shodan_key not set — skipping Shodan OSINT")

        return findings if findings else [Finding(
            plugin=self.meta.name,
            title="OSINT: no results",
            severity=FindingSeverity.INFO,
            target=domain, port=None,
            description="All OSINT sources returned no results.",
        )]

    # ── AlienVault OTX ────────────────────────────────────────────────────────

    async def _query_otx(
        self,
        http,
        domain: str,
        layout: OutputLayout,
        api_key: Optional[str],
    ) -> list[Finding]:
        headers = {"X-OTX-API-KEY": api_key} if api_key else {}
        base    = "https://otx.alienvault.com/api/v1/indicators/domain"
        findings: list[Finding] = []

        # Passive DNS
        try:
            async with http.get(
                f"{base}/{domain}/passive_dns", headers=headers
            ) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    passive_dns = data.get("passive_dns", [])
                    subdomains  = list({
                        entry.get("hostname", "").lower()
                        for entry in passive_dns
                        if domain in entry.get("hostname", "")
                        and entry.get("hostname", "") != domain
                    })

                    layout.otx_result.write_text(
                        json.dumps(data, indent=2), encoding="utf-8"
                    )

                    if subdomains:
                        findings.append(Finding(
                            plugin=self.meta.name,
                            title=f"OTX passive DNS: {len(subdomains)} subdomains",
                            severity=FindingSeverity.INFO,
                            target=domain, port=None,
                            description="\n".join(sorted(subdomains)[:20]),
                            metadata={"source": "otx", "subdomains": subdomains},
                        ))
        except Exception as e:
            logger.warning(f"OTX query failed: {e}")

        # Pulse count (threat intelligence context)
        try:
            async with http.get(
                f"{base}/{domain}/general", headers=headers
            ) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    pulse_count = data.get("pulse_info", {}).get("count", 0)
                    if pulse_count > 0:
                        findings.append(Finding(
                            plugin=self.meta.name,
                            title=f"OTX: domain appears in {pulse_count} threat pulses",
                            severity=FindingSeverity.MEDIUM if pulse_count > 5 else FindingSeverity.LOW,
                            target=domain, port=None,
                            description=(
                                f"AlienVault OTX reports {pulse_count} threat intelligence "
                                f"pulses associated with {domain}. This may indicate the "
                                "domain has been involved in malicious activity, is a "
                                "known attack target, or has been flagged by researchers."
                            ),
                            metadata={"pulse_count": pulse_count, "source": "otx"},
                        ))
        except Exception as e:
            logger.warning(f"OTX general query failed: {e}")

        return findings

    # ── URLScan.io ────────────────────────────────────────────────────────────

    async def _query_urlscan(
        self, http, domain: str, layout: OutputLayout
    ) -> list[Finding]:
        findings: list[Finding] = []

        try:
            async with http.get(
                f"https://urlscan.io/api/v1/search/?q=domain:{domain}&size=100"
            ) as resp:
                if resp.status != 200:
                    return findings
                data = await resp.json()
        except Exception as e:
            logger.warning(f"URLScan query failed: {e}")
            return findings

        layout.urlscan_result.write_text(
            json.dumps(data, indent=2), encoding="utf-8"
        )

        results    = data.get("results", [])
        subdomains = set()
        endpoints  = set()
        tech_seen  = set()

        for result in results:
            page = result.get("page", {})
            host = page.get("domain", "").lower()
            url  = page.get("url", "")
            if host and domain in host:
                subdomains.add(host)
            if url:
                endpoints.add(url)

            # Technology info
            meta_tech = result.get("meta", {}).get("processors", {})
            for tech_name in meta_tech:
                tech_seen.add(tech_name)

        if subdomains:
            findings.append(Finding(
                plugin=self.meta.name,
                title=f"URLScan: {len(subdomains)} unique subdomains in scan history",
                severity=FindingSeverity.INFO,
                target=domain, port=None,
                description="\n".join(sorted(subdomains)[:20]),
                metadata={
                    "source": "urlscan",
                    "subdomains": list(subdomains),
                    "scan_count": len(results),
                },
            ))

        if endpoints:
            findings.append(Finding(
                plugin=self.meta.name,
                title=f"URLScan: {len(endpoints)} historical endpoints",
                severity=FindingSeverity.INFO,
                target=domain, port=None,
                description="\n".join(sorted(endpoints)[:10]),
                evidence=list(sorted(endpoints)[:20]),
                metadata={"source": "urlscan", "endpoints": list(endpoints)},
            ))

        return findings

    # ── Shodan ────────────────────────────────────────────────────────────────

    async def _query_shodan(
        self,
        http,
        domain: str,
        layout: OutputLayout,
        api_key: str,
    ) -> list[Finding]:
        findings: list[Finding] = []

        try:
            async with http.get(
                f"https://api.shodan.io/shodan/host/search",
                params={"key": api_key, "query": f"hostname:{domain}"},
            ) as resp:
                if resp.status != 200:
                    error = await resp.text()
                    logger.warning(f"Shodan query failed ({resp.status}): {error[:100]}")
                    return findings
                data = await resp.json()
        except Exception as e:
            logger.warning(f"Shodan query failed: {e}")
            return findings

        layout.shodan_result.write_text(
            json.dumps(data, indent=2), encoding="utf-8"
        )

        matches = data.get("matches", [])
        if not matches:
            return findings

        # Aggregate by IP
        for match in matches[:50]:
            ip      = match.get("ip_str", "")
            ports   = [match.get("port", 0)]
            product = match.get("product", "")
            version = match.get("version", "")
            vulns   = match.get("vulns", {})
            org     = match.get("org", "")
            hostnames = match.get("hostnames", [])

            # CVE findings from Shodan
            if vulns:
                for cve_id, vuln_info in list(vulns.items())[:10]:
                    cvss = vuln_info.get("cvss", None)
                    severity = FindingSeverity.HIGH
                    if cvss:
                        try:
                            cvss_f = float(cvss)
                            if cvss_f >= 9.0:
                                severity = FindingSeverity.CRITICAL
                            elif cvss_f >= 7.0:
                                severity = FindingSeverity.HIGH
                            elif cvss_f >= 4.0:
                                severity = FindingSeverity.MEDIUM
                            else:
                                severity = FindingSeverity.LOW
                        except (ValueError, TypeError):
                            pass

                    findings.append(Finding(
                        plugin=self.meta.name,
                        title=f"Shodan: {cve_id} on {ip}:{ports[0]}",
                        severity=severity,
                        target=ip, port=ports[0],
                        description=(
                            f"Shodan reports {cve_id} for {product} {version} "
                            f"on {ip}:{ports[0]} ({org})"
                        ),
                        cve_ids=[cve_id],
                        cvss=float(cvss) if cvss else None,
                        metadata={"ip": ip, "source": "shodan", "org": org},
                    ))

            # General host finding
            findings.append(Finding(
                plugin=self.meta.name,
                title=f"Shodan: {ip}:{ports[0]} ({product} {version})".strip(),
                severity=FindingSeverity.INFO,
                target=ip, port=ports[0],
                description=(
                    f"IP: {ip}\nOrg: {org}\n"
                    f"Service: {product} {version}\n"
                    f"Hostnames: {', '.join(hostnames[:5])}"
                ),
                metadata={
                    "ip": ip, "port": ports[0], "org": org,
                    "product": product, "version": version,
                    "source": "shodan",
                },
            ))

        findings.insert(0, Finding(
            plugin=self.meta.name,
            title=f"Shodan: {len(matches)} results for {domain}",
            severity=FindingSeverity.INFO,
            target=domain, port=None,
            description=f"Shodan returned {len(matches)} records for hostname:{domain}",
            metadata={"source": "shodan", "count": len(matches)},
        ))

        return findings
