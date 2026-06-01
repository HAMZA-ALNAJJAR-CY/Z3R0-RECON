"""
plugins/subdomain_enum.py — Subdomain enumeration plugin.

Phase 0: runs before nmap. Discovers subdomains via:
  1. subfinder   — passive enumeration (certificate transparency, APIs)
  2. puredns     — active brute-force resolution against a wordlist
  3. dnsgen      — permutation generation on discovered subdomains

All three tools are optional — the plugin degrades gracefully when
any of them is absent. Results are deduplicated and written to
recon/subdomains/resolved.txt for downstream consumption.

Output to session.subdomains (list[SubdomainInfo]) — the CLI reads
this list to build httpx probe tasks for live-host detection.

Install:
    go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
    go install -v github.com/d3mondev/puredns/v2@latest
    go install -v github.com/rverton/dnsgen@latest   # or: pip install dnsgen
    # massdns is a puredns dependency:
    apt install massdns  # or build from source
"""

from __future__ import annotations

import asyncio
import logging
import shutil
from pathlib import Path
from typing import ClassVar

from ..core.models import Finding, FindingSeverity, ScanSession, SubdomainInfo, TaskRecord
from ..core.output_layout import OutputLayout
from ..core.plugin_base import PluginMeta, ReconPlugin

logger = logging.getLogger("z3r0.subdomain_enum")

# Default public resolvers file — puredns needs this
_DEFAULT_RESOLVERS = Path(__file__).parent.parent / "data" / "resolvers.txt"

# Fallback wordlists (puredns brute-force)
_WORDLIST_CANDIDATES = [
    Path("/opt/SecLists/Discovery/DNS/subdomains-top1million-5000.txt"),
    Path("/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt"),
    Path("/opt/SecLists/Discovery/DNS/2m-subdomains.txt"),
]


def _find_wordlist(override: str | None = None) -> str | None:
    if override and Path(override).exists():
        return override
    for p in _WORDLIST_CANDIDATES:
        if p.exists():
            return str(p)
    return None


class SubdomainEnumPlugin(ReconPlugin):

    meta: ClassVar[PluginMeta] = PluginMeta(
        name="subdomain_enum",
        description="Passive + active subdomain enumeration (subfinder, puredns, dnsgen)",
        always_run=False,     # triggered explicitly from cli.py, not by decision engine
        requires_binary=None, # checked per-tool below
        default_timeout=600,
    )

    async def execute(
        self, task: TaskRecord, session: ScanSession
    ) -> list[Finding]:
        domain  = str(task.target)
        layout  = OutputLayout.from_session(session)
        config  = session.config
        wordlist = _find_wordlist(config.wordlist)

        all_subdomains: set[str] = set()
        findings: list[Finding] = []

        # ── 1. Subfinder: passive enumeration ─────────────────────────────────
        if shutil.which("subfinder"):
            subs = await self._run_subfinder(domain, layout, session)
            all_subdomains.update(subs)
            findings.append(Finding(
                plugin=self.meta.name,
                title=f"subfinder: {len(subs)} subdomains discovered",
                severity=FindingSeverity.INFO,
                target=domain, port=None,
                description="\n".join(sorted(subs)[:20]) + (
                    f"\n...and {len(subs)-20} more" if len(subs) > 20 else ""
                ),
                metadata={"source": "subfinder", "count": len(subs)},
            ))
            logger.info(f"subfinder found {len(subs)} subdomains")
        else:
            logger.warning("subfinder not found — skipping passive enumeration")

        # ── 2. Puredns: active brute-force ────────────────────────────────────
        if shutil.which("puredns") and wordlist:
            subs = await self._run_puredns(domain, wordlist, layout, session)
            new = subs - all_subdomains
            all_subdomains.update(subs)
            if new:
                findings.append(Finding(
                    plugin=self.meta.name,
                    title=f"puredns brute-force: {len(new)} new subdomains",
                    severity=FindingSeverity.INFO,
                    target=domain, port=None,
                    description="\n".join(sorted(new)[:20]),
                    metadata={"source": "puredns", "count": len(new)},
                ))
            logger.info(f"puredns found {len(subs)} subdomains ({len(new)} new)")
        elif not shutil.which("puredns"):
            logger.warning("puredns not found — skipping brute-force")
        elif not wordlist:
            logger.warning("No wordlist found — skipping puredns brute-force. "
                           "Install seclists or use --wordlist")

        # ── 3. Dnsgen: permutation generation ────────────────────────────────
        if shutil.which("dnsgen") and all_subdomains:
            subs = await self._run_dnsgen(domain, all_subdomains, layout, session)
            new = subs - all_subdomains
            all_subdomains.update(subs)
            if new:
                findings.append(Finding(
                    plugin=self.meta.name,
                    title=f"dnsgen permutations: {len(new)} new subdomains",
                    severity=FindingSeverity.INFO,
                    target=domain, port=None,
                    description="\n".join(sorted(new)[:20]),
                    metadata={"source": "dnsgen", "count": len(new)},
                ))
            logger.info(f"dnsgen found {len(new)} new subdomains")
        else:
            logger.warning("dnsgen not found — skipping permutation phase")

        # ── 4. Write final resolved list and populate session ─────────────────
        if all_subdomains:
            layout.subdomains_resolved.write_text(
                "\n".join(sorted(all_subdomains)), encoding="utf-8"
            )
            # Populate session.subdomains for downstream consumers (httpx, reports)
            for hostname in sorted(all_subdomains):
                session.subdomains.append(SubdomainInfo(
                    hostname=hostname,
                    source="enum",
                ))
            findings.append(Finding(
                plugin=self.meta.name,
                title=f"Total unique subdomains discovered: {len(all_subdomains)}",
                severity=FindingSeverity.INFO,
                target=domain, port=None,
                description=f"Results written to {layout.subdomains_resolved}",
                metadata={"total": len(all_subdomains)},
            ))
        else:
            findings.append(Finding(
                plugin=self.meta.name,
                title="No subdomains discovered",
                severity=FindingSeverity.INFO,
                target=domain, port=None,
                description="All enumeration methods returned zero results.",
            ))

        return findings

    # ── Tool runners ──────────────────────────────────────────────────────────

    async def _run_subfinder(
        self, domain: str, layout: OutputLayout, session: ScanSession
    ) -> set[str]:
        out_file = layout.subfinder_result
        cmd = ["subfinder", "-d", domain, "-o", str(out_file), "-silent"]

        # Inject API keys from session config if available
        # subfinder reads ~/.config/subfinder/config.yaml automatically,
        # but we can also pass provider config
        try:
            stdout, stderr, rc = await self.run_subprocess(cmd, timeout=300)
        except asyncio.TimeoutError:
            logger.warning("subfinder timed out")
            return set()
        except Exception as e:
            logger.error(f"subfinder error: {e}")
            return set()

        return self._read_hostnames(out_file)

    async def _run_puredns(
        self,
        domain: str,
        wordlist: str,
        layout: OutputLayout,
        session: ScanSession,
    ) -> set[str]:
        out_file = layout.puredns_result
        resolvers = str(_DEFAULT_RESOLVERS) if _DEFAULT_RESOLVERS.exists() else None

        cmd = [
            "puredns", "brute", wordlist, domain,
            "-w", str(out_file),
        ]
        if resolvers:
            cmd += ["-r", resolvers]

        try:
            stdout, stderr, rc = await self.run_subprocess(cmd, timeout=self.meta.default_timeout)
        except asyncio.TimeoutError:
            logger.warning("puredns timed out — partial results may be in file")
        except Exception as e:
            logger.error(f"puredns error: {e}")
            return set()

        return self._read_hostnames(out_file)

    async def _run_dnsgen(
        self,
        domain: str,
        existing: set[str],
        layout: OutputLayout,
        session: ScanSession,
    ) -> set[str]:
        # Write current subs to a temp file for dnsgen input
        input_file = layout.subdomains_dir / "dnsgen_input.txt"
        input_file.write_text("\n".join(sorted(existing)), encoding="utf-8")

        out_file = layout.dnsgen_result

        # dnsgen writes to stdout; we pipe through puredns resolve if available
        try:
            stdout, stderr, rc = await self.run_subprocess(
                ["dnsgen", str(input_file)], timeout=120
            )
        except asyncio.TimeoutError:
            logger.warning("dnsgen timed out")
            return set()
        except Exception as e:
            logger.error(f"dnsgen error: {e}")
            return set()

        permutations = {line.strip() for line in stdout.splitlines() if line.strip()}
        if not permutations:
            return set()

        # Resolve permutations with puredns if available
        if shutil.which("puredns"):
            perm_file = layout.subdomains_dir / "dnsgen_perms.txt"
            perm_file.write_text("\n".join(sorted(permutations)), encoding="utf-8")

            resolvers = str(_DEFAULT_RESOLVERS) if _DEFAULT_RESOLVERS.exists() else None
            cmd = ["puredns", "resolve", str(perm_file), "-w", str(out_file)]
            if resolvers:
                cmd += ["-r", resolvers]

            try:
                await self.run_subprocess(cmd, timeout=300)
            except asyncio.TimeoutError:
                logger.warning("puredns resolve (dnsgen) timed out")

            return self._read_hostnames(out_file)
        else:
            # Without puredns, save raw permutations
            out_file.write_text("\n".join(sorted(permutations)), encoding="utf-8")
            return permutations

    @staticmethod
    def _read_hostnames(path: Path) -> set[str]:
        try:
            return {
                line.strip().lower()
                for line in path.read_text(encoding="utf-8").splitlines()
                if line.strip() and not line.startswith("#")
            }
        except FileNotFoundError:
            return set()
