"""
plugins/arjun_plugin.py — Hidden parameter discovery via Arjun.

Arjun discovers hidden HTTP parameters by fuzzing GET/POST requests
and analyzing differences in responses. High-value findings include
parameters that resemble file paths (LFI candidates), redirect targets
(open redirect), or database identifiers (IDOR/SQLi candidates).

Install:
    pip install arjun
    # or: pipx install arjun

Arjun runs after the web scanning phase — it needs a confirmed live
URL. The decision engine adds it alongside gobuster/ffuf.
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

logger = logging.getLogger("z3r0.arjun")

# Parameters that suggest high-impact injection candidates
_HIGH_IMPACT_PATTERNS = [
    # File / path traversal
    "file", "path", "dir", "folder", "include", "require", "template",
    "load", "read", "document", "root", "pg",
    # Redirect / SSRF
    "url", "redirect", "return", "next", "dest", "destination",
    "redir", "location", "callback", "out", "target", "to",
    # SQL injection candidates
    "id", "user_id", "item_id", "order", "sort", "orderby", "page",
    "num", "cat", "category", "product",
    # SSTI / code execution
    "template", "lang", "locale",
]


class ArjunPlugin(ReconPlugin):

    meta: ClassVar[PluginMeta] = PluginMeta(
        name="arjun",
        description="Hidden HTTP parameter discovery via Arjun",
        triggers_on_ports=frozenset({80, 443, 8080, 8443, 8000, 8008, 8888, 3000, 5000}),
        requires_binary="arjun",
        default_timeout=300,
    )

    async def execute(
        self, task: TaskRecord, session: ScanSession
    ) -> list[Finding]:
        url    = task.params.get("url", "")
        port   = task.port or 80
        layout = OutputLayout.from_session(session)

        if not url:
            return []

        if not shutil.which("arjun"):
            return [Finding(
                plugin=self.meta.name,
                title="arjun not installed",
                severity=FindingSeverity.INFO,
                target=url, port=port,
                description="Install arjun: pip install arjun",
            )]

        out_file = layout.arjun_result(port)
        wordlist = session.config.arjun_wordlist

        cmd = [
            "arjun",
            "-u", url,
            "-oJ", str(out_file),
            "-t", "10",
            "--stable",
        ]
        if wordlist and Path(wordlist).exists():
            cmd += ["-w", wordlist]

        logger.info(f"arjun: discovering parameters on {url}")

        try:
            stdout, stderr, rc = await self.run_subprocess(
                cmd, timeout=self.meta.default_timeout
            )
        except TimeoutError:
            return [Finding(
                plugin=self.meta.name,
                title="arjun timed out",
                severity=FindingSeverity.INFO,
                target=url, port=port,
                description="Arjun exceeded timeout.",
            )]
        except Exception as e:
            return [Finding(
                plugin=self.meta.name,
                title=f"arjun error: {e}",
                severity=FindingSeverity.INFO,
                target=url, port=port,
                description=str(e),
            )]

        return self._parse_arjun_json(out_file, url, port)

    def _parse_arjun_json(
        self, out_file: Path, url: str, port: int
    ) -> list[Finding]:
        try:
            data = json.loads(out_file.read_text(encoding="utf-8"))
        except (FileNotFoundError, json.JSONDecodeError):
            return [Finding(
                plugin=self.meta.name,
                title="arjun: no parameters found",
                severity=FindingSeverity.INFO,
                target=url, port=port,
                description="Arjun completed with no discovered parameters.",
            )]

        # Arjun output: {"url": {"GET": [...], "POST": [...]}}
        findings: list[Finding] = []

        for target_url, methods in data.items():
            for method, params in methods.items():
                if not params:
                    continue

                # Classify each parameter
                high_impact = [
                    p for p in params
                    if any(pat in p.lower() for pat in _HIGH_IMPACT_PATTERNS)
                ]
                normal = [p for p in params if p not in high_impact]

                if high_impact:
                    findings.append(Finding(
                        plugin=self.meta.name,
                        title=f"High-impact parameters: {', '.join(high_impact[:5])}",
                        severity=FindingSeverity.MEDIUM,
                        target=target_url,
                        port=port,
                        description=(
                            f"Arjun found potentially high-impact {method} parameters "
                            f"on {target_url}:\n"
                            + "\n".join(f"  • {p}" for p in high_impact)
                            + "\n\nThese parameter names suggest possible LFI, open "
                            "redirect, SSRF, IDOR, or SQLi candidates. Manual testing required."
                        ),
                        evidence=[f"{method} {p}" for p in high_impact],
                        metadata={
                            "method": method,
                            "params": high_impact,
                            "category": "high_impact",
                        },
                    ))

                if normal:
                    findings.append(Finding(
                        plugin=self.meta.name,
                        title=f"Arjun: {len(normal)} {method} parameters on {target_url}",
                        severity=FindingSeverity.LOW,
                        target=target_url,
                        port=port,
                        description=(
                            f"Discovered {method} parameters: "
                            + ", ".join(normal[:20])
                            + (f" ...+{len(normal)-20} more" if len(normal) > 20 else "")
                        ),
                        evidence=[f"{method} {p}" for p in normal],
                        metadata={"method": method, "params": normal},
                    ))

        if not findings:
            findings.append(Finding(
                plugin=self.meta.name,
                title="arjun: no parameters found",
                severity=FindingSeverity.INFO,
                target=url, port=port,
                description="Arjun completed with no discoverable parameters.",
            ))

        return findings
