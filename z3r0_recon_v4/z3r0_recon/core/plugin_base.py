"""
core/plugin_base.py — Abstract base class for all recon plugins.

Every plugin implements this interface. The orchestrator only knows
about ReconPlugin — it never imports individual plugin modules directly.
This is the contract that makes the plugin system extensible.
"""

from __future__ import annotations

import asyncio
import shutil
from abc import ABC, abstractmethod
from dataclasses import dataclass
from pathlib import Path
from typing import ClassVar, Optional

from .models import Finding, PortInfo, ScanSession, ScanTarget, TaskRecord


@dataclass
class PluginMeta:
    """Metadata descriptor attached to every plugin class."""
    name:        str
    description: str
    # Ports this plugin is relevant for. Empty = not port-triggered.
    triggers_on_ports: frozenset[int] = frozenset()
    # If True, plugin is always run regardless of ports (e.g. nmap phase 1)
    always_run:  bool = False
    # Binary that must be on PATH for this plugin to activate
    requires_binary: Optional[str] = None
    # Estimated timeout in seconds — used by the worker to set subprocess timeout
    default_timeout: int = 300


class PluginUnavailableError(Exception):
    """Raised when a plugin's required binary is not installed."""


class ReconPlugin(ABC):
    """
    Base class for all Z3R0 recon plugins.

    Subclass this, set `meta`, implement `execute()`.
    The framework handles everything else: queuing, concurrency,
    state tracking, result storage.

    Example minimal plugin:

        class MyPlugin(ReconPlugin):
            meta = PluginMeta(
                name="my_plugin",
                description="Does something useful",
                triggers_on_ports=frozenset({1234}),
                requires_binary="mytool",
            )

            async def execute(
                self, task: TaskRecord, session: ScanSession
            ) -> list[Finding]:
                output = await self.run_subprocess(
                    ["mytool", "-t", str(task.target)],
                    timeout=self.meta.default_timeout,
                )
                return self._parse_output(output, task)

            def _parse_output(self, output: str, task: TaskRecord) -> list[Finding]:
                findings = []
                # ... parse output, create Finding objects ...
                return findings
    """

    # Every subclass must define this class variable
    meta: ClassVar[PluginMeta]

    def is_available(self) -> bool:
        """Returns True if the plugin's required binary is on PATH."""
        if self.meta.requires_binary is None:
            return True
        return shutil.which(self.meta.requires_binary) is not None

    def check_available(self) -> None:
        """Raise PluginUnavailableError if binary not found."""
        if not self.is_available():
            raise PluginUnavailableError(
                f"Plugin '{self.meta.name}' requires '{self.meta.requires_binary}' "
                f"but it was not found on PATH."
            )

    @abstractmethod
    async def execute(
        self,
        task: TaskRecord,
        session: ScanSession,
    ) -> list[Finding]:
        """
        Run the plugin and return structured findings.

        MUST return a list of Finding objects — do not write raw text to
        disk as a substitute for findings. Raw output can be stored in
        Finding.raw_output for reference.

        The session object is available for context (target, output_dir,
        previously discovered ports) but should not be mutated directly.
        """

    async def run_subprocess(
        self,
        cmd: list[str],
        timeout: int = 300,
        cwd: Optional[str] = None,
    ) -> tuple[str, str, int]:
        """
        Run an external command asynchronously.

        Returns (stdout, stderr, returncode).
        Raises asyncio.TimeoutError on timeout — callers should handle.

        Why async subprocess instead of subprocess.run()?
        Because N plugins run concurrently via the worker pool. Using
        subprocess.run() blocks the event loop — the entire concurrent
        benefit disappears. asyncio.create_subprocess_exec() yields
        control while waiting for the process, allowing other plugins
        to progress simultaneously.
        """
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=cwd,
            )
            stdout_bytes, stderr_bytes = await asyncio.wait_for(
                proc.communicate(), timeout=timeout
            )
            stdout = stdout_bytes.decode("utf-8", errors="replace")
            stderr = stderr_bytes.decode("utf-8", errors="replace")
            return stdout, stderr, proc.returncode or 0

        except asyncio.TimeoutError:
            # Kill the process before propagating
            try:
                proc.kill()
                await proc.wait()
            except Exception:
                pass
            raise

    def save_raw_output(
        self,
        output: str,
        session: ScanSession,
        dest: "str | Path",
    ) -> str:
        """
        Persist raw tool output to a path under the session output directory.

        `dest` can be:
          - An absolute Path (used as-is, must be under session.output_dir)
          - A relative Path or string (resolved under session.output_dir)

        The parent directory is created automatically.
        Returns the absolute path as a string.
        """
        dest_path = Path(dest)
        if not dest_path.is_absolute():
            dest_path = Path(session.output_dir) / dest_path

        dest_path.parent.mkdir(parents=True, exist_ok=True)
        dest_path.write_text(output, encoding="utf-8")
        return str(dest_path)
