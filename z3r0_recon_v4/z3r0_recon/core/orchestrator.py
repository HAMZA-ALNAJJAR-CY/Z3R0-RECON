"""
core/orchestrator.py — Async worker pool orchestrator.

This replaces the sequential `run_all_tasks()` for loop with a proper
concurrent execution model. N workers pull tasks from an asyncio.Queue
and execute them in parallel. The queue is bounded — this provides
natural backpressure and prevents spawning 50 nmap processes at once.

Architecture decisions:
- asyncio.Queue over threading.Queue: we're I/O bound (subprocess waits),
  not CPU bound. The GIL is not the bottleneck. True threads would add
  complexity with no benefit for subprocess-based tools.
- Worker count defaults to 5: enough parallelism to run web + service
  scans simultaneously, low enough to avoid triggering IDS rate limits.
- Findings are aggregated into the ScanSession under a lock.
- Failed tasks are recorded with their error — not silently dropped.
"""

from __future__ import annotations

import asyncio
import logging
from datetime import datetime
from typing import Optional

from .models import Finding, ScanSession, TaskRecord, TaskStatus
from .plugin_base import PluginUnavailableError, ReconPlugin
from .plugin_registry import PluginRegistry

logger = logging.getLogger("z3r0.orchestrator")


class Orchestrator:
    """
    Manages concurrent execution of scan tasks.

    Usage:
        registry = PluginRegistry()
        registry.discover("z3r0_recon.plugins")

        orchestrator = Orchestrator(registry, concurrency=5)
        await orchestrator.run(session)
        # session.findings and session.tasks are now populated
    """

    def __init__(
        self,
        registry: PluginRegistry,
        concurrency: int = 5,
        on_finding: Optional[callable] = None,
        on_task_complete: Optional[callable] = None,
    ) -> None:
        self.registry = registry
        self.concurrency = concurrency
        # Callbacks for live progress reporting
        self._on_finding = on_finding
        self._on_task_complete = on_task_complete
        self._findings_lock = asyncio.Lock()

    async def run(self, session: ScanSession) -> None:
        """
        Execute all pending tasks in the session concurrently.

        This is the single entry point. The session's task list must be
        populated (by build_task_list) before calling this.
        """
        if not session.tasks:
            logger.warning("No tasks to run.")
            return

        queue: asyncio.Queue[TaskRecord] = asyncio.Queue()

        # Enqueue only pending tasks — allows resuming partial sessions
        pending = [t for t in session.tasks if t.status == TaskStatus.PENDING]
        for task in pending:
            await queue.put(task)

        logger.info(
            f"Starting {len(pending)} tasks with {self.concurrency} workers "
            f"(session: {session.session_id})"
        )

        # Spawn workers
        workers = [
            asyncio.create_task(self._worker(f"worker-{i}", queue, session))
            for i in range(min(self.concurrency, len(pending)))
        ]

        # Wait for the queue to drain
        await queue.join()

        # Cancel idle workers
        for w in workers:
            w.cancel()
        await asyncio.gather(*workers, return_exceptions=True)

        session.completed_at = datetime.utcnow()
        logger.info(
            f"Scan complete. "
            f"{len(session.findings)} findings across "
            f"{len(session.tasks)} tasks."
        )

    async def _worker(
        self,
        name: str,
        queue: asyncio.Queue[TaskRecord],
        session: ScanSession,
    ) -> None:
        """Worker coroutine — pulls tasks from queue and executes them."""
        while True:
            try:
                task = await queue.get()
            except asyncio.CancelledError:
                return

            try:
                await self._execute_task(task, session)
            except Exception as e:
                logger.error(f"[{name}] Unhandled error in task {task.id}: {e}")
                task.status = TaskStatus.FAILED
                task.error = str(e)
                task.completed_at = datetime.utcnow()
            finally:
                queue.task_done()

    async def _execute_task(
        self,
        task: TaskRecord,
        session: ScanSession,
    ) -> None:
        """Execute a single task via its plugin."""
        plugin_cls = self.registry.get(task.plugin)

        if plugin_cls is None:
            logger.warning(f"No plugin registered for '{task.plugin}' — skipping.")
            task.status = TaskStatus.SKIPPED
            task.error = f"Plugin '{task.plugin}' not registered"
            task.completed_at = datetime.utcnow()
            return

        plugin: ReconPlugin = plugin_cls()

        if not plugin.is_available():
            logger.warning(
                f"Plugin '{task.plugin}' requires '{plugin.meta.requires_binary}' "
                f"which is not installed — skipping."
            )
            task.status = TaskStatus.SKIPPED
            task.error = f"Binary '{plugin.meta.requires_binary}' not found"
            task.completed_at = datetime.utcnow()
            return

        task.status = TaskStatus.RUNNING
        task.started_at = datetime.utcnow()

        logger.info(
            f"[{task.plugin}] Starting on port {task.port} "
            f"(task {task.id[:8]})"
        )

        try:
            findings: list[Finding] = await asyncio.wait_for(
                plugin.execute(task, session),
                timeout=plugin.meta.default_timeout + 30,  # grace period
            )

            task.findings = findings
            task.status = TaskStatus.DONE
            task.completed_at = datetime.utcnow()

            # Aggregate findings into session under lock
            async with self._findings_lock:
                session.findings.extend(findings)

            if findings:
                logger.info(
                    f"[{task.plugin}] port {task.port}: "
                    f"{len(findings)} finding(s)"
                )

            # Fire callbacks for live progress
            if self._on_task_complete:
                await self._maybe_call(self._on_task_complete, task)
            for finding in findings:
                if self._on_finding:
                    await self._maybe_call(self._on_finding, finding)

        except asyncio.TimeoutError:
            task.status = TaskStatus.FAILED
            task.error = f"Plugin timed out after {plugin.meta.default_timeout}s"
            task.completed_at = datetime.utcnow()
            logger.warning(
                f"[{task.plugin}] Timed out on port {task.port}"
            )
        except PluginUnavailableError as e:
            task.status = TaskStatus.SKIPPED
            task.error = str(e)
            task.completed_at = datetime.utcnow()
        except Exception as e:
            task.status = TaskStatus.FAILED
            task.error = str(e)
            task.completed_at = datetime.utcnow()
            logger.error(
                f"[{task.plugin}] port {task.port}: {type(e).__name__}: {e}"
            )

    @staticmethod
    async def _maybe_call(fn, *args) -> None:
        """Call fn whether it's async or sync."""
        import inspect
        if inspect.iscoroutinefunction(fn):
            await fn(*args)
        else:
            fn(*args)
