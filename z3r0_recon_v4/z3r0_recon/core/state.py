"""
core/state.py — SQLite-backed persistence layer.

Provides resumable scans. Session state is written to a local SQLite
database after each task completes. If a run crashes, the next
invocation can load the session and skip already-completed tasks.

Why SQLite and not flat JSON?
- Concurrent writes from multiple workers without corruption (via WAL)
- Query capability: find all sessions against a target, filter by severity
- No external dependency — ships with Python
- Simple migration path to PostgreSQL if distributed architecture is needed

Schema is kept intentionally minimal. We store sessions, tasks, and
findings as JSON blobs rather than fully normalized tables. This avoids
a complex schema migration story for a v1 framework.
"""

from __future__ import annotations

import json
import logging
import sqlite3
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path
from typing import Generator, Optional

from .models import (
    Finding,
    FindingSeverity,
    PortInfo,
    Protocol,
    ScanSession,
    ScanTarget,
    TaskRecord,
    TaskStatus,
)

logger = logging.getLogger("z3r0.state")

SCHEMA = """
CREATE TABLE IF NOT EXISTS sessions (
    session_id   TEXT PRIMARY KEY,
    target_host  TEXT NOT NULL,
    started_at   TEXT NOT NULL,
    completed_at TEXT,
    output_dir   TEXT,
    operator     TEXT,
    authorized   INTEGER DEFAULT 0,
    open_ports   TEXT DEFAULT '[]',   -- JSON array
    metadata     TEXT DEFAULT '{}'
);

CREATE TABLE IF NOT EXISTS tasks (
    task_id      TEXT PRIMARY KEY,
    session_id   TEXT NOT NULL,
    plugin       TEXT NOT NULL,
    port         INTEGER,
    reason       TEXT,
    status       TEXT DEFAULT 'pending',
    params       TEXT DEFAULT '{}',
    error        TEXT,
    started_at   TEXT,
    completed_at TEXT,
    findings     TEXT DEFAULT '[]',   -- JSON array of Finding dicts
    FOREIGN KEY (session_id) REFERENCES sessions(session_id)
);

CREATE TABLE IF NOT EXISTS findings (
    finding_id    TEXT PRIMARY KEY,
    session_id    TEXT NOT NULL,
    task_id       TEXT NOT NULL,
    plugin        TEXT NOT NULL,
    title         TEXT NOT NULL,
    severity      TEXT NOT NULL,
    target        TEXT NOT NULL,
    port          INTEGER,
    description   TEXT,
    raw_output    TEXT,
    evidence      TEXT DEFAULT '[]',
    cve_ids       TEXT DEFAULT '[]',
    cvss          REAL,
    metadata      TEXT DEFAULT '{}',
    discovered_at TEXT,
    FOREIGN KEY (session_id) REFERENCES sessions(session_id)
);

CREATE INDEX IF NOT EXISTS idx_tasks_session    ON tasks(session_id);
CREATE INDEX IF NOT EXISTS idx_findings_session ON findings(session_id);
CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);
"""


class StateStore:
    """
    Thin wrapper around SQLite for scan session persistence.

    All methods are synchronous. The orchestrator calls these from
    asyncio callbacks — for a production distributed system, swap this
    for an aiosqlite-backed async store.
    """

    def __init__(self, db_path: str | Path = "z3r0_recon.db") -> None:
        self.db_path = Path(db_path)
        self._init_db()

    def _init_db(self) -> None:
        with self._connect() as conn:
            conn.executescript(SCHEMA)
        logger.debug(f"State store initialized at {self.db_path}")

    @contextmanager
    def _connect(self) -> Generator[sqlite3.Connection, None, None]:
        conn = sqlite3.connect(
            self.db_path,
            isolation_level=None,  # autocommit
            detect_types=sqlite3.PARSE_DECLTYPES,
        )
        conn.execute("PRAGMA journal_mode=WAL")
        conn.row_factory = sqlite3.Row
        try:
            yield conn
        finally:
            conn.close()

    # ─── Session CRUD ──────────────────────────────────────────────────────────

    def save_session(self, session: ScanSession) -> None:
        """Insert or update a session record."""
        ports_json = json.dumps([
            {
                "port":      p.port,
                "protocol":  p.protocol.value,
                "service":   p.service,
                "product":   p.product,
                "version":   p.version,
                "extrainfo": p.extrainfo,
            }
            for p in session.open_ports
        ])

        with self._connect() as conn:
            conn.execute("""
                INSERT OR REPLACE INTO sessions
                    (session_id, target_host, started_at, completed_at,
                     output_dir, operator, authorized, open_ports)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                session.session_id,
                session.target.host,
                session.started_at.isoformat(),
                session.completed_at.isoformat() if session.completed_at else None,
                session.output_dir,
                session.operator,
                int(session.authorized),
                ports_json,
            ))

    def load_session(self, session_id: str) -> Optional[ScanSession]:
        """Load a session and its tasks from DB. Returns None if not found."""
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM sessions WHERE session_id = ?", (session_id,)
            ).fetchone()

            if not row:
                return None

            ports_data = json.loads(row["open_ports"] or "[]")
            open_ports = [
                PortInfo(
                    port=p["port"],
                    protocol=Protocol(p["protocol"]),
                    service=p["service"],
                    product=p["product"],
                    version=p["version"],
                    extrainfo=p["extrainfo"],
                )
                for p in ports_data
            ]

            tasks = self._load_tasks(conn, session_id)
            findings = self._load_findings(conn, session_id)

            session = ScanSession(
                session_id=row["session_id"],
                target=ScanTarget(host=row["target_host"]),
                started_at=datetime.fromisoformat(row["started_at"]),
                completed_at=(
                    datetime.fromisoformat(row["completed_at"])
                    if row["completed_at"] else None
                ),
                output_dir=row["output_dir"] or "",
                operator=row["operator"] or "unknown",
                authorized=bool(row["authorized"]),
                open_ports=open_ports,
                tasks=tasks,
                findings=findings,
            )
            return session

    def list_sessions(self, target: Optional[str] = None) -> list[dict]:
        """Return summary rows for all sessions, optionally filtered by target."""
        with self._connect() as conn:
            if target:
                rows = conn.execute(
                    "SELECT * FROM sessions WHERE target_host = ? ORDER BY started_at DESC",
                    (target,)
                ).fetchall()
            else:
                rows = conn.execute(
                    "SELECT * FROM sessions ORDER BY started_at DESC"
                ).fetchall()
            return [dict(r) for r in rows]

    # ─── Task Persistence ──────────────────────────────────────────────────────

    def save_task(self, task: TaskRecord, session_id: str) -> None:
        """Insert or update a single task record."""
        findings_json = json.dumps([f.to_dict() for f in task.findings])

        with self._connect() as conn:
            conn.execute("""
                INSERT OR REPLACE INTO tasks
                    (task_id, session_id, plugin, port, reason, status,
                     params, error, started_at, completed_at, findings)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                task.id,
                session_id,
                task.plugin,
                task.port,
                task.reason,
                task.status.value,
                json.dumps(task.params),
                task.error,
                task.started_at.isoformat() if task.started_at else None,
                task.completed_at.isoformat() if task.completed_at else None,
                findings_json,
            ))

    def _load_tasks(
        self, conn: sqlite3.Connection, session_id: str
    ) -> list[TaskRecord]:
        rows = conn.execute(
            "SELECT * FROM tasks WHERE session_id = ?", (session_id,)
        ).fetchall()

        tasks = []
        for row in rows:
            task = TaskRecord(
                id=row["task_id"],
                plugin=row["plugin"],
                target=ScanTarget(host=""),   # re-linked by caller
                port=row["port"],
                reason=row["reason"] or "",
                status=TaskStatus(row["status"]),
                params=json.loads(row["params"] or "{}"),
                error=row["error"],
                started_at=(
                    datetime.fromisoformat(row["started_at"])
                    if row["started_at"] else None
                ),
                completed_at=(
                    datetime.fromisoformat(row["completed_at"])
                    if row["completed_at"] else None
                ),
            )
            tasks.append(task)
        return tasks

    # ─── Finding Persistence ───────────────────────────────────────────────────

    def save_finding(self, finding: Finding, session_id: str, task_id: str) -> None:
        with self._connect() as conn:
            conn.execute("""
                INSERT OR REPLACE INTO findings
                    (finding_id, session_id, task_id, plugin, title,
                     severity, target, port, description, raw_output,
                     evidence, cve_ids, cvss, metadata, discovered_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                finding.id,
                session_id,
                task_id,
                finding.plugin,
                finding.title,
                finding.severity.value,
                finding.target,
                finding.port,
                finding.description,
                finding.raw_output,
                json.dumps(finding.evidence),
                json.dumps(finding.cve_ids),
                finding.cvss,
                json.dumps(finding.metadata),
                finding.discovered_at.isoformat(),
            ))

    @staticmethod
    def _row_to_finding(row: sqlite3.Row) -> Finding:
        """Convert a DB row to a Finding. Single source of truth."""
        return Finding(
            id=row["finding_id"],
            plugin=row["plugin"],
            title=row["title"],
            severity=FindingSeverity(row["severity"]),
            target=row["target"],
            port=row["port"],
            description=row["description"] or "",
            raw_output=row["raw_output"] or "",
            evidence=json.loads(row["evidence"] or "[]"),
            cve_ids=json.loads(row["cve_ids"] or "[]"),
            cvss=row["cvss"],
            metadata=json.loads(row["metadata"] or "{}"),
            discovered_at=datetime.fromisoformat(row["discovered_at"]),
        )

    def _load_findings(
        self, conn: sqlite3.Connection, session_id: str
    ) -> list[Finding]:
        rows = conn.execute(
            "SELECT * FROM findings WHERE session_id = ?", (session_id,)
        ).fetchall()
        return [self._row_to_finding(r) for r in rows]

    def query_findings(
        self,
        session_id: Optional[str] = None,
        severity: Optional[str] = None,
        plugin: Optional[str] = None,
    ) -> list[Finding]:
        """Flexible finding query for reporting use cases."""
        conditions = []
        params: list = []
        if session_id:
            conditions.append("session_id = ?")
            params.append(session_id)
        if severity:
            conditions.append("severity = ?")
            params.append(severity)
        if plugin:
            conditions.append("plugin = ?")
            params.append(plugin)

        where = f"WHERE {' AND '.join(conditions)}" if conditions else ""
        with self._connect() as conn:
            rows = conn.execute(
                f"SELECT * FROM findings {where} ORDER BY severity, discovered_at",
                params
            ).fetchall()
            return [self._row_to_finding(r) for r in rows]
