"""
core/models.py — Structured data models for Z3R0 Recon Framework.

All findings, tasks, and scan sessions are represented as typed
dataclasses or Pydantic-style dataclasses. This is the single source
of truth for data shapes across the entire framework.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Optional


# ─── Enumerations ─────────────────────────────────────────────────────────────

class TaskStatus(str, Enum):
    PENDING   = "pending"
    RUNNING   = "running"
    DONE      = "done"
    FAILED    = "failed"
    SKIPPED   = "skipped"


class FindingSeverity(str, Enum):
    CRITICAL = "critical"
    HIGH     = "high"
    MEDIUM   = "medium"
    LOW      = "low"
    INFO     = "info"


class Protocol(str, Enum):
    TCP = "tcp"
    UDP = "udp"


# ─── Core Structures ──────────────────────────────────────────────────────────

@dataclass
class ScanTarget:
    """Represents a validated scan target."""
    host: str
    # Populated after initial nmap phase
    resolved_ip: Optional[str] = None
    hostnames:   list[str]     = field(default_factory=list)

    def __str__(self) -> str:
        return self.host


@dataclass
class PortInfo:
    """A single open port with associated service metadata."""
    port:      int
    protocol:  Protocol
    service:   str
    product:   str
    version:   str
    extrainfo: str
    state:     str = "open"

    @property
    def version_string(self) -> str:
        return f"{self.product} {self.version}".strip()

    @property
    def has_version_info(self) -> bool:
        return bool(self.product or self.version)


@dataclass
class Finding:
    """
    A normalized finding produced by any plugin.

    Plugins must return List[Finding] — not raw text, not file paths.
    The reporting engine reads findings from here, not from disk.
    """
    plugin:      str
    title:       str
    severity:    FindingSeverity
    target:      str
    port:        Optional[int]
    description: str
    raw_output:  str                    = ""
    evidence:    list[str]             = field(default_factory=list)
    cve_ids:     list[str]             = field(default_factory=list)
    cvss:        Optional[float]       = None
    metadata:    dict[str, Any]        = field(default_factory=dict)
    id:          str                   = field(default_factory=lambda: str(uuid.uuid4()))
    discovered_at: datetime            = field(default_factory=datetime.utcnow)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id":           self.id,
            "plugin":       self.plugin,
            "title":        self.title,
            "severity":     self.severity.value,
            "target":       self.target,
            "port":         self.port,
            "description":  self.description,
            "evidence":     self.evidence,
            "cve_ids":      self.cve_ids,
            "cvss":         self.cvss,
            "metadata":     self.metadata,
            "discovered_at": self.discovered_at.isoformat(),
        }


@dataclass
class TaskRecord:
    """
    A unit of work in the task queue.

    Created by the decision engine. Consumed by workers.
    Status is updated by the orchestrator throughout the lifecycle.
    """
    plugin:   str
    target:   ScanTarget
    port:     Optional[int]
    reason:   str
    params:   dict[str, Any]    = field(default_factory=dict)
    status:   TaskStatus        = TaskStatus.PENDING
    findings: list[Finding]     = field(default_factory=list)
    error:    Optional[str]     = None
    started_at:   Optional[datetime] = None
    completed_at: Optional[datetime] = None
    id: str = field(default_factory=lambda: str(uuid.uuid4()))

    @property
    def duration_seconds(self) -> Optional[float]:
        if self.started_at and self.completed_at:
            return (self.completed_at - self.started_at).total_seconds()
        return None

    @property
    def key(self) -> tuple[str, str, Optional[int]]:
        """
        Dedup key — prevents running the same plugin twice on the same
        (target, port) combination.

        BEFORE: (plugin, port)
        AFTER:  (plugin, target_host, port)

        Why this matters: in masscan CIDR mode and httpx subdomain phase,
        tasks for multiple hosts share one session.tasks list. Two hosts on
        port 80 produce identical (plugin, port) keys — the second host is
        silently dropped by build_task_list()'s dedup set. Adding target_host
        makes the key globally unique across all hosts in a session.
        """
        return (self.plugin, str(self.target), self.port)


@dataclass
class SubdomainInfo:
    """A discovered subdomain with source attribution."""
    hostname:   str
    source:     str               # "subfinder", "brute", "permutation", "osint"
    resolved_ip: Optional[str]   = None
    is_live:    bool              = False   # confirmed by httpx probe
    http_status: Optional[int]   = None
    screenshot_path: Optional[str] = None
    technologies: list[str]      = field(default_factory=list)
    discovered_at: datetime      = field(default_factory=datetime.utcnow)

    def to_dict(self) -> dict[str, Any]:
        return {
            "hostname":        self.hostname,
            "source":          self.source,
            "resolved_ip":     self.resolved_ip,
            "is_live":         self.is_live,
            "http_status":     self.http_status,
            "screenshot_path": self.screenshot_path,
            "technologies":    self.technologies,
            "discovered_at":   self.discovered_at.isoformat(),
        }


@dataclass
class ScanConfig:
    """
    Runtime configuration passed through the session.
    Populated from CLI args and config.yaml.
    Avoids threading individual flags through every function signature.
    """
    # Subdomain enumeration
    subdomains_enabled: bool        = False
    wordlist:           Optional[str] = None
    # Masscan
    masscan_enabled:    bool        = False
    masscan_rate:       int         = 1000
    cidr:               Optional[str] = None
    # Nuclei
    nuclei_enabled:     bool        = True
    nuclei_templates:   Optional[str] = None
    # OSINT
    osint_enabled:      bool        = False
    shodan_key:         Optional[str] = None
    otx_key:            Optional[str] = None
    # Screenshots
    screenshots_enabled: bool       = False
    # Arjun is now default-on (same as gobuster/ffuf/nikto).
    # Disable with --no-arjun.
    arjun_enabled:      bool        = True
    arjun_wordlist:     Optional[str] = None
    # Cloud
    cloud_enum_enabled: bool        = False


@dataclass
class ScanSession:
    """
    Top-level container for a complete scan run.

    Persisted to SQLite so runs can be resumed or queried.
    """
    target:      ScanTarget
    session_id:  str             = field(default_factory=lambda: str(uuid.uuid4()))
    started_at:  datetime        = field(default_factory=datetime.utcnow)
    completed_at: Optional[datetime] = None
    open_ports:  list[PortInfo]  = field(default_factory=list)
    tasks:       list[TaskRecord] = field(default_factory=list)
    findings:    list[Finding]   = field(default_factory=list)
    subdomains:  list[SubdomainInfo] = field(default_factory=list)
    output_dir:  str             = ""
    operator:    str             = "unknown"
    authorized:  bool            = False
    config:      ScanConfig      = field(default_factory=ScanConfig)

    @property
    def is_complete(self) -> bool:
        return self.completed_at is not None

    @property
    def finding_counts(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for f in self.findings:
            counts[f.severity.value] = counts.get(f.severity.value, 0) + 1
        return counts

    @property
    def live_subdomains(self) -> list[SubdomainInfo]:
        return [s for s in self.subdomains if s.is_live]
