"""
core/decision.py — Decision engine: open ports → task list.

Extracted from the monolith and rewritten to produce TaskRecord objects
instead of raw dicts. The decision engine is pure — it takes a list of
PortInfo and returns a list of TaskRecord. No I/O, no subprocess calls.

Port→service mapping is data-driven. Adding a new service handler means
adding an entry to SERVICE_MAP, not editing a sequence of if-statements.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable

from .models import PortInfo, ScanTarget, TaskRecord

# ─── Port Category Sets ────────────────────────────────────────────────────────

WEB_PORTS     = frozenset({80, 443, 8080, 8443, 8000, 8008, 8888, 3000, 5000})
SMB_PORTS     = frozenset({139, 445})
FTP_PORTS     = frozenset({21})
SSH_PORTS     = frozenset({22})
RDP_PORTS     = frozenset({3389})
MSSQL_PORTS   = frozenset({1433})
MYSQL_PORTS   = frozenset({3306})
ORACLE_PORTS  = frozenset({1521})
LDAP_PORTS    = frozenset({389, 636})
SMTP_PORTS    = frozenset({25, 465, 587})
DNS_PORTS     = frozenset({53})
SNMP_PORTS    = frozenset({161})
MONGO_PORTS   = frozenset({27017})
REDIS_PORTS   = frozenset({6379})
ELASTIC_PORTS = frozenset({9200, 9300})


# ─── Task Factory Functions ────────────────────────────────────────────────────
#
# Each function receives (port: PortInfo, target: ScanTarget) and returns
# a list of TaskRecord objects for that port. This replaces the nested
# add() closure with explicit, testable factory functions.

def _web_tasks(port: PortInfo, target: ScanTarget) -> list[TaskRecord]:
    scheme = "https" if port.port in {443, 8443} else "http"
    host = str(target)
    std_ports = {80, 443}
    url = (
        f"{scheme}://{host}"
        if port.port in std_ports
        else f"{scheme}://{host}:{port.port}"
    )
    base_params = {"url": url, "scheme": scheme}
    tasks = []
    # Core web plugins — always run when a web port is detected
    for plugin in ("nikto", "gobuster", "ffuf", "whatweb", "wafw00f", "nuclei"):
        tasks.append(TaskRecord(
            plugin=plugin,
            target=target,
            port=port.port,
            reason=f"Web server detected on port {port.port}",
            params=dict(base_params),
        ))
    # Arjun runs after gobuster/ffuf have found live paths — same trigger
    tasks.append(TaskRecord(
        plugin="arjun",
        target=target,
        port=port.port,
        reason=f"Parameter discovery on web endpoint port {port.port}",
        params=dict(base_params),
    ))
    return tasks


def _smb_tasks(port: PortInfo, target: ScanTarget) -> list[TaskRecord]:
    return [TaskRecord(
        plugin="enum4linux",
        target=target,
        port=port.port,
        reason=f"SMB service detected on port {port.port}",
        params={},
    )]


def _ftp_tasks(port: PortInfo, target: ScanTarget) -> list[TaskRecord]:
    return [TaskRecord(
        plugin="ftp_check",
        target=target,
        port=port.port,
        reason="FTP service detected — checking anonymous login",
        params={},
    )]


def _ssh_tasks(port: PortInfo, target: ScanTarget) -> list[TaskRecord]:
    return [TaskRecord(
        plugin="ssh_audit",
        target=target,
        port=port.port,
        reason=f"SSH detected (version: {port.version_string})",
        params={"version": port.version},
    )]


def _mysql_tasks(port: PortInfo, target: ScanTarget) -> list[TaskRecord]:
    return [TaskRecord(
        plugin="mysql_check",
        target=target,
        port=port.port,
        reason="MySQL detected — checking anonymous/weak auth",
        params={},
    )]


def _mssql_tasks(port: PortInfo, target: ScanTarget) -> list[TaskRecord]:
    return [TaskRecord(
        plugin="mssql_check",
        target=target,
        port=port.port,
        reason="MSSQL detected",
        params={},
    )]


def _redis_tasks(port: PortInfo, target: ScanTarget) -> list[TaskRecord]:
    return [TaskRecord(
        plugin="redis_check",
        target=target,
        port=port.port,
        reason="Redis detected — checking unauthenticated access",
        params={},
    )]


def _mongo_tasks(port: PortInfo, target: ScanTarget) -> list[TaskRecord]:
    return [TaskRecord(
        plugin="mongo_check",
        target=target,
        port=port.port,
        reason="MongoDB detected — checking unauthenticated access",
        params={},
    )]


def _snmp_tasks(port: PortInfo, target: ScanTarget) -> list[TaskRecord]:
    return [TaskRecord(
        plugin="snmp_check",
        target=target,
        port=port.port,
        reason="SNMP detected — community string enumeration",
        params={},
    )]


def _elastic_tasks(port: PortInfo, target: ScanTarget) -> list[TaskRecord]:
    return [TaskRecord(
        plugin="elastic_check",
        target=target,
        port=port.port,
        reason="Elasticsearch detected — checking open access",
        params={},
    )]


# ─── Service Map ──────────────────────────────────────────────────────────────
#
# Maps a port category (frozenset) to a task factory function.
# To add a new service: add a factory function above and one entry here.
# The decision engine loops over this — no more if/elif chains.

TaskFactory = Callable[[PortInfo, ScanTarget], list[TaskRecord]]

SERVICE_MAP: list[tuple[frozenset[int], TaskFactory]] = [
    (WEB_PORTS,     _web_tasks),
    (SMB_PORTS,     _smb_tasks),
    (FTP_PORTS,     _ftp_tasks),
    (SSH_PORTS,     _ssh_tasks),
    (MYSQL_PORTS,   _mysql_tasks),
    (MSSQL_PORTS,   _mssql_tasks),
    (REDIS_PORTS,   _redis_tasks),
    (MONGO_PORTS,   _mongo_tasks),
    (SNMP_PORTS,    _snmp_tasks),
    (ELASTIC_PORTS, _elastic_tasks),
]


# ─── CVE Lookup Task Factory ──────────────────────────────────────────────────

def _cve_task(port: PortInfo, target: ScanTarget) -> TaskRecord:
    return TaskRecord(
        plugin="cve_lookup",
        target=target,
        port=port.port,
        reason=f"Version info available: {port.version_string}",
        params={
            "product": port.product,
            "version": port.version,
            "service": port.service,
        },
    )


# ─── Subdomain / HTTPX task builder ──────────────────────────────────────────

def build_httpx_tasks(
    hostnames: list[str],
    target: ScanTarget,
) -> list[TaskRecord]:
    """
    Build httpx probe + gowitness screenshot tasks for a list of hostnames.
    Called after subdomain enumeration completes.
    """
    tasks = []
    seen: set[str] = set()
    for hostname in hostnames:
        if hostname in seen:
            continue
        seen.add(hostname)
        sub_target = ScanTarget(host=hostname)
        tasks.append(TaskRecord(
            plugin="httpx_probe",
            target=sub_target,
            port=None,
            reason=f"Probe live web services on {hostname}",
            params={"hostname": hostname, "parent_target": str(target)},
        ))
        tasks.append(TaskRecord(
            plugin="gowitness",
            target=sub_target,
            port=None,
            reason=f"Screenshot {hostname}",
            params={"hostname": hostname},
        ))
    return tasks


# ─── Decision Engine ──────────────────────────────────────────────────────────

def build_task_list(
    open_ports: list[PortInfo],
    target: ScanTarget,
) -> list[TaskRecord]:
    """
    Given a list of open ports, return a deduplicated list of TaskRecords.

    This is the only function the orchestrator calls. It is pure —
    no I/O, no side effects. Fully testable in isolation.
    """
    port_set = frozenset(p.port for p in open_ports)
    tasks: list[TaskRecord] = []
    seen: set[tuple[str, str, int | None]] = set()

    def add(task: TaskRecord) -> None:
        key = task.key
        if key not in seen:
            seen.add(key)
            tasks.append(task)

    for port_info in open_ports:
        # Service-based tasks
        for port_category, factory in SERVICE_MAP:
            if port_info.port in port_category:
                for task in factory(port_info, target):
                    add(task)

        # CVE lookup for any port with version information
        if port_info.has_version_info:
            add(_cve_task(port_info, target))

    return tasks
