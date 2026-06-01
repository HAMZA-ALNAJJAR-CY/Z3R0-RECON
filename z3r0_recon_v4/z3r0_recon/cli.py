"""
cli.py — Command-line interface for Z3R0 Recon Framework.

Execution flow:
  0. Parse args → build ScanConfig
  1. Ethics gate + target validation
  2. Create ScanSession, StateStore, OutputLayout
  3. [Optional] Phase 0a: OSINT collection (passive, no scanning)
  4. [Optional] Phase 0b: Subdomain enumeration
  5. [Optional] Phase 0c: Masscan rapid port scan (CIDR mode)
  6. Phase 1:   Nmap port + service detection
  7.            Decision engine → build follow-on task list
  8. Phase 2:   Concurrent execution of all service plugins
  9. [Optional] Phase 3: HTTPX probing + screenshots of live subdomains
  10. Generate reports (markdown, JSON, HTML)
"""

from __future__ import annotations

import argparse
import asyncio
import logging
import sys
from pathlib import Path

logging.basicConfig(
    level=logging.WARNING,
    format="%(asctime)s %(name)s %(levelname)s %(message)s",
)

from .core.decision import build_task_list, build_httpx_tasks
from .core.models import ScanConfig, ScanSession, ScanTarget, TaskRecord, TaskStatus
from .core.orchestrator import Orchestrator
from .core.output_layout import OutputLayout
from .core.plugin_registry import PluginRegistry
from .core.state import StateStore
from .ethics import run_ethics_gate, validate_target, TargetValidationError
from .reporting.engine import generate_reports

# ─── ANSI Colors ──────────────────────────────────────────────────────────────
R = "\033[91m"; G = "\033[92m"; Y = "\033[93m"
C = "\033[96m"; M = "\033[95m"; W = "\033[97m"
DIM = "\033[2m"; B = "\033[1m"; RST = "\033[0m"

BANNER = f"""{C}{B}
╔══════════════════════════════════════════════════════════════╗
║   ███████╗███████╗██████╗  ██████╗     ██████╗ ███████╗     ║
║   ╚══███╔╝██╔════╝██╔══██╗██╔═══██╗    ██╔══██╗██╔════╝     ║
║     ███╔╝ █████╗  ██████╔╝██║   ██║    ██████╔╝█████╗       ║
║    ███╔╝  ██╔══╝  ██╔══██╗██║   ██║    ██╔══██╗██╔══╝       ║
║   ███████╗███████╗██║  ██║╚██████╔╝    ██║  ██║███████╗     ║
║   ╚══════╝╚══════╝╚═╝  ╚═╝ ╚═════╝     ╚═╝  ╚═╝╚══════╝     ║
║         {Y}Intelligent Auto-Recon — Authorized Use Only{C}      ║
╚══════════════════════════════════════════════════════════════╝{RST}
"""


def log(level: str, msg: str) -> None:
    icons = {
        "info": f"{C}[*]{RST}", "ok":   f"{G}[+]{RST}",
        "warn": f"{Y}[!]{RST}", "err":  f"{R}[-]{RST}",
        "step": f"{M}[>]{RST}",
    }
    print(f"{icons.get(level, '[?]')} {msg}")


def section(title: str) -> None:
    print(f"\n{M}{B}{'━' * 60}{RST}")
    print(f"{Y}{B}  ⚡ {title}{RST}")
    print(f"{M}{B}{'━' * 60}{RST}\n")


def print_ports(session: ScanSession) -> None:
    if not session.open_ports:
        log("warn", "No open ports detected.")
        return
    print(f"\n{B}{C}{'─' * 58}{RST}")
    print(f"{B}  {'PORT':<10} {'SERVICE':<14} {'PRODUCT/VERSION'}{RST}")
    print(f"{C}{'─' * 58}{RST}")
    for p in session.open_ports:
        print(
            f"  {G}{p.port:<10}{RST}"
            f"{Y}{p.service:<14}{RST}"
            f"{DIM}{p.version_string}{RST}"
        )
    print(f"{C}{'─' * 58}{RST}\n")


def print_subdomains(session: ScanSession) -> None:
    subs = session.subdomains
    if not subs:
        return
    live = session.live_subdomains
    print(f"\n{B}{C}{'─' * 58}{RST}")
    print(f"{B}  SUBDOMAINS  {G}{len(subs)} discovered{RST}  {DIM}({len(live)} live){RST}")
    print(f"{C}{'─' * 58}{RST}")
    for s in sorted(subs, key=lambda x: x.hostname)[:20]:
        status = f"{G}LIVE [{s.http_status}]{RST}" if s.is_live else f"{DIM}dead{RST}"
        print(f"  {C}{s.hostname:<45}{RST} {status}")
    if len(subs) > 20:
        print(f"  {DIM}...and {len(subs) - 20} more — see reports/{RST}")
    print(f"{C}{'─' * 58}{RST}\n")


def print_plan(tasks: list[TaskRecord]) -> None:
    section("DECISION ENGINE — Auto-detected Scan Plan")
    seen: set = set()
    for t in tasks:
        if t.key in seen:
            continue
        seen.add(t.key)
        log("step",
            f"{B}{Y}{t.plugin:<20}{RST} "
            f"port {G}{t.port or 'N/A':<8}{RST} "
            f"{DIM}← {t.reason}{RST}"
        )


def print_summary(session: ScanSession, report_paths: dict) -> None:
    counts = session.finding_counts
    print(f"\n{G}{B}{'═' * 60}{RST}")
    print(f"{G}{B}  ✓  Z3R0 Recon Complete!{RST}")
    print(f"\n{B}  Output directory:{RST}")
    print(f"    {C}{session.output_dir}/{RST}")
    print(f"      {DIM}├── recon/       raw tool output{RST}")
    print(f"      {DIM}├── reports/     findings & reports{RST}")
    print(f"      {DIM}├── screenshots/ gowitness captures{RST}")
    print(f"      {DIM}└── loot/        session database{RST}")
    print(f"\n{B}  Reports:{RST}")
    for label, path in report_paths.items():
        print(f"    {G}{label:<12}{RST} {path}")
    print(f"\n{B}  Finding Summary:{RST}")
    for sev in ["critical", "high", "medium", "low", "info"]:
        count = counts.get(sev, 0)
        if count:
            color = {"critical": R, "high": R, "medium": Y, "low": C, "info": W}.get(sev, W)
            bar   = "█" * min(count, 30)
            print(f"    {color}{sev.upper():<12}{RST} {count:>4}  {color}{bar}{RST}")
    total = sum(counts.values())
    subs  = len(session.subdomains)
    live  = len(session.live_subdomains)
    print(f"\n    {'TOTAL':<12} {total:>4}")
    if subs:
        print(f"\n{B}  Subdomains:{RST}  {G}{subs}{RST} discovered  {G}{live}{RST} live")
    print(f"{G}{B}{'═' * 60}{RST}\n")


def _live_finding_callback(finding) -> None:
    from .core.models import FindingSeverity
    sev_colors = {
        FindingSeverity.CRITICAL: R,
        FindingSeverity.HIGH:     R,
        FindingSeverity.MEDIUM:   Y,
        FindingSeverity.LOW:      C,
        FindingSeverity.INFO:     DIM,
    }
    color = sev_colors.get(finding.severity, W)
    if finding.severity not in (FindingSeverity.INFO,):
        print(
            f"  {color}[{finding.severity.value.upper()}]{RST} "
            f"{finding.plugin}: {finding.title}"
        )


def _load_config_yaml(path: Path) -> dict:
    """Load config.yaml if present; return empty dict on missing/parse error."""
    if not path.exists():
        return {}
    try:
        import yaml
        return yaml.safe_load(path.read_text()) or {}
    except ImportError:
        return {}
    except Exception as e:
        logging.getLogger("z3r0").warning(f"config.yaml parse error: {e}")
        return {}


# ─── Resume helpers ──────────────────────────────────────────────────────────

def cmd_sessions() -> None:
    """List all saved sessions across all targets."""
    from .core.state import StateStore
    from pathlib import Path

    # Walk outputs/ directory for all session.db files
    outputs = Path("outputs")
    if not outputs.exists():
        print("No outputs directory found.")
        return

    dbs = list(outputs.glob("*/loot/session.db"))
    if not dbs:
        print("No sessions found.")
        return

    print(f"\n{B}{'SESSION ID':<38} {'TARGET':<25} {'STARTED':<22} {'STATUS'}{RST}")
    print("-" * 100)

    for db_path in sorted(dbs):
        store = StateStore(db_path)
        for row in store.list_sessions():
            sid      = row["session_id"]
            target   = row["target_host"]
            started  = row["started_at"][:19]
            status   = f"{G}complete{RST}" if row["completed_at"] else f"{Y}incomplete{RST}"
            print(f"  {C}{sid}{RST}  {target:<25} {started}  {status}")
    print()


async def run_scan(
    target_str: str,
    config: ScanConfig,
    concurrency: int,
    plan_only: bool,
    no_confirm: bool,
    verbose: bool,
    operator: str,
    config_file: Path,
) -> None:
    """Main async scan coroutine."""
    if verbose:
        logging.getLogger("z3r0").setLevel(logging.DEBUG)
    else:
        logging.getLogger("z3r0").setLevel(logging.INFO)

    print(BANNER)

    # ── Load config.yaml for API keys / tool paths ────────────────────────────
    yaml_conf = _load_config_yaml(config_file)
    if not config.shodan_key:
        config.shodan_key = yaml_conf.get("api_keys", {}).get("shodan")
    if not config.otx_key:
        config.otx_key = yaml_conf.get("api_keys", {}).get("otx")

    # ── 1. Validate target ────────────────────────────────────────────────────
    try:
        target_str = validate_target(target_str)
    except TargetValidationError as e:
        log("err", f"Invalid target: {e}")
        sys.exit(1)

    # ── 2. Ethics gate ────────────────────────────────────────────────────────
    run_ethics_gate(target_str, interactive=not no_confirm)

    # ── 3. Setup session ──────────────────────────────────────────────────────
    out_dir = Path("outputs") / target_str
    layout  = OutputLayout(out_dir)
    state   = StateStore(layout.session_db)
    target  = ScanTarget(host=target_str)
    session = ScanSession(
        target=target,
        output_dir=str(out_dir),
        operator=operator,
        authorized=True,
        config=config,
    )
    state.save_session(session)
    log("ok", f"Session: {session.session_id[:8]} | Output: {out_dir}")

    # ── 4. Load plugins ───────────────────────────────────────────────────────
    registry = PluginRegistry()
    registry.discover("z3r0_recon.plugins")
    log("info", f"Loaded {len(registry)} plugins | {len(registry.available())} available")

    orchestrator = Orchestrator(
        registry,
        concurrency=concurrency,
        on_finding=_live_finding_callback,
    )

    # ── Phase 0a: OSINT (passive, before any active scanning) ─────────────────
    if config.osint_enabled:
        section("PHASE 0a — PASSIVE OSINT COLLECTION")
        osint_task = TaskRecord(
            plugin="osint_collector",
            target=target, port=None,
            reason="Passive OSINT: OTX, URLScan, Shodan",
        )
        session.tasks = [osint_task]
        await orchestrator.run(session)
        sub_count = len(session.subdomains)
        if sub_count:
            log("ok", f"OSINT added {sub_count} subdomains to scope")

    # ── Phase 0b: Subdomain enumeration ───────────────────────────────────────
    if config.subdomains_enabled:
        section("PHASE 0b — SUBDOMAIN ENUMERATION")
        sub_task = TaskRecord(
            plugin="subdomain_enum",
            target=target, port=None,
            reason="Passive + active subdomain enumeration",
        )
        session.tasks += [sub_task]
        await orchestrator.run(session)
        log("ok", f"Subdomains discovered: {len(session.subdomains)}")

    # ── Phase 0c: Masscan (CIDR mode) ─────────────────────────────────────────
    if config.masscan_enabled and config.cidr:
        section(f"PHASE 0c — MASSCAN RAPID PORT SCAN ({config.cidr})")
        mc_task = TaskRecord(
            plugin="masscan_scan",
            target=target, port=None,
            reason=f"Rapid scan of {config.cidr}",
            params={"cidr": config.cidr, "rate": config.masscan_rate},
        )
        session.tasks += [mc_task]
        await orchestrator.run(session)

    # ── Phase 0d: Cloud enumeration ───────────────────────────────────────────
    if config.cloud_enum_enabled:
        section("PHASE 0d — CLOUD STORAGE ENUMERATION")
        cloud_task = TaskRecord(
            plugin="cloud_enum",
            target=target, port=None,
            reason="AWS S3 / Azure / GCP bucket enumeration",
        )
        session.tasks += [cloud_task]
        await orchestrator.run(session)

    # ── Phase 1: Nmap ─────────────────────────────────────────────────────────
    section("PHASE 1 — NMAP PORT & SERVICE DISCOVERY")
    log("info", f"Target: {B}{target_str}{RST}")

    nmap_task = TaskRecord(
        plugin="nmap",
        target=target, port=None,
        reason="Initial port and service discovery",
    )
    session.tasks += [nmap_task]
    await orchestrator.run(session)
    print_ports(session)

    if not session.open_ports:
        log("warn", "No open ports detected.")
        if not session.subdomains:
            log("warn", "No subdomains either. Saving session and exiting.")
            state.save_session(session)
            sys.exit(0)

    # ── Build follow-on tasks from decision engine ────────────────────────────
    follow_on_tasks = build_task_list(session.open_ports, target)

    # Filter plugins based on config flags
    if not config.nuclei_enabled:
        follow_on_tasks = [t for t in follow_on_tasks if t.plugin != "nuclei"]
    if not config.arjun_enabled:
        follow_on_tasks = [t for t in follow_on_tasks if t.plugin != "arjun"]

    if follow_on_tasks:
        print_plan(follow_on_tasks)

    if plan_only:
        log("info", "--plan-only: exiting without executing.")
        sys.exit(0)

    # ── Phase 2: Service scanning ─────────────────────────────────────────────
    if follow_on_tasks:
        section("PHASE 2 — CONCURRENT SERVICE SCANNING")
        log("info", f"{len(follow_on_tasks)} tasks | {concurrency} workers")

        for t in follow_on_tasks:
            t.status = TaskStatus.PENDING
        session.tasks.extend(follow_on_tasks)
        await orchestrator.run(session)

    # ── Phase 3: HTTPX + screenshots of subdomains ────────────────────────────
    if session.subdomains:
        section("PHASE 3 — HTTPX PROBING + SCREENSHOTS")
        log("info", f"Probing {len(session.subdomains)} subdomains for live hosts")

        httpx_tasks = []

        # One batch httpx task covers all subdomains at once
        httpx_tasks.append(TaskRecord(
            plugin="httpx_probe",
            target=target, port=None,
            reason=f"Probe {len(session.subdomains)} subdomains for live web services",
        ))

        if config.screenshots_enabled:
            httpx_tasks.append(TaskRecord(
                plugin="gowitness",
                target=target, port=None,
                reason="Screenshot live web hosts",
            ))

        for t in httpx_tasks:
            t.status = TaskStatus.PENDING
        session.tasks.extend(httpx_tasks)
        await orchestrator.run(session)

        print_subdomains(session)

    # ── Persist everything ────────────────────────────────────────────────────
    for t in session.tasks:
        state.save_task(t, session.session_id)
        for f in t.findings:
            state.save_finding(f, session.session_id, t.id)
    state.save_session(session)

    # ── Generate reports ──────────────────────────────────────────────────────
    section("GENERATING REPORTS")
    report_paths = generate_reports(session)
    for label, path in report_paths.items():
        log("ok", f"{label} report → {B}{path}{RST}")

    print_summary(session, report_paths)


async def run_resume(
    session_id: str,
    concurrency: int,
    verbose: bool,
) -> None:
    """
    Resume an incomplete scan by session_id.

    Loads the session from its loot/session.db, skips all tasks that
    already have status DONE or SKIPPED, and re-runs everything else.
    The orchestrator already handles this — it only enqueues PENDING tasks.
    So resume = load + re-mark non-finished tasks as PENDING + run.
    """
    if verbose:
        logging.getLogger("z3r0").setLevel(logging.DEBUG)
    else:
        logging.getLogger("z3r0").setLevel(logging.INFO)

    print(BANNER)

    from pathlib import Path
    from .core.state import StateStore
    from .core.output_layout import OutputLayout

    # Find the session db — search outputs/ tree
    outputs = Path("outputs")
    db_path = None
    for candidate in outputs.glob("*/loot/session.db"):
        store_tmp = StateStore(candidate)
        rows = store_tmp.list_sessions()
        if any(r["session_id"] == session_id for r in rows):
            db_path = candidate
            break

    if db_path is None:
        log("err", f"Session {session_id!r} not found in outputs/")
        sys.exit(1)

    state   = StateStore(db_path)
    session = state.load_session(session_id)

    if session is None:
        log("err", f"Could not load session {session_id}")
        sys.exit(1)

    if session.is_complete:
        log("warn", f"Session {session_id[:8]} is already complete.")
        log("info", f"Output dir: {session.output_dir}")
        sys.exit(0)

    # Count incomplete tasks
    incomplete = [
        t for t in session.tasks
        if t.status not in (TaskStatus.DONE, TaskStatus.SKIPPED)
    ]
    log("ok",
        f"Resuming session {session_id[:8]} for target {session.target.host}")
    log("info",
        f"{len(session.tasks)} total tasks | "
        f"{len(incomplete)} pending/failed | "
        f"{len(session.tasks) - len(incomplete)} already done")

    # Re-mark failed tasks as pending so they retry
    for t in session.tasks:
        if t.status == TaskStatus.FAILED:
            t.status = TaskStatus.PENDING
            t.error  = None

    registry = PluginRegistry()
    registry.discover("z3r0_recon.plugins")

    orchestrator = Orchestrator(
        registry,
        concurrency=concurrency,
        on_finding=_live_finding_callback,
    )

    section("RESUMING SCAN")
    await orchestrator.run(session)

    # Persist updated state
    for t in session.tasks:
        state.save_task(t, session.session_id)
        for f in t.findings:
            state.save_finding(f, session.session_id, t.id)
    state.save_session(session)

    report_paths = generate_reports(session)
    for label, path in report_paths.items():
        log("ok", f"{label} report → {B}{path}{RST}")

    print_summary(session, report_paths)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Z3R0 Recon — Authorized penetration testing framework",
        epilog=(
            "Examples:\n"
            "  python3 -m z3r0_recon -t example.com --subdomains --osint\n"
            "  python3 -m z3r0_recon -t 10.10.10.10 --no-nuclei --concurrency 8\n"
            "  python3 -m z3r0_recon -t 10.10.10.0/24 --masscan --masscan-rate 5000\n"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    # ── Core ──────────────────────────────────────────────────────────────────
    parser.add_argument("-t", "--target", default=None,
        help="Target IP, hostname, or CIDR (e.g. 10.10.10.0/24)")
    parser.add_argument("--concurrency", type=int, default=5, metavar="N",
        help="Concurrent scan workers (default: 5)")
    parser.add_argument("--plan-only", action="store_true",
        help="Show scan plan without executing")
    parser.add_argument("--no-confirm", action="store_true",
        help="Skip authorization prompt (lab/automation mode)")
    parser.add_argument("--operator", default="z3r0",
        help="Operator name for report attribution")
    parser.add_argument("-v", "--verbose", action="store_true",
        help="Verbose logging")
    parser.add_argument("--config", default="config.yaml", metavar="PATH",
        help="Path to config.yaml (default: ./config.yaml)")
    parser.add_argument("--resume", metavar="SESSION_ID",
        help="Resume an incomplete scan by session ID")
    parser.add_argument("--sessions", action="store_true",
        help="List all saved sessions and exit")

    # ── Subdomain enumeration ─────────────────────────────────────────────────
    sub_grp = parser.add_argument_group("Subdomain Enumeration")
    sub_grp.add_argument("--subdomains", action="store_true",
        help="Enable subdomain enumeration (subfinder + puredns + dnsgen)")
    sub_grp.add_argument("--wordlist", metavar="PATH",
        help="Wordlist for puredns brute-force")

    # ── Masscan ───────────────────────────────────────────────────────────────
    mc_grp = parser.add_argument_group("Masscan")
    mc_grp.add_argument("--masscan", action="store_true",
        help="Enable masscan rapid port scan")
    mc_grp.add_argument("--masscan-rate", type=int, default=1000, metavar="PPS",
        help="Masscan packets/sec (default: 1000)")
    mc_grp.add_argument("--cidr", metavar="RANGE",
        help="CIDR range for masscan (e.g. 10.10.10.0/24)")

    # ── Web scanning ──────────────────────────────────────────────────────────
    web_grp = parser.add_argument_group("Web Scanning")
    web_grp.add_argument("--no-nuclei", action="store_true",
        help="Disable Nuclei scanning")
    web_grp.add_argument("--nuclei-templates", metavar="PATH",
        help="Custom Nuclei template directory")
    web_grp.add_argument("--no-arjun", action="store_true",
        help="Disable Arjun parameter discovery (enabled by default)")
    web_grp.add_argument("--arjun-wordlist", metavar="PATH",
        help="Custom wordlist for Arjun")

    # ── OSINT ─────────────────────────────────────────────────────────────────
    osint_grp = parser.add_argument_group("OSINT & Passive Recon")
    osint_grp.add_argument("--osint", action="store_true",
        help="Enable OSINT collection (OTX, URLScan, Shodan)")
    osint_grp.add_argument("--shodan-key", metavar="KEY",
        help="Shodan API key (or set in config.yaml)")
    osint_grp.add_argument("--otx-key", metavar="KEY",
        help="AlienVault OTX API key (or set in config.yaml)")

    # ── Screenshots ───────────────────────────────────────────────────────────
    sc_grp = parser.add_argument_group("Screenshots")
    sc_grp.add_argument("--screenshots", action="store_true",
        help="Enable gowitness screenshot capture")

    # ── Cloud ─────────────────────────────────────────────────────────────────
    cloud_grp = parser.add_argument_group("Cloud Enumeration")
    cloud_grp.add_argument("--cloud", action="store_true",
        help="Enable cloud storage enumeration (S3, Azure, GCP)")

    args = parser.parse_args()

    # ── Sessions listing ──────────────────────────────────────────────────────
    if args.sessions:
        cmd_sessions()
        sys.exit(0)

    # ── Resume mode ───────────────────────────────────────────────────────────
    if args.resume:
        try:
            asyncio.run(run_resume(
                session_id  = args.resume,
                concurrency = args.concurrency,
                verbose     = args.verbose,
            ))
        except KeyboardInterrupt:
            print(f"\n{Y}[!] Interrupted.{RST}")
            sys.exit(130)
        sys.exit(0)

    # ── Normal scan requires --target ─────────────────────────────────────────
    if not args.target:
        parser.error("argument -t/--target is required (or use --resume SESSION_ID)")

    # ── Build ScanConfig from args ────────────────────────────────────────────
    config = ScanConfig(
        subdomains_enabled  = args.subdomains,
        wordlist            = args.wordlist,
        masscan_enabled     = args.masscan,
        masscan_rate        = args.masscan_rate,
        cidr                = args.cidr,
        nuclei_enabled      = not args.no_nuclei,
        nuclei_templates    = args.nuclei_templates,
        arjun_enabled       = not args.no_arjun,
        arjun_wordlist      = args.arjun_wordlist,
        osint_enabled       = args.osint,
        shodan_key          = args.shodan_key,
        otx_key             = args.otx_key,
        screenshots_enabled = args.screenshots,
        cloud_enum_enabled  = args.cloud,
    )

    try:
        asyncio.run(run_scan(
            target_str  = args.target,
            config      = config,
            concurrency = args.concurrency,
            plan_only   = args.plan_only,
            no_confirm  = args.no_confirm,
            verbose     = args.verbose,
            operator    = args.operator,
            config_file = Path(args.config),
        ))
    except KeyboardInterrupt:
        print(f"\n{Y}[!] Interrupted. Partial results may be in the output directory.{RST}")
        sys.exit(130)


if __name__ == "__main__":
    main()
