"""
core/output_layout.py — Centralized output path management.

Single source of truth for every file and directory the framework writes.
Plugins call methods here instead of constructing paths inline.

Target layout:
    outputs/<target>/
    ├── recon/
    │   ├── nmap/
    │   │   ├── scan.txt
    │   │   └── scan.xml
    │   ├── web/
    │   │   ├── ffuf/        results.json
    │   │   ├── gobuster/    results.txt
    │   │   ├── nikto/       results.txt
    │   │   ├── wafw00f/     results.txt
    │   │   └── whatweb/     results.txt
    │   ├── ssh/
    │   │   ├── ssh_audit.txt
    │   │   └── cve_lookup.txt
    │   ├── smb/
    │   │   └── enum4linux.txt
    │   ├── ftp/
    │   │   └── ftp_anon.txt
    │   ├── db/
    │   │   ├── mysql/       results.txt
    │   │   ├── mssql/       results.txt
    │   │   ├── redis/       results.txt
    │   │   ├── mongo/       results.txt
    │   │   └── <service>/   cve_lookup.txt
    │   └── snmp/
    │       └── results.txt
    ├── reports/
    │   ├── RECON_REPORT.md
    │   └── findings.json
    └── loot/
        └── session.db

Design rules:
- Every property/method returns a Path, never a string.
- Every directory is created on first access (mkdir is cheap; missing dirs break tools).
- Web plugins serving multiple ports write to port-specific subdirectories so
  concurrent runs against ports 80 and 8080 do not overwrite each other.
- No logic lives here beyond path construction and mkdir. Parsing, subprocess
  calls, and findings are the caller's responsibility.
"""

from __future__ import annotations

from pathlib import Path


class OutputLayout:
    """
    Resolves all output paths for a single scan session.

    Instantiate once in cli.py with the root output directory,
    then pass to each plugin via session.output_dir (the root)
    plus direct calls to layout.<property>.

    Alternatively, plugins can reconstruct the layout from
    session.output_dir:
        layout = OutputLayout(session.output_dir)

    This is intentionally cheap — no I/O in __init__.
    """

    def __init__(self, root: str | Path) -> None:
        self.root = Path(root)

    # ── Top-level directories ──────────────────────────────────────────────────

    @property
    def recon_dir(self) -> Path:
        return self._ensure(self.root / "recon")

    @property
    def reports_dir(self) -> Path:
        return self._ensure(self.root / "reports")

    @property
    def loot_dir(self) -> Path:
        return self._ensure(self.root / "loot")

    # ── Nmap ──────────────────────────────────────────────────────────────────

    @property
    def nmap_dir(self) -> Path:
        return self._ensure(self.recon_dir / "nmap")

    @property
    def nmap_txt(self) -> Path:
        return self.nmap_dir / "scan.txt"

    @property
    def nmap_xml(self) -> Path:
        return self.nmap_dir / "scan.xml"

    # ── Web tools (per-port subdirectory) ─────────────────────────────────────
    #
    # Web plugins can run against multiple ports (80, 443, 8080, …).
    # Each port gets its own subdirectory to prevent concurrent writes
    # from clobbering each other.
    #
    # e.g. recon/web/80/nikto/results.txt
    #      recon/web/443/gobuster/results.txt

    def web_dir(self, port: int) -> Path:
        return self._ensure(self.recon_dir / "web" / str(port))

    def nikto_result(self, port: int) -> Path:
        return self._ensure(self.web_dir(port) / "nikto") / "results.txt"

    def gobuster_result(self, port: int) -> Path:
        return self._ensure(self.web_dir(port) / "gobuster") / "results.txt"

    def ffuf_result(self, port: int) -> Path:
        return self._ensure(self.web_dir(port) / "ffuf") / "results.json"

    def whatweb_result(self, port: int) -> Path:
        return self._ensure(self.web_dir(port) / "whatweb") / "results.txt"

    def wafw00f_result(self, port: int) -> Path:
        return self._ensure(self.web_dir(port) / "wafw00f") / "results.txt"

    # ── SSH ───────────────────────────────────────────────────────────────────

    @property
    def ssh_dir(self) -> Path:
        return self._ensure(self.recon_dir / "ssh")

    @property
    def ssh_audit_result(self) -> Path:
        return self.ssh_dir / "ssh_audit.txt"

    @property
    def ssh_cve_result(self) -> Path:
        return self.ssh_dir / "cve_lookup.txt"

    # ── SMB ───────────────────────────────────────────────────────────────────

    @property
    def smb_dir(self) -> Path:
        return self._ensure(self.recon_dir / "smb")

    @property
    def enum4linux_result(self) -> Path:
        return self.smb_dir / "enum4linux.txt"

    # ── FTP ───────────────────────────────────────────────────────────────────

    @property
    def ftp_dir(self) -> Path:
        return self._ensure(self.recon_dir / "ftp")

    @property
    def ftp_anon_result(self) -> Path:
        return self.ftp_dir / "ftp_anon.txt"

    # ── Databases ─────────────────────────────────────────────────────────────

    def db_dir(self, service: str) -> Path:
        """e.g. db_dir("mysql") → recon/db/mysql/"""
        return self._ensure(self.recon_dir / "db" / service)

    def db_result(self, service: str) -> Path:
        return self.db_dir(service) / "results.txt"

    def db_cve_result(self, service: str) -> Path:
        return self.db_dir(service) / "cve_lookup.txt"

    # ── SNMP ──────────────────────────────────────────────────────────────────

    @property
    def snmp_dir(self) -> Path:
        return self._ensure(self.recon_dir / "snmp")

    @property
    def snmp_result(self) -> Path:
        return self.snmp_dir / "results.txt"

    # ── Reports ───────────────────────────────────────────────────────────────

    @property
    def markdown_report(self) -> Path:
        return self.reports_dir / "RECON_REPORT.md"

    @property
    def json_report(self) -> Path:
        return self.reports_dir / "findings.json"

    # ── Subdomain enumeration ─────────────────────────────────────────────────

    @property
    def subdomains_dir(self) -> Path:
        return self._ensure(self.recon_dir / "subdomains")

    @property
    def subfinder_result(self) -> Path:
        return self.subdomains_dir / "subfinder.txt"

    @property
    def puredns_result(self) -> Path:
        return self.subdomains_dir / "puredns.txt"

    @property
    def dnsgen_result(self) -> Path:
        return self.subdomains_dir / "dnsgen.txt"

    @property
    def subdomains_resolved(self) -> Path:
        """Final deduplicated resolved subdomain list."""
        return self.subdomains_dir / "resolved.txt"

    # ── Masscan ───────────────────────────────────────────────────────────────

    @property
    def masscan_dir(self) -> Path:
        return self._ensure(self.recon_dir / "masscan")

    @property
    def masscan_result(self) -> Path:
        return self.masscan_dir / "results.json"

    @property
    def masscan_open_ports(self) -> Path:
        return self.masscan_dir / "open_ports.txt"

    # ── Nuclei ────────────────────────────────────────────────────────────────

    def nuclei_dir(self, port: int) -> Path:
        return self._ensure(self.web_dir(port) / "nuclei")

    def nuclei_result(self, port: int) -> Path:
        return self.nuclei_dir(port) / "results.json"

    # ── HTTPX probing ─────────────────────────────────────────────────────────

    @property
    def httpx_dir(self) -> Path:
        return self._ensure(self.recon_dir / "httpx")

    @property
    def httpx_result(self) -> Path:
        return self.httpx_dir / "results.json"

    # ── Screenshots ───────────────────────────────────────────────────────────

    @property
    def screenshots_dir(self) -> Path:
        return self._ensure(self.root / "screenshots")

    # ── Arjun ─────────────────────────────────────────────────────────────────

    def arjun_result(self, port: int) -> Path:
        return self._ensure(self.web_dir(port) / "arjun") / "params.json"

    # ── OSINT ─────────────────────────────────────────────────────────────────

    @property
    def osint_dir(self) -> Path:
        return self._ensure(self.recon_dir / "osint")

    @property
    def otx_result(self) -> Path:
        return self.osint_dir / "otx.json"

    @property
    def urlscan_result(self) -> Path:
        return self.osint_dir / "urlscan.json"

    @property
    def shodan_result(self) -> Path:
        return self.osint_dir / "shodan.json"

    # ── Cloud enumeration ─────────────────────────────────────────────────────

    @property
    def cloud_dir(self) -> Path:
        return self._ensure(self.recon_dir / "cloud")

    @property
    def s3_result(self) -> Path:
        return self.cloud_dir / "s3_buckets.txt"

    @property
    def azure_result(self) -> Path:
        return self.cloud_dir / "azure.txt"

    @property
    def gcp_result(self) -> Path:
        return self.cloud_dir / "gcp.txt"

    # ── HTML report ───────────────────────────────────────────────────────────

    @property
    def html_report(self) -> Path:
        return self.reports_dir / "report.html"

    # ── Loot / session state ──────────────────────────────────────────────────

    @property
    def session_db(self) -> Path:
        return self.loot_dir / "session.db"

    # ── CVE lookup: generic fallback ──────────────────────────────────────────

    def cve_result(self, port: int, service: str) -> Path:
        safe_service = service.replace(" ", "_").replace("/", "_") or "unknown"
        return self._ensure(self.recon_dir / "cve") / f"port_{port}_{safe_service}.txt"

    # ── Internal helper ───────────────────────────────────────────────────────

    @staticmethod
    def _ensure(path: Path) -> Path:
        """Create directory if it does not exist, return the Path."""
        path.mkdir(parents=True, exist_ok=True)
        return path

    # ── Convenience constructor ───────────────────────────────────────────────

    @classmethod
    def from_session(cls, session) -> "OutputLayout":
        """Construct from a ScanSession without importing ScanSession here."""
        return cls(session.output_dir)
