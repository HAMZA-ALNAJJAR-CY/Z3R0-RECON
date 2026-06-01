# Z3R0 Recon Framework

> **Authorized use only.** This tool is for professional penetration testing,
> bug bounty research, and CTF/lab environments with explicit authorization.
> Unauthorized scanning is illegal. You are responsible for obtaining written
> permission before scanning any target.

A production-grade automated reconnaissance framework for professional bug
bounty and penetration testing workflows. Built around a plugin architecture
with async concurrent execution, structured findings, and multi-format reporting.

---

## Features

| Phase | What it does | Tools used |
|-------|-------------|-----------|
| 0a — OSINT | Passive intelligence gathering | OTX, URLScan.io, Shodan |
| 0b — Subdomains | Passive + active subdomain enumeration | subfinder, puredns, dnsgen |
| 0c — Masscan | Rapid port scanning of CIDR ranges | masscan |
| 0d — Cloud | S3, Azure, GCP bucket enumeration | s3scanner, aiohttp |
| 1 — Ports | Service + version detection | nmap |
| 2 — Web | Vuln scan, dir brute, fuzzing, WAF, tech | nuclei, gobuster, ffuf, nikto, whatweb, wafw00f |
| 2 — Params | Hidden parameter discovery | arjun |
| 2 — Services | SMB, FTP, SSH, DBs, SNMP | enum4linux, nmap NSE |
| 2 — CVEs | Exploit + CVE lookup | searchsploit, circl.lu |
| 3 — Probing | Live host confirmation + screenshots | httpx, gowitness |
| Reports | Markdown, JSON, interactive HTML | built-in |

---

## Quick Start

```bash
# Basic scan (ports + services + web scanning)
python3 -m z3r0_recon -t 10.10.10.10

# Full bug bounty workflow
python3 -m z3r0_recon -t example.com \
  --subdomains \
  --osint \
  --screenshots \
  --cloud \
  --arjun \
  --concurrency 10

# Lab/CTF (skip authorization prompt)
python3 -m z3r0_recon -t 10.10.10.10 --no-confirm

# CIDR range with masscan
python3 -m z3r0_recon -t 10.10.10.1 --masscan --cidr 10.10.10.0/24 --masscan-rate 5000

# Preview scan plan without executing
python3 -m z3r0_recon -t 10.10.10.10 --plan-only
```

---

## Installation

### 1. Python setup

```bash
git clone https://github.com/yourname/z3r0-recon
cd z3r0-recon
pip install -r requirements.txt
pip install -e .
```

### 2. External tools

All tools below are optional — the framework degrades gracefully when
any binary is missing. Install only what you need.

#### Package manager (Kali / Debian)

```bash
sudo apt update && sudo apt install -y \
  nmap masscan nikto gobuster ffuf \
  enum4linux smbclient ldap-utils snmp \
  searchsploit
```

#### Go tools (install Go first: https://go.dev/dl/)

```bash
# Add Go binaries to PATH
export PATH=$PATH:$(go env GOPATH)/bin
echo 'export PATH=$PATH:$(go env GOPATH)/bin' >> ~/.bashrc

# ProjectDiscovery suite
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest

# Other Go tools
go install -v github.com/d3mondev/puredns/v2@latest
go install -v github.com/ffuf/ffuf/v2@latest
go install github.com/sensepost/gowitness@latest
go install github.com/OJ/gobuster/v3@latest
go install github.com/sa7mon/s3scanner@latest
```

#### Python tools

```bash
pip install arjun dnsgen
```

#### massdns (puredns dependency)

```bash
sudo apt install massdns
# or build from source:
git clone https://github.com/blechschmidt/massdns
cd massdns && make && sudo cp bin/massdns /usr/local/bin/
```

#### Update Nuclei templates

```bash
nuclei -update-templates
```

#### Verify installation

```bash
python3 -m z3r0_recon --help
```

### 3. Configuration

```bash
cp config.yaml.example config.yaml
# Edit config.yaml to add API keys
```

Add to `.gitignore`:
```
config.yaml
outputs/
```

#### Subfinder API keys (optional but recommended)

Create `~/.config/subfinder/provider-config.yaml`:
```yaml
securitytrails:
  - YOUR_SECURITYTRAILS_KEY
shodan:
  - YOUR_SHODAN_KEY
censysid:
  - YOUR_CENSYS_ID
censyssecret:
  - YOUR_CENSYS_SECRET
```

---

## CLI Reference

```
usage: python3 -m z3r0_recon -t TARGET [options]

Core:
  -t TARGET             Target IP, hostname, or CIDR
  --concurrency N       Concurrent workers (default: 5)
  --plan-only           Show scan plan, don't execute
  --no-confirm          Skip authorization prompt (lab mode)
  --operator NAME       Operator name for reports
  --config PATH         Path to config.yaml (default: ./config.yaml)
  -v, --verbose         Verbose logging

Subdomain Enumeration:
  --subdomains          Enable (subfinder + puredns + dnsgen)
  --wordlist PATH       Brute-force wordlist for puredns

Masscan:
  --masscan             Enable masscan rapid scan
  --masscan-rate PPS    Packets/sec (default: 1000)
  --cidr RANGE          CIDR range (e.g. 10.10.10.0/24)

Web Scanning:
  --no-nuclei           Disable Nuclei
  --nuclei-templates P  Custom Nuclei template directory
  --arjun               Enable Arjun parameter discovery
  --arjun-wordlist PATH Custom Arjun wordlist

OSINT & Passive Recon:
  --osint               Enable OTX + URLScan + Shodan
  --shodan-key KEY      Shodan API key
  --otx-key KEY         AlienVault OTX API key

Screenshots:
  --screenshots         Enable gowitness screenshots

Cloud Enumeration:
  --cloud               Enable S3 / Azure / GCP bucket enumeration
```

---

## Output Structure

```
outputs/
└── <target>/
    ├── recon/
    │   ├── nmap/           scan.xml, scan.txt
    │   ├── subdomains/     subfinder.txt, puredns.txt, resolved.txt
    │   ├── masscan/        results.json, open_ports.txt
    │   ├── web/
    │   │   ├── 80/         nikto/, gobuster/, ffuf/, nuclei/, arjun/, whatweb/, wafw00f/
    │   │   └── 443/        (same structure)
    │   ├── ssh/            ssh_audit.txt, cve_lookup.txt
    │   ├── smb/            enum4linux.txt
    │   ├── db/             mysql/, mssql/, redis/, mongo/
    │   ├── osint/          otx.json, urlscan.json, shodan.json
    │   ├── cloud/          s3_buckets.txt, azure.txt, gcp.txt
    │   └── httpx/          results.json
    ├── screenshots/        gowitness PNG captures
    ├── reports/
    │   ├── RECON_REPORT.md   human-readable markdown
    │   ├── findings.json     machine-readable (CI/CD friendly)
    │   └── report.html       interactive sortable/filterable HTML
    └── loot/
        └── session.db        SQLite (resumable scans, cross-run queries)
```

---

## Writing a Custom Plugin

Drop a `.py` file in `z3r0_recon/plugins/` — it's auto-discovered:

```python
from z3r0_recon.core import ReconPlugin, PluginMeta, Finding, FindingSeverity

class MyPlugin(ReconPlugin):
    meta = PluginMeta(
        name="my_plugin",
        description="Does something useful",
        triggers_on_ports=frozenset({1234}),
        requires_binary="mytool",
        default_timeout=60,
    )

    async def execute(self, task, session):
        stdout, stderr, rc = await self.run_subprocess(
            ["mytool", "-t", str(task.target)],
            timeout=self.meta.default_timeout,
        )
        # Parse stdout, return Finding objects
        return [Finding(
            plugin=self.meta.name,
            title="My finding",
            severity=FindingSeverity.MEDIUM,
            target=str(task.target),
            port=task.port,
            description=stdout[:500],
        )]
```

---

## Ethics & Legal

- Only scan targets you own or have **explicit written authorization** to test.
- The framework displays an authorization confirmation prompt on every run.
- Use `--no-confirm` only in lab environments (HTB, TryHackMe, your own infra).
- Unauthorized scanning violates the Computer Fraud and Abuse Act (CFAA),
  Computer Misuse Act, and equivalent laws in most jurisdictions.
- The authors accept no liability for misuse.

---

## Architecture

```
CLI (cli.py)
 └─ ScanSession + ScanConfig
     ├─ PluginRegistry  (auto-discovers all plugins/)
     ├─ Orchestrator    (asyncio worker pool, N concurrent tasks)
     │   └─ ReconPlugin.execute() → List[Finding]
     ├─ DecisionEngine  (open ports → TaskRecord list)
     ├─ OutputLayout    (all file paths in one place)
     ├─ StateStore      (SQLite persistence, resumable runs)
     └─ ReportEngine    (markdown + JSON + HTML)
```
