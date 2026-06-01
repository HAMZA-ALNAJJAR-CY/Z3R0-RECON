# Z3R0 Recon Framework

```
╔══════════════════════════════════════════════════════════════╗
║   ███████╗███████╗██████╗  ██████╗     ██████╗ ███████╗      ║
║   ╚══███╔╝██╔════╝██╔══██╗██╔═══██╗    ██╔══██╗██╔════╝      ║
║     ███╔╝ █████╗  ██████╔╝██║   ██║    ██████╔╝█████╗        ║
║    ███╔╝  ██╔══╝  ██╔══██╗██║   ██║    ██╔══██╗██╔══╝        ║
║   ███████╗███████╗██║  ██║╚██████╔╝    ██║  ██║███████╗      ║
║   ╚══════╝╚══════╝╚═╝  ╚═╝ ╚═════╝     ╚═╝  ╚═╝╚══════╝      ║
║              Intelligent Auto-Recon — Authorized Use Only    ║
╚══════════════════════════════════════════════════════════════╝
```

> **Authorized penetration testing only.** Unauthorized scanning is illegal.

---

## Table of Contents

- [What is Z3R0 Recon?](#what-is-z3r0-recon)
- [Features](#features)
- [How It Works](#how-it-works)
- [Installation](#installation)
- [Usage](#usage)
- [Configuration](#configuration)
- [Output Structure](#output-structure)
- [Disclaimer](#disclaimer)
- [Conclusion](#conclusion)

---

## What is Z3R0 Recon?

**Z3R0 Recon** is an intelligent, automated reconnaissance framework designed for authorized penetration testing engagements, CTF competitions, and security research. It chains together industry-standard tools into a single, cohesive pipeline — removing the manual overhead of running, parsing, and correlating outputs from multiple tools.

Instead of manually running nmap, then nuclei, then gobuster, then nikto one by one, Z3R0 Recon orchestrates all of them automatically. A built-in **decision engine** analyzes open ports and services to determine exactly which follow-on scans make sense, then executes them concurrently.

### Key Characteristics

- **Plugin-based architecture** — each tool (nmap, nuclei, gobuster, etc.) is a self-contained plugin
- **Async concurrent execution** — multiple service scans run in parallel for speed
- **Ethics gate** — requires explicit authorization confirmation before any scan begins
- **Session persistence** — scans are saved to SQLite; interrupted sessions can be resumed
- **Automatic reporting** — generates Markdown, JSON, and HTML reports on completion

---

## Features

| Category | Capabilities |
|---|---|
| **Port Scanning** | Nmap service/version detection, Masscan rapid CIDR sweep |
| **Web Scanning** | Nikto, Gobuster, FFUF, WhatWeb, WafW00f, Nuclei |
| **Subdomain Enum** | Subfinder, PureDNS brute-force, DNSGen permutations |
| **OSINT / Passive** | AlienVault OTX, URLScan.io, Shodan |
| **Parameter Discovery** | Arjun parameter fuzzing on web endpoints |
| **Cloud Enum** | AWS S3, Azure Blob, GCP bucket enumeration |
| **HTTPX Probing** | Live subdomain detection with status codes |
| **Screenshots** | Gowitness captures for live web hosts |
| **Reporting** | Markdown + JSON + HTML reports with severity breakdown |
| **Resume** | Interrupted scans can be resumed by session ID |

---

## How It Works

Z3R0 Recon follows a structured multi-phase execution pipeline:

```
Phase 0a  →  Passive OSINT (OTX, URLScan, Shodan)
Phase 0b  →  Subdomain Enumeration (subfinder + puredns + dnsgen)
Phase 0c  →  Masscan rapid port scan (CIDR mode)
Phase 0d  →  Cloud storage enumeration (S3 / Azure / GCP)
Phase 1   →  Nmap port & service discovery
            ↓  Decision Engine analyzes results
Phase 2   →  Concurrent service scanning (web, SMB, FTP, SQL, LDAP, ...)
Phase 3   →  HTTPX probing + Gowitness screenshots (if subdomains found)
            ↓
          →  Report generation (Markdown, JSON, HTML)
```

The **decision engine** (`core/decision.py`) maps open ports to the right tools automatically — detecting HTTP/HTTPS runs web plugins, SMB ports trigger enum4linux, MSSQL triggers service enumeration, and so on.

---

## Installation

### Requirements

- Python 3.10+
- Linux / macOS (Kali Linux recommended)
- External tools installed and on `$PATH` (see below)

### Step 1 — Clone the repository

```bash
git clone https://github.com/YOUR_USERNAME/z3r0-recon.git
cd z3r0-recon
```

### Step 2 — Install Python dependencies

```bash
pip install -r requirements.txt
```

Or install as a package:

```bash
pip install -e .
```

### Step 3 — Install external tools

Z3R0 Recon orchestrates external binaries. Install the ones you need:

```bash
# Core
sudo apt install nmap masscan nikto gobuster enum4linux

# Go-based tools
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
go install -v github.com/ffuf/ffuf/v2@latest
go install -v github.com/d3mondev/puredns/v2@latest
go install -v github.com/sensepost/gowitness@latest

# Python-based
pip install arjun dnsgen

# Update nuclei templates
nuclei -update-templates
```

### Step 4 — Configure (optional)

```bash
cp config.yaml.example config.yaml
# Edit config.yaml to add API keys and custom wordlist paths
```

---

## Usage

### Basic scan

```bash
python3 -m z3r0_recon -t 10.10.10.10
```

### Full scan with all modules

```bash
python3 -m z3r0_recon -t example.com --subdomains --osint --screenshots --cloud
```

### CIDR range sweep with Masscan

```bash
python3 -m z3r0_recon -t 10.10.10.1 --masscan --cidr 10.10.10.0/24 --masscan-rate 5000
```

### Preview the scan plan without executing

```bash
python3 -m z3r0_recon -t 10.10.10.10 --plan-only
```

### Skip authorization prompt (lab/CTF/automation mode)

```bash
python3 -m z3r0_recon -t 10.10.10.10 --no-confirm
```

### List saved sessions

```bash
python3 -m z3r0_recon --sessions
```

### Resume an interrupted scan

```bash
python3 -m z3r0_recon --resume <SESSION_ID>
```

### All available flags

| Flag | Description |
|---|---|
| `-t / --target` | Target IP, hostname, or CIDR |
| `--concurrency N` | Number of concurrent scan workers (default: 5) |
| `--plan-only` | Show scan plan without executing |
| `--no-confirm` | Skip authorization prompt (lab/automation mode) |
| `--operator NAME` | Operator name for report attribution |
| `-v / --verbose` | Enable verbose logging |
| `--config PATH` | Path to config.yaml (default: `./config.yaml`) |
| `--resume SESSION_ID` | Resume an incomplete scan |
| `--sessions` | List all saved sessions |
| `--subdomains` | Enable subdomain enumeration |
| `--wordlist PATH` | Custom wordlist for puredns brute-force |
| `--masscan` | Enable masscan rapid port scan |
| `--masscan-rate PPS` | Masscan packets/sec (default: 1000) |
| `--cidr RANGE` | CIDR range for masscan |
| `--no-nuclei` | Disable Nuclei scanning |
| `--nuclei-templates PATH` | Custom Nuclei template directory |
| `--no-arjun` | Disable Arjun parameter discovery |
| `--osint` | Enable OSINT collection (OTX, URLScan, Shodan) |
| `--shodan-key KEY` | Shodan API key |
| `--otx-key KEY` | AlienVault OTX API key |
| `--screenshots` | Enable Gowitness screenshot capture |
| `--cloud` | Enable cloud storage enumeration |

---

## Configuration

Copy `config.yaml.example` to `config.yaml` and fill in your values:

```yaml
api_keys:
  shodan: "YOUR_SHODAN_KEY"
  otx: "YOUR_OTX_KEY"

tools:
  nmap: ""        # Leave blank to use $PATH
  nuclei: ""
  subfinder: ""
  # ... etc

wordlists:
  subdomains: "/opt/SecLists/Discovery/DNS/subdomains-top1million-5000.txt"
  web_content: "/opt/SecLists/Discovery/Web-Content/common.txt"

scan:
  nmap_timing: "T4"
  masscan_rate: 1000
  concurrency: 5
  nuclei_severity: "critical,high,medium,low"
```

> **Never commit `config.yaml` to version control** — it contains API keys. Add it to `.gitignore`.

---

## Output Structure

Each scan creates a timestamped directory under `outputs/`:

```
outputs/<target>/
├── recon/          # Raw tool output (nmap XML, gobuster txt, nuclei JSON, ...)
├── reports/        # Generated reports
│   ├── report.md
│   ├── report.json
│   └── report.html
├── screenshots/    # Gowitness captures
└── loot/
    └── session.db  # SQLite session database (resumable)
```

---

## Disclaimer

> **This tool is intended strictly for:**
> - Authorized penetration testing engagements with written permission
> - Ethical security research on systems you own
> - CTF / HackTheBox / TryHackMe / lab environments
> - Defensive security assessments you are explicitly authorized to perform

**Unauthorized scanning is illegal** under the Computer Fraud and Abuse Act (CFAA), the Computer Misuse Act, and equivalent laws in most jurisdictions.

The author(s) of this tool assume **no liability** and are **not responsible** for any misuse, damage, or legal consequences arising from unauthorized or malicious use of this software.

**You — the operator — are solely responsible for obtaining explicit authorization before scanning any target.**

---

## Conclusion

Z3R0 Recon was built to eliminate the repetitive, manual work of chaining recon tools during authorized assessments. Whether you're working through a HackTheBox machine, a CTF lab, or a real-world pentest engagement, it gives you a structured, reproducible, and well-documented recon pipeline in a single command.

The framework is designed to be extended — adding a new tool means writing a plugin, not touching the core. Sessions are persisted so no work is lost if something crashes. Reports are generated automatically so you can focus on exploitation, not formatting.

**Scan responsibly. Hack ethically.**

---

*Built for the security community — use it to learn, defend, and test with permission.*
