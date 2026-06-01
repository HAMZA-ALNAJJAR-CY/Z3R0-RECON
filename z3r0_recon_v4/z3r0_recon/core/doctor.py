"""
core/doctor.py — Framework health-check command.

Invoked via: python3 -m z3r0_recon doctor

Checks all external tool dependencies against PATH using shutil.which —
the same mechanism the plugin registry uses for is_available(). No
duplicate validation logic; we reuse PluginMeta.requires_binary where
possible and supplement with a hardcoded list for tools not yet covered
by a plugin (e.g. masscan, puredns, dnsgen).
"""

from __future__ import annotations

import shutil
import sys

# ─── Tool inventory ───────────────────────────────────────────────────────────
#
# Each entry: (binary_name, description, install_hint)
# Grouped by category for readability in output.

_TOOLS: list[tuple[str, str, str, str]] = [
    # category, binary, description, install hint
    ("Core",     "nmap",          "Port scanning",                  "apt install nmap"),
    ("Core",     "searchsploit",  "Exploit/CVE lookup",             "apt install exploitdb"),
    ("Web",      "nikto",         "Web vulnerability scanner",      "apt install nikto"),
    ("Web",      "gobuster",      "Directory brute-forcing",        "apt install gobuster"),
    ("Web",      "ffuf",          "Web fuzzing",                    "go install github.com/ffuf/ffuf/v2@latest"),
    ("Web",      "whatweb",       "Technology fingerprinting",      "apt install whatweb"),
    ("Web",      "wafw00f",       "WAF detection",                  "pip install wafw00f"),
    ("Web",      "nuclei",        "Template-based vuln scanning",   "go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"),
    ("Web",      "arjun",         "Parameter discovery",            "pip install arjun"),
    ("Services", "enum4linux",    "SMB/NetBIOS enumeration",        "apt install enum4linux"),
    ("Recon",    "subfinder",     "Passive subdomain enumeration",  "go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"),
    ("Recon",    "httpx",         "HTTP probing",                   "go install github.com/projectdiscovery/httpx/cmd/httpx@latest"),
    ("Recon",    "puredns",       "Active DNS brute-force",         "go install github.com/d3mondev/puredns/v2@latest"),
    ("Recon",    "massdns",       "DNS resolver (puredns dep)",     "apt install massdns"),
    ("Recon",    "dnsgen",        "Subdomain permutations",         "pip install dnsgen"),
    ("Recon",    "masscan",       "Rapid port scanning",            "apt install masscan"),
    ("Recon",    "gowitness",     "Web screenshots",                "go install github.com/sensepost/gowitness@latest"),
    ("Recon",    "s3scanner",     "AWS S3 bucket enumeration",      "go install github.com/sa7mon/s3scanner@latest"),
]

# ANSI colors — same constants as cli.py, defined locally to avoid circular import
_G   = "\033[92m"
_R   = "\033[91m"
_Y   = "\033[93m"
_C   = "\033[96m"
_DIM = "\033[2m"
_B   = "\033[1m"
_RST = "\033[0m"


def run_doctor() -> int:
    """
    Print tool availability and return exit code:
      0  — all tools present
      1  — one or more tools missing (non-fatal; tools are optional)
    """
    print(f"\n{_B}{_C}Z3R0 Recon — Dependency Check{_RST}\n")

    current_category = ""
    missing: list[tuple[str, str]] = []
    installed: list[str] = []

    for category, binary, description, hint in _TOOLS:
        if category != current_category:
            current_category = category
            print(f"{_Y}{_B}  {category}{_RST}")

        found = shutil.which(binary) is not None
        if found:
            path = shutil.which(binary)
            print(f"    {_G}✓{_RST}  {binary:<16} {_DIM}{description}{_RST}")
            installed.append(binary)
        else:
            print(f"    {_R}✗{_RST}  {binary:<16} {_DIM}{description}{_RST}")
            missing.append((binary, hint))

    # Summary
    print(f"\n{_B}  Summary:{_RST}")
    print(f"    {_G}Installed:{_RST} {len(installed)}/{len(_TOOLS)}")

    if missing:
        print(f"    {_R}Missing:  {len(missing)}/{len(_TOOLS)}{_RST}\n")
        print(f"{_Y}  Install missing tools:{_RST}")
        for binary, hint in missing:
            print(f"    {_DIM}{binary:<16}{_RST} {hint}")
        print()
        return 1

    print(f"\n  {_G}All tools are installed. Framework is ready.{_RST}\n")
    return 0
