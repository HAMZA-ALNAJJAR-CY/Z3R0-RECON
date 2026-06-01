"""
ethics.py — Authorization gate and target validation.

The ethics gate is a hard requirement, not a checkbox.
It runs before any scan logic executes. It serves two purposes:

1. Remind the operator of their legal obligations — authorization
   is their responsibility, not the tool's.
2. Create an audit trail. The ScanSession.authorized flag is written
   to the database, so you can confirm at report-review time that
   authorization was explicitly acknowledged.

The gate is skipped ONLY in non-interactive mode (--no-confirm flag),
which is intended for lab automation (HTB, TryHackMe pipelines) where
authorization is structurally guaranteed by the environment. It is NOT
a bypass for real engagements.
"""

from __future__ import annotations

import ipaddress
import re
import sys
from typing import Optional


# ─── Ethics Gate ──────────────────────────────────────────────────────────────

BANNER = """
╔══════════════════════════════════════════════════════════════╗
║          Z3R0 RECON FRAMEWORK — AUTHORIZED USE ONLY          ║
╠══════════════════════════════════════════════════════════════╣
║                                                              ║
║  This tool is intended STRICTLY for:                         ║
║    • Authorized penetration testing engagements              ║
║    • Ethical security research with written permission       ║
║    • CTF / HTB / TryHackMe / lab environments                ║
║    • Defensive security assessments you own or are           ║
║      explicitly authorized to assess                         ║
║                                                              ║
║  LEGAL NOTICE:                                               ║
║    Unauthorized scanning is illegal under the Computer       ║
║    Fraud and Abuse Act (CFAA), Computer Misuse Act,          ║
║    and equivalent laws in most jurisdictions.                ║
║                                                              ║
║    You — the operator — are solely responsible for           ║
║    obtaining authorization before scanning any target.       ║
║    This tool provides no authorization and assumes none.     ║
║                                                              ║
╚══════════════════════════════════════════════════════════════╝
"""

OPSEC_WARNINGS = """
[OPSEC] Scan profile notes:
  • nmap -sV -sC produces detectable traffic patterns
  • Nikto, Gobuster, FFUF use identifiable user-agents by default
  • Default scan threads (40) may trigger rate-limiting or IDS alerts
  • searchsploit/CVE lookups may send version strings to external APIs
  • Consider --profile stealth for engagements with active monitoring
"""


def run_ethics_gate(target: str, interactive: bool = True) -> bool:
    """
    Display the authorization warning and require explicit confirmation.

    Returns True if authorized (confirmed or non-interactive).
    Returns False / exits if declined.

    Args:
        target: The target being scanned (shown in confirmation prompt)
        interactive: If False, skip the prompt (lab/automation mode only)
    """
    print(BANNER)

    if not interactive:
        print("[!] Non-interactive mode: authorization gate bypassed.")
        print("[!] Ensure you have explicit authorization before proceeding.\n")
        return True

    print(f"  Target: {target}\n")
    print(OPSEC_WARNINGS)

    try:
        answer = input(
            "  Confirm: Do you have explicit authorization to scan this target?\n"
            "  (yes to proceed, anything else to exit): "
        ).strip().lower()
    except (EOFError, KeyboardInterrupt):
        print("\n[!] Interrupted. Exiting.")
        sys.exit(1)

    if answer in ("yes", "y"):
        print("\n[+] Authorization confirmed. Proceeding with scan.\n")
        return True
    else:
        print("\n[-] Authorization not confirmed. Exiting.")
        print("    Obtain written authorization before scanning targets.\n")
        sys.exit(0)


# ─── Target Validation ────────────────────────────────────────────────────────

# RFC 1123 hostname regex
_HOSTNAME_RE = re.compile(
    r"^(?:[a-zA-Z0-9]"
    r"(?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?"
    r"\.)*"
    r"[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?$"
)

# Loopback / RFC1918 ranges that indicate lab environments
_PRIVATE_RANGES = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
]

# Clearly dangerous targets — catch common mistakes
_BLOCKED_TARGETS = frozenset({
    "google.com", "cloudflare.com", "amazon.com", "microsoft.com",
    "github.com", "facebook.com", "twitter.com", "8.8.8.8",
    "1.1.1.1",
})


class TargetValidationError(ValueError):
    """Raised when a target fails validation."""


def validate_target(target: str) -> str:
    """
    Validate and normalize a scan target.

    Accepts IPv4 addresses and valid hostnames.
    Rejects shell metacharacters, obviously public targets,
    and malformed inputs.

    Returns the normalized target string.
    Raises TargetValidationError on invalid input.
    """
    target = target.strip()

    if not target:
        raise TargetValidationError("Target cannot be empty.")

    # Shell injection guard — these characters have no place in a hostname/IP
    dangerous_chars = set(";&|`$(){}\\'\"\n\r\t <>")
    if any(c in dangerous_chars for c in target):
        raise TargetValidationError(
            f"Target contains illegal characters: {target!r}"
        )

    if len(target) > 253:
        raise TargetValidationError("Target exceeds maximum hostname length (253).")

    # Normalize: strip trailing dot
    normalized = target.rstrip(".")

    # Check against obviously public/blocked targets
    if normalized.lower() in _BLOCKED_TARGETS:
        raise TargetValidationError(
            f"Target '{normalized}' is on the blocked list. "
            "Only scan targets you own or have explicit authorization for."
        )

    # Try parsing as IP address
    try:
        addr = ipaddress.ip_address(normalized)
        # Warn (not block) on public IPs — operator confirmed via ethics gate
        return normalized
    except ValueError:
        pass

    # Try as hostname
    if _HOSTNAME_RE.match(normalized):
        return normalized

    raise TargetValidationError(
        f"'{target}' is not a valid IPv4 address or hostname."
    )


def is_private_target(target: str) -> bool:
    """Return True if target is a private/loopback IP (lab indicator)."""
    try:
        addr = ipaddress.ip_address(target)
        return any(addr in net for net in _PRIVATE_RANGES)
    except ValueError:
        return False


def safe_filename(target: str) -> str:
    """Convert a target string to a safe filesystem name component."""
    return re.sub(r"[^\w\-]", "_", target)
