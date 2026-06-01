"""
tests/test_nmap_parser.py — Unit tests for the Nmap XML parser.

Tests _parse_xml() directly — no subprocess, no filesystem I/O
beyond reading the fixture file. Validates:
  - Port discovery
  - Service metadata extraction
  - High-risk service detection (telnet)
  - OS detection findings
  - NSE script output findings
"""

import pytest
from pathlib import Path


@pytest.fixture
def nmap_plugin():
    from z3r0_recon.plugins.nmap import NmapPlugin
    return NmapPlugin()


@pytest.fixture
def nmap_xml(fixture_dir):
    return str(fixture_dir / "nmap_scan.xml")


def test_parses_open_ports(nmap_plugin, nmap_xml):
    ports, findings = nmap_plugin._parse_xml(nmap_xml, "10.10.10.10")
    port_numbers = [p.port for p in ports]
    assert 22 in port_numbers
    assert 80 in port_numbers
    assert 23 in port_numbers


def test_port_service_metadata(nmap_plugin, nmap_xml):
    ports, _ = nmap_plugin._parse_xml(nmap_xml, "10.10.10.10")
    ssh = next(p for p in ports if p.port == 22)
    assert ssh.service == "ssh"
    assert ssh.product == "OpenSSH"
    assert ssh.version == "7.4"
    assert ssh.has_version_info is True


def test_produces_info_finding_per_port(nmap_plugin, nmap_xml):
    from z3r0_recon.core.models import FindingSeverity
    ports, findings = nmap_plugin._parse_xml(nmap_xml, "10.10.10.10")
    port_findings = [
        f for f in findings
        if f.severity == FindingSeverity.INFO and "Open port" in f.title
    ]
    assert len(port_findings) == len(ports)


def test_detects_telnet_as_high_risk(nmap_plugin, nmap_xml):
    from z3r0_recon.core.models import FindingSeverity
    _, findings = nmap_plugin._parse_xml(nmap_xml, "10.10.10.10")
    telnet_findings = [
        f for f in findings
        if "telnet" in f.title.lower() and f.severity == FindingSeverity.HIGH
    ]
    assert len(telnet_findings) >= 1, "Telnet should produce a HIGH severity finding"


def test_os_detection_finding(nmap_plugin, nmap_xml):
    from z3r0_recon.core.models import FindingSeverity
    _, findings = nmap_plugin._parse_xml(nmap_xml, "10.10.10.10")
    os_findings = [f for f in findings if "OS detected" in f.title]
    assert len(os_findings) == 1
    assert "Linux" in os_findings[0].title


def test_nse_script_finding(nmap_plugin, nmap_xml):
    _, findings = nmap_plugin._parse_xml(nmap_xml, "10.10.10.10")
    script_findings = [f for f in findings if "http-title" in f.title]
    assert len(script_findings) == 1
    assert "Apache2" in script_findings[0].description


def test_returns_empty_on_bad_xml(nmap_plugin, tmp_path):
    bad_xml = tmp_path / "bad.xml"
    bad_xml.write_text("this is not xml")
    ports, findings = nmap_plugin._parse_xml(str(bad_xml), "10.0.0.1")
    assert ports == []
    assert len(findings) == 1
    assert "parse error" in findings[0].title.lower()


def test_returns_empty_on_missing_file(nmap_plugin):
    ports, findings = nmap_plugin._parse_xml("/nonexistent/path.xml", "10.0.0.1")
    assert ports == []
    assert len(findings) == 1
