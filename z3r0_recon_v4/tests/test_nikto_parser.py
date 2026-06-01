"""
tests/test_nikto_parser.py — Unit tests for NiktoPlugin._parse_nikto_output().
"""

import pytest


@pytest.fixture
def nikto_plugin():
    from z3r0_recon.plugins.web import NiktoPlugin
    return NiktoPlugin()


@pytest.fixture
def nikto_output(fixture_dir):
    return (fixture_dir / "nikto_results.txt").read_text()


def test_parses_findings_from_plus_lines(nikto_plugin, nikto_output):
    findings = nikto_plugin._parse_nikto_output(nikto_output, "http://10.10.10.10", 80)
    # Should find things, not just "no notable findings"
    non_info = [f for f in findings if "no notable" not in f.title.lower()]
    assert len(non_info) >= 1


def test_skips_header_lines(nikto_plugin, nikto_output):
    findings = nikto_plugin._parse_nikto_output(nikto_output, "http://10.10.10.10", 80)
    titles = [f.title for f in findings]
    assert not any("Target IP" in t for t in titles)
    assert not any("Target Port" in t for t in titles)
    assert not any("Start Time" in t for t in titles)


def test_default_credentials_is_high(nikto_plugin, nikto_output):
    from z3r0_recon.core.models import FindingSeverity
    findings = nikto_plugin._parse_nikto_output(nikto_output, "http://10.10.10.10", 80)
    cred_findings = [f for f in findings if "default credentials" in f.title.lower()]
    assert len(cred_findings) >= 1
    assert cred_findings[0].severity == FindingSeverity.HIGH


def test_cve_extraction(nikto_plugin, nikto_output):
    findings = nikto_plugin._parse_nikto_output(nikto_output, "http://10.10.10.10", 80)
    cve_findings = [f for f in findings if f.cve_ids]
    assert len(cve_findings) >= 1
    assert "CVE-2021-41773" in cve_findings[0].cve_ids


def test_empty_output_returns_no_findings(nikto_plugin):
    findings = nikto_plugin._parse_nikto_output("", "http://10.10.10.10", 80)
    assert len(findings) == 1
    assert "no notable" in findings[0].title.lower()
