"""
tests/test_whatweb_parser.py — Unit tests for WhatWebPlugin._parse_whatweb_output().
"""

import pytest


@pytest.fixture
def whatweb_plugin():
    from z3r0_recon.plugins.web import WhatWebPlugin
    return WhatWebPlugin()


@pytest.fixture
def whatweb_output(fixture_dir):
    return (fixture_dir / "whatweb_results.txt").read_text()


def test_extracts_technologies(whatweb_plugin, whatweb_output):
    findings = whatweb_plugin._parse_whatweb_output(whatweb_output, "http://10.10.10.10", 80)
    tech_findings = [f for f in findings if "Technologies identified" in f.title]
    assert len(tech_findings) == 1
    assert len(tech_findings[0].evidence) >= 1


def test_detects_apache_in_technologies(whatweb_plugin, whatweb_output):
    findings = whatweb_plugin._parse_whatweb_output(whatweb_output, "http://10.10.10.10", 80)
    tech_f = next(f for f in findings if "Technologies identified" in f.title)
    evidence_str = " ".join(tech_f.evidence)
    assert "Apache" in evidence_str or "apache" in evidence_str.lower()


def test_flags_outdated_apache(whatweb_plugin, whatweb_output):
    from z3r0_recon.core.models import FindingSeverity
    findings = whatweb_plugin._parse_whatweb_output(whatweb_output, "http://10.10.10.10", 80)
    outdated = [f for f in findings if "outdated" in f.title.lower()]
    assert len(outdated) >= 1
    assert outdated[0].severity == FindingSeverity.MEDIUM


def test_empty_output_returns_empty_list(whatweb_plugin):
    findings = whatweb_plugin._parse_whatweb_output("", "http://10.10.10.10", 80)
    assert findings == []


def test_target_and_port_propagated(whatweb_plugin, whatweb_output):
    findings = whatweb_plugin._parse_whatweb_output(whatweb_output, "http://10.10.10.10", 8080)
    for f in findings:
        assert f.target == "http://10.10.10.10"
        assert f.port == 8080
