"""
tests/test_gobuster_parser.py — Unit tests for GobusterPlugin._parse_gobuster_output().
"""

import pytest


@pytest.fixture
def gobuster_plugin():
    from z3r0_recon.plugins.web import GobusterPlugin
    return GobusterPlugin()


@pytest.fixture
def gobuster_output(fixture_dir):
    return (fixture_dir / "gobuster_results.txt").read_text()


def test_parses_200_paths(gobuster_plugin, gobuster_output):
    findings = gobuster_plugin._parse_gobuster_output(gobuster_output, "http://10.10.10.10", 80)
    titles = [f.title for f in findings]
    assert any("/index.html" in t and "200" in t for t in titles)


def test_excludes_404(gobuster_plugin, gobuster_output):
    findings = gobuster_plugin._parse_gobuster_output(gobuster_output, "http://10.10.10.10", 80)
    assert not any("404" in f.title for f in findings)


def test_high_value_path_git_is_high_severity(gobuster_plugin, gobuster_output):
    from z3r0_recon.core.models import FindingSeverity
    findings = gobuster_plugin._parse_gobuster_output(gobuster_output, "http://10.10.10.10", 80)
    git_findings = [f for f in findings if ".git" in f.title]
    assert len(git_findings) >= 1
    assert git_findings[0].severity == FindingSeverity.HIGH


def test_high_value_path_wp_admin_is_medium_or_high(gobuster_plugin, gobuster_output):
    from z3r0_recon.core.models import FindingSeverity
    findings = gobuster_plugin._parse_gobuster_output(gobuster_output, "http://10.10.10.10", 80)
    wp = [f for f in findings if "wp-admin" in f.title]
    assert len(wp) >= 1
    assert wp[0].severity in (FindingSeverity.MEDIUM, FindingSeverity.HIGH)


def test_finding_metadata_contains_status(gobuster_plugin, gobuster_output):
    findings = gobuster_plugin._parse_gobuster_output(gobuster_output, "http://10.10.10.10", 80)
    for f in findings:
        if "no interesting" not in f.title:
            assert "status" in f.metadata


def test_empty_output_returns_no_findings_found(gobuster_plugin):
    findings = gobuster_plugin._parse_gobuster_output("", "http://10.10.10.10", 80)
    assert len(findings) == 1
    assert "no interesting" in findings[0].title.lower()
