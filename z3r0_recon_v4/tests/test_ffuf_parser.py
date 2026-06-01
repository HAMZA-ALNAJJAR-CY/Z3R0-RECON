"""
tests/test_ffuf_parser.py — Unit tests for FfufPlugin._parse_ffuf_json().
"""

import json
import pytest
from pathlib import Path


@pytest.fixture
def ffuf_plugin():
    from z3r0_recon.plugins.web import FfufPlugin
    return FfufPlugin()


@pytest.fixture
def ffuf_json_path(fixture_dir):
    return fixture_dir / "ffuf_results.json"


def test_parses_results(ffuf_plugin, ffuf_json_path):
    findings = ffuf_plugin._parse_ffuf_json(ffuf_json_path, "http://10.10.10.10", 80)
    assert len(findings) == 3


def test_result_titles_include_status(ffuf_plugin, ffuf_json_path):
    findings = ffuf_plugin._parse_ffuf_json(ffuf_json_path, "http://10.10.10.10", 80)
    for f in findings:
        assert any(code in f.title for code in ["200", "302", "403"])


def test_metadata_contains_path_and_status(ffuf_plugin, ffuf_json_path):
    findings = ffuf_plugin._parse_ffuf_json(ffuf_json_path, "http://10.10.10.10", 80)
    for f in findings:
        assert "path" in f.metadata
        assert "status" in f.metadata


def test_missing_file_returns_empty(ffuf_plugin, tmp_path):
    findings = ffuf_plugin._parse_ffuf_json(tmp_path / "nonexistent.json", "http://10.10.10.10", 80)
    assert findings == []


def test_malformed_json_returns_empty(ffuf_plugin, tmp_path):
    bad = tmp_path / "bad.json"
    bad.write_text("not json")
    findings = ffuf_plugin._parse_ffuf_json(bad, "http://10.10.10.10", 80)
    assert findings == []


def test_target_and_port_propagated(ffuf_plugin, ffuf_json_path):
    findings = ffuf_plugin._parse_ffuf_json(ffuf_json_path, "http://10.10.10.10", 8443)
    for f in findings:
        assert f.target == "http://10.10.10.10"
        assert f.port == 8443


def test_decision_engine_key_collision_fix():
    """
    Regression test for CHANGE 1: TaskRecord.key must include target host.
    Two different hosts on the same port must produce different keys.
    """
    from z3r0_recon.core.models import ScanTarget, TaskRecord
    t1 = TaskRecord(plugin="nikto", target=ScanTarget(host="10.10.10.1"),  port=80, reason="")
    t2 = TaskRecord(plugin="nikto", target=ScanTarget(host="10.10.10.2"),  port=80, reason="")
    t3 = TaskRecord(plugin="nikto", target=ScanTarget(host="10.10.10.1"),  port=80, reason="")
    assert t1.key != t2.key, "Same plugin+port on different hosts must have different keys"
    assert t1.key == t3.key, "Same plugin+port+host must have identical keys (dedup)"
