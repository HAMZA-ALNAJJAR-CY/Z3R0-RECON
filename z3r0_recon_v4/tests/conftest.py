"""
tests/conftest.py — Shared pytest fixtures.

All fixtures are minimal — they create real objects using the actual
dataclasses, not mocks. This gives genuine confidence that the parsers
produce correct Finding objects, not that mocks behave as told.
"""

import pytest
from pathlib import Path

# ─── Path helper ──────────────────────────────────────────────────────────────

@pytest.fixture
def fixture_dir() -> Path:
    """Return the path to tests/fixtures/ where sample tool outputs live."""
    return Path(__file__).parent / "fixtures"


# ─── Minimal session fixture ──────────────────────────────────────────────────

@pytest.fixture
def target():
    from z3r0_recon.core.models import ScanTarget
    return ScanTarget(host="10.10.10.10")


@pytest.fixture
def session(tmp_path, target):
    from z3r0_recon.core.models import ScanSession
    return ScanSession(
        target=target,
        output_dir=str(tmp_path),
        authorized=True,
    )


@pytest.fixture
def task(target):
    from z3r0_recon.core.models import TaskRecord
    return TaskRecord(
        plugin="test",
        target=target,
        port=80,
        reason="test",
        params={"url": "http://10.10.10.10"},
    )
