"""
Shared pytest fixtures.

Tests never touch the real keys/, releases/ or device_flash/ folders:
everything is created inside pytest's temporary directories.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from demo.harness import build_all_releases, create_context, ensure_keys  # noqa: E402


@pytest.fixture(scope="session")
def workspace(tmp_path_factory) -> dict[str, Path]:
    """Keys and signed releases, created once for the whole test session."""
    root = tmp_path_factory.mktemp("workspace")
    keys_dir = root / "keys"
    releases_dir = root / "releases"
    ensure_keys(keys_dir)
    build_all_releases(keys_dir, releases_dir)
    return {"keys": keys_dir, "releases": releases_dir}


@pytest.fixture
def ctx(workspace, tmp_path):
    """A factory-fresh device (running v1.0.0) with its own private flash folder."""
    return create_context(
        keys_dir=workspace["keys"],
        releases_dir=workspace["releases"],
        flash_dir=tmp_path / "device_flash",
        trusted_key_path=tmp_path / "trusted_key.pem",
        build_releases=False,
    )
