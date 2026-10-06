import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))


@pytest.fixture(autouse=True)
def workspace(tmp_path, monkeypatch):
    monkeypatch.setenv("AMANAH_HOME", str(tmp_path / "var"))
    yield tmp_path


@pytest.fixture
def env():
    from amanah.core import Config, Store
    return Store(), Config()
