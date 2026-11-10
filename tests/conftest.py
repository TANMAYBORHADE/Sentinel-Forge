import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import pytest

from sentinelforge import checks

checks.load_all()   
import vulnserver  # noqa: E402


@pytest.fixture
def bad_server():
    srv, url = vulnserver.start(bad=True)
    yield url
    srv.shutdown()


@pytest.fixture
def good_server():
    srv, url = vulnserver.start(bad=False)
    yield url
    srv.shutdown()