from datetime import datetime, timezone

import pytest

from netguard.models import Observation
from netguard.storage import Store

T0 = datetime(2026, 10, 1, 12, 0, tzinfo=timezone.utc)


def obs(ip: str, mac: str, at: datetime = T0) -> Observation:
    return Observation(ip=ip, mac=mac, source="arp-scan", seen_at=at)


@pytest.fixture
def store():
    with Store(":memory:") as s:
        yield s
