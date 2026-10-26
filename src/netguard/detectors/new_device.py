from __future__ import annotations

from collections.abc import Iterable
from datetime import datetime

from netguard.models import Alert, Observation


def detect_new_devices(
    observations: Iterable[Observation],
    known_macs: set[str],
    baseline: bool,
    now: datetime,
) -> list[Alert]:
    """Alert once for every MAC that is not in the inventory yet.

    On the very first scan (`baseline`) every device is new, so nothing is
    raised: that scan only records what is already on the network.
    """
    if baseline:
        return []

    alerts = []
    seen: set[str] = set()
    for obs in observations:
        if obs.mac in known_macs or obs.mac in seen:
            continue
        seen.add(obs.mac)
        alerts.append(
            Alert(
                kind="new_device",
                severity="warning",
                message=f"Unknown device joined: {obs.mac} at {obs.ip}",
                created_at=now,
                mac=obs.mac,
                ip=obs.ip,
            )
        )
    return alerts
