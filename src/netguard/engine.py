"""Glue between discovery, detectors and storage."""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from datetime import datetime

from netguard.detectors.new_device import detect_new_devices
from netguard.models import Alert, Observation, utcnow
from netguard.storage import Store


@dataclass(frozen=True)
class ScanResult:
    observations: Sequence[Observation]
    alerts: Sequence[Alert]
    baseline: bool


def process_scan(
    store: Store,
    observations: Sequence[Observation],
    source: str,
    network: str,
    now: datetime | None = None,
) -> ScanResult:
    """Run the detectors on one scan, then save the scan and its alerts."""
    now = now or utcnow()
    baseline = store.is_first_scan()
    alerts = detect_new_devices(observations, store.known_macs(), baseline, now)
    store.record_scan(observations, source=source, network=network, started_at=now)
    store.add_alerts(alerts)
    return ScanResult(observations=observations, alerts=alerts, baseline=baseline)
