"""Glue between discovery, detectors and storage."""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from datetime import datetime, timedelta

from netguard.detectors.new_device import detect_new_devices
from netguard.detectors.presence import detect_presence_changes
from netguard.models import Alert, Event, Observation, utcnow
from netguard.storage import Store


@dataclass(frozen=True)
class ScanResult:
    observations: Sequence[Observation]
    alerts: Sequence[Alert]
    events: Sequence[Event]
    baseline: bool


def process_scan(
    store: Store,
    observations: Sequence[Observation],
    source: str,
    network: str,
    now: datetime | None = None,
    away_after: timedelta = timedelta(minutes=15),
    dedup_window: timedelta = timedelta(hours=1),
) -> ScanResult:
    """Run the detectors on one scan, then save the scan, its events and alerts.

    Detectors must see the inventory as it was *before* this scan, so they run
    first and the scan is saved afterwards.
    """
    now = now or utcnow()
    baseline = store.is_first_scan()
    devices = store.devices()

    # Only an active scan asks every address, so only it can tell that a device left.
    complete = source == "arp-scan"
    events = detect_presence_changes(devices, observations, now, away_after, complete)
    alerts = detect_new_devices(observations, {d.mac for d in devices}, baseline, now)

    store.record_scan(observations, source=source, network=network, started_at=now)
    store.mark_absent(e.mac for e in events if e.kind == "left")
    alerts = record_findings(store, alerts, events, now, dedup_window)
    return ScanResult(observations=observations, alerts=alerts, events=events, baseline=baseline)


def record_findings(
    store: Store,
    alerts: Sequence[Alert],
    events: Sequence[Event],
    now: datetime,
    dedup_window: timedelta,
) -> list[Alert]:
    """Save events and alerts, dropping alerts already raised within `dedup_window`.

    Returns the alerts that were kept.
    """
    kept = [a for a in alerts if not store.has_recent_alert(a, since=now - dedup_window)]
    store.add_events(events)
    store.add_alerts(kept)
    return kept
