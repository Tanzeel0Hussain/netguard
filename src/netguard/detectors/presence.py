from __future__ import annotations

from collections.abc import Iterable
from datetime import datetime, timedelta

from netguard.models import Device, Event, Observation


def detect_presence_changes(
    devices: Iterable[Device],
    observations: Iterable[Observation],
    now: datetime,
    away_after: timedelta,
    complete: bool = True,
) -> list[Event]:
    """Work out which devices appeared, left or came back in this scan.

    A device only counts as gone once it has not been seen for `away_after`.
    Phones in power-saving mode skip ARP replies now and then, and a single
    missed scan should not make them flap between "left" and "returned".

    `complete` says whether the scan asked every address (an active ARP scan).
    The kernel ARP cache only lists hosts we talked to recently, so a device
    missing from it proves nothing: such scans never report "left".
    """
    seen: dict[str, Observation] = {}
    for obs in observations:
        seen.setdefault(obs.mac, obs)

    events = []
    known = set()
    for device in devices:
        known.add(device.mac)
        obs = seen.get(device.mac)
        if obs and not device.present:
            events.append(
                Event("returned", f"{device.name} is back at {obs.ip}", now, device.mac, obs.ip)
            )
        elif complete and not obs and device.present and now - device.last_seen >= away_after:
            events.append(
                Event("left", f"{device.name} left (last seen at {device.ip})", now, device.mac, device.ip)
            )

    for mac, obs in seen.items():
        if mac not in known:
            events.append(Event("first_seen", f"First time seen: {mac} at {obs.ip}", now, mac, obs.ip))
    return events
