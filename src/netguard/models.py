"""Plain data objects shared by every part of NetGuard."""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime, timezone

_MAC_RE = re.compile(r"^[0-9a-f]{2}([:-]?)[0-9a-f]{2}(\1[0-9a-f]{2}){4}$")


def normalize_mac(mac: str) -> str:
    """Return a MAC as lowercase 'aa:bb:cc:dd:ee:ff', or raise ValueError."""
    value = mac.strip().lower()
    if not _MAC_RE.match(value):
        raise ValueError(f"not a valid MAC address: {mac!r}")
    digits = value.replace(":", "").replace("-", "")
    return ":".join(digits[i : i + 2] for i in range(0, 12, 2))


def utcnow() -> datetime:
    return datetime.now(timezone.utc).replace(microsecond=0)


@dataclass(frozen=True)
class Observation:
    """One sighting of an IP/MAC pair on the network."""

    ip: str
    mac: str
    source: str  # "arp-scan" or "arp-table"
    seen_at: datetime


@dataclass(frozen=True)
class Device:
    """A device in the inventory, keyed by MAC address."""

    mac: str
    ip: str
    first_seen: datetime
    last_seen: datetime
    trusted: bool = False
    label: str | None = None


@dataclass(frozen=True)
class Alert:
    kind: str  # e.g. "new_device"
    severity: str  # "info", "warning" or "critical"
    message: str
    created_at: datetime
    mac: str | None = None
    ip: str | None = None
