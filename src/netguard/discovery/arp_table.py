"""Passive discovery: read the kernel's ARP cache. Needs no root."""

from __future__ import annotations

from datetime import datetime
from pathlib import Path

from netguard.models import Observation, normalize_mac, utcnow

ARP_FILE = Path("/proc/net/arp")
ATF_COM = 0x2  # the entry is complete (the MAC is known)


def parse_arp_table(
    text: str, iface: str | None = None, seen_at: datetime | None = None
) -> list[Observation]:
    seen_at = seen_at or utcnow()
    observations = []
    # Columns: IP address, HW type, Flags, HW address, Mask, Device
    for line in text.splitlines()[1:]:
        fields = line.split()
        if len(fields) < 6:
            continue
        ip, _hw_type, flags, mac, _mask, device = fields[:6]
        if iface and device != iface:
            continue
        if not int(flags, 16) & ATF_COM or mac == "00:00:00:00:00:00":
            continue
        observations.append(
            Observation(ip=ip, mac=normalize_mac(mac), source="arp-table", seen_at=seen_at)
        )
    return observations


def read_arp_table(iface: str | None = None, path: Path = ARP_FILE) -> list[Observation]:
    return parse_arp_table(path.read_text(), iface=iface)
