"""Find the devices on the local network."""

from __future__ import annotations

import ipaddress

from netguard.discovery.arp_scan import ScanPermissionError, arp_scan
from netguard.discovery.arp_table import read_arp_table
from netguard.models import Observation

__all__ = ["ScanPermissionError", "discover"]


def discover(
    network: ipaddress.IPv4Network,
    iface: str | None = None,
    passive: bool = False,
    timeout: float = 2.0,
) -> list[Observation]:
    """Return one observation per IP/MAC pair seen inside `network`."""
    if passive:
        observations = read_arp_table(iface)
    else:
        observations = arp_scan(network, iface=iface, timeout=timeout)

    unique: dict[tuple[str, str], Observation] = {}
    for obs in observations:
        if ipaddress.ip_address(obs.ip) in network:
            unique.setdefault((obs.ip, obs.mac), obs)
    return sorted(unique.values(), key=lambda o: ipaddress.ip_address(o.ip))
