"""Active discovery: broadcast an ARP request to every address in the subnet.

Sending raw Ethernet frames needs root or the CAP_NET_RAW capability.
"""

from __future__ import annotations

import ipaddress

from netguard.models import Observation, normalize_mac, utcnow


class ScanPermissionError(PermissionError):
    pass


def arp_scan(
    network: ipaddress.IPv4Network,
    iface: str | None = None,
    timeout: float = 2.0,
    retry: int = 1,
) -> list[Observation]:
    # Imported here so the rest of NetGuard (and passive mode) loads fast.
    from scapy.layers.l2 import ARP, Ether
    from scapy.sendrecv import srp

    request = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=str(network))
    try:
        answered, _unanswered = srp(
            request, iface=iface, timeout=timeout, retry=retry, verbose=False
        )
    except PermissionError as exc:
        raise ScanPermissionError(
            "an active ARP scan needs root (or CAP_NET_RAW). "
            "Run it with sudo, or use --passive."
        ) from exc

    seen_at = utcnow()
    return [
        Observation(
            ip=reply[ARP].psrc,
            mac=normalize_mac(reply[ARP].hwsrc),
            source="arp-scan",
            seen_at=seen_at,
        )
        for _request, reply in answered
    ]
