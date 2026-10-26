"""Work out which network to watch, and refuse targets that are not ours.

The default interface, its subnet and the gateway are read from
/proc/net/route, so no extra tools or root access are needed.
"""

from __future__ import annotations

import ipaddress
import struct
from dataclasses import dataclass
from pathlib import Path

ROUTE_FILE = Path("/proc/net/route")
RTF_UP = 0x1

# Largest subnet we agree to ARP-scan (a /20). A home LAN is usually a /24.
MAX_SCAN_ADDRESSES = 4096


class UnsafeTargetError(ValueError):
    """Raised when a scan target is outside what NetGuard is meant for."""


@dataclass(frozen=True)
class NetInfo:
    iface: str
    network: ipaddress.IPv4Network
    gateway: ipaddress.IPv4Address | None


@dataclass(frozen=True)
class _Route:
    iface: str
    destination: ipaddress.IPv4Address
    gateway: ipaddress.IPv4Address
    mask: ipaddress.IPv4Address
    metric: int


def _hex_to_ip(value: str) -> ipaddress.IPv4Address:
    # The kernel prints each address as a native-endian 32-bit hex number,
    # e.g. "0164A8C0" is 192.168.100.1 on x86.
    return ipaddress.IPv4Address(struct.pack("=I", int(value, 16)))


def parse_route_table(text: str) -> list[_Route]:
    routes = []
    for line in text.splitlines()[1:]:
        fields = line.split()
        if len(fields) < 8 or not int(fields[3], 16) & RTF_UP:
            continue
        routes.append(
            _Route(
                iface=fields[0],
                destination=_hex_to_ip(fields[1]),
                gateway=_hex_to_ip(fields[2]),
                metric=int(fields[6]),
                mask=_hex_to_ip(fields[7]),
            )
        )
    return routes


def detect_netinfo(route_text: str | None = None, iface: str | None = None) -> NetInfo:
    """Find the subnet and gateway of `iface` (default: the default-route interface)."""
    if route_text is None:
        route_text = ROUTE_FILE.read_text()
    routes = parse_route_table(route_text)

    defaults = sorted(
        (r for r in routes if int(r.destination) == 0 and int(r.mask) == 0),
        key=lambda r: r.metric,
    )
    if iface is None:
        if not defaults:
            raise RuntimeError("no default route found; are you connected to a network?")
        iface = defaults[0].iface
    gateway = next((r.gateway for r in defaults if r.iface == iface), None)

    for route in sorted(routes, key=lambda r: r.metric):
        if route.iface == iface and int(route.mask) != 0 and int(route.gateway) == 0:
            network = ipaddress.IPv4Network(f"{route.destination}/{route.mask}")
            return NetInfo(iface=iface, network=network, gateway=gateway)
    raise RuntimeError(f"could not find the local subnet of {iface}")


def validate_scan_target(network: ipaddress.IPv4Network) -> None:
    """Only allow private, LAN-sized networks: NetGuard watches your own network."""
    if not network.is_private:
        raise UnsafeTargetError(
            f"{network} is not a private network; NetGuard only scans your own LAN"
        )
    if network.num_addresses > MAX_SCAN_ADDRESSES:
        raise UnsafeTargetError(
            f"{network} has {network.num_addresses} addresses; the limit is "
            f"{MAX_SCAN_ADDRESSES} (a /20). Pass a smaller subnet."
        )
