"""Find device names (hostnames) on the local network. Needs no root.

Three sources, tried in this order:

- reverse DNS: many routers answer with the name a device gave via DHCP;
- mDNS (port 5353): Apple devices, printers, smart TVs and Linux machines
  announce their own ".local" name;
- NetBIOS (port 137): Windows computers answer a "node status" request with
  their computer name.

Each query is a single small UDP packet with a short timeout, and the
devices are asked in parallel.
"""

from __future__ import annotations

import socket
import struct
from collections.abc import Callable, Iterable
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass

TIMEOUT = 1.0  # seconds per query
MAX_WORKERS = 32
MDNS_PORT = 5353
NETBIOS_PORT = 137
DNS_PTR, DNS_IN = 12, 1
NETBIOS_NBSTAT = 0x21

# Names that say nothing about the device (systemd-resolved invents "_gateway").
IGNORED = {"_gateway", "localhost"}


@dataclass(frozen=True)
class DeviceName:
    name: str
    source: str  # "dns", "mdns" or "netbios"


# --- reverse DNS -----------------------------------------------------------


def reverse_dns(ip: str, timeout: float = TIMEOUT, lookup=socket.gethostbyaddr) -> str | None:
    """PTR lookup through the system resolver, abandoned after `timeout` seconds."""
    with ThreadPoolExecutor(max_workers=1) as pool:
        future = pool.submit(lookup, ip)
        try:
            return future.result(timeout=timeout)[0]
        except Exception:  # noqa: BLE001 - herror, gaierror, timeout: all mean "no name"
            return None
        finally:
            pool.shutdown(wait=False, cancel_futures=True)


# --- mDNS ----------------------------------------------------------------------


def _reverse_name(ip: str) -> bytes:
    labels = [*reversed(ip.split(".")), "in-addr", "arpa"]
    return b"".join(bytes([len(label)]) + label.encode() for label in labels) + b"\0"


def mdns_query(ip: str, query_id: int = 0x4E47) -> bytes:
    header = struct.pack("!HHHHHH", query_id, 0, 1, 0, 0, 0)
    return header + _reverse_name(ip) + struct.pack("!HH", DNS_PTR, DNS_IN)


def _read_name(data: bytes, offset: int, depth: int = 0) -> tuple[str, int]:
    """A DNS name at `offset`, following compression pointers. Returns (name, next offset)."""
    labels = []
    while True:
        if depth > 10 or offset >= len(data):
            raise ValueError("bad DNS name")
        length = data[offset]
        if length == 0:
            return ".".join(labels), offset + 1
        if length & 0xC0 == 0xC0:
            pointer = struct.unpack("!H", data[offset : offset + 2])[0] & 0x3FFF
            rest, _ = _read_name(data, pointer, depth + 1)
            return ".".join([*labels, rest] if rest else labels), offset + 2
        labels.append(data[offset + 1 : offset + 1 + length].decode("utf-8", "replace"))
        offset += 1 + length


def parse_mdns_answer(data: bytes) -> str | None:
    """The first PTR answer in a DNS response, without the trailing '.local'."""
    try:
        questions, answers = struct.unpack("!HH", data[4:8])
        offset = 12
        for _ in range(questions):
            _, offset = _read_name(data, offset)
            offset += 4
        for _ in range(answers):
            _, offset = _read_name(data, offset)
            rtype, _, _, rdlength = struct.unpack("!HHIH", data[offset : offset + 10])
            offset += 10
            if rtype == DNS_PTR:
                name, _ = _read_name(data, offset)
                return name.removesuffix(".local") or None
            offset += rdlength
    except (ValueError, struct.error, IndexError):
        return None
    return None


def _udp_ask(ip: str, port: int, payload: bytes, timeout: float) -> bytes | None:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(timeout)
        try:
            sock.sendto(payload, (ip, port))
            data, (sender, _) = sock.recvfrom(4096)
        except OSError:
            return None
        return data if sender == ip else None


def mdns_name(ip: str, timeout: float = TIMEOUT, port: int = MDNS_PORT) -> str | None:
    """Ask the device itself (unicast mDNS) which .local name it has."""
    data = _udp_ask(ip, port, mdns_query(ip), timeout)
    return parse_mdns_answer(data) if data else None


# --- NetBIOS -------------------------------------------------------------------


def netbios_query(query_id: int = 0x4E47) -> bytes:
    # The wildcard name "*" padded to 16 bytes, in NetBIOS "first level" encoding.
    raw = b"*" + b"\0" * 15
    encoded = bytes(c for byte in raw for c in (ord("A") + (byte >> 4), ord("A") + (byte & 0x0F)))
    header = struct.pack("!HHHHHH", query_id, 0, 1, 0, 0, 0)
    return header + bytes([32]) + encoded + b"\0" + struct.pack("!HH", NETBIOS_NBSTAT, DNS_IN)


def parse_netbios_answer(data: bytes) -> str | None:
    """The computer name from a node status response (the unique name of type 0x00)."""
    try:
        offset = 12 + 34 + 4 + 4 + 2  # header, name, type/class, TTL, data length
        count = data[offset]
        offset += 1
        for _ in range(count):
            entry = data[offset : offset + 18]
            if len(entry) < 18:
                return None
            name = entry[:15].decode("ascii", "replace").strip()
            suffix, flags = entry[15], struct.unpack("!H", entry[16:18])[0]
            if suffix == 0x00 and not flags & 0x8000 and name:  # 0x8000 = group name
                return name
            offset += 18
    except (IndexError, struct.error):
        return None
    return None


def netbios_name(ip: str, timeout: float = TIMEOUT, port: int = NETBIOS_PORT) -> str | None:
    data = _udp_ask(ip, port, netbios_query(), timeout)
    return parse_netbios_answer(data) if data else None


# --- all together -----------------------------------------------------------


def find_name(
    ip: str,
    resolvers: Iterable[tuple[str, Callable[[str], str | None]]] | None = None,
) -> DeviceName | None:
    if resolvers is None:
        resolvers = [("dns", reverse_dns), ("mdns", mdns_name), ("netbios", netbios_name)]
    for source, resolve in resolvers:
        name = resolve(ip)
        if name and name.strip() and name.strip().lower() not in IGNORED:
            return DeviceName(name.strip()[:64], source)
    return None


def find_names(ips: Iterable[str], resolvers=None) -> dict[str, DeviceName]:
    """Names for every IP that has one, looked up in parallel."""
    ips = list(dict.fromkeys(ips))
    if not ips:
        return {}
    with ThreadPoolExecutor(max_workers=min(MAX_WORKERS, len(ips))) as pool:
        results = pool.map(lambda ip: find_name(ip, resolvers), ips)
        return {ip: name for ip, name in zip(ips, results) if name}
