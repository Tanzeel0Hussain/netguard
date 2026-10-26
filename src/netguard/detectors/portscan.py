"""Port-scan detection from a stream of TCP SYN packets.

A SYN (without ACK) opens a TCP connection. Normal clients open a few, to a
few services. A scanner such as `nmap -sS` sends SYNs to many ports of one
host (a vertical scan) or to one port on many hosts (a horizontal sweep),
all within seconds. Both show up as one source touching too many distinct
targets inside a sliding time window.

Very slow scans (e.g. `nmap -T1`, one probe every 15 s) stay under any
reasonable threshold. Catching those needs long-term statistics and is left out.
"""

from __future__ import annotations

from collections import OrderedDict, deque
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import datetime, timedelta

from netguard.models import Alert

MAX_PORTS_IN_MESSAGE = 10


@dataclass(frozen=True)
class TcpSyn:
    src_mac: str
    src_ip: str
    dst_ip: str
    dst_port: int
    at: datetime


@dataclass(frozen=True)
class PortScanSettings:
    window: timedelta = timedelta(seconds=60)
    ports: int = 15  # distinct ports on one host within `window`
    hosts: int = 10  # distinct hosts on one port within `window`
    # Cap on tracked sources. A scanner with spoofed source IPs must not be
    # able to make NetGuard keep state for millions of them.
    max_sources: int = 10_000


class PortScanWatch:
    def __init__(
        self,
        own_macs: Iterable[str] = (),
        allow_ips: Iterable[str] = (),
        settings: PortScanSettings | None = None,
    ):
        self.own_macs = set(own_macs)
        self.allow_ips = set(allow_ips)
        self.settings = settings or PortScanSettings()
        # source IP -> recent (time, dst_ip, dst_port), oldest source first
        self._recent: OrderedDict[str, deque[tuple[datetime, str, int]]] = OrderedDict()
        self._raised: set[tuple[str, str]] = set()  # alert once per (kind, source)

    @property
    def tracked_sources(self) -> int:
        return len(self._recent)

    def feed(self, syn: TcpSyn) -> list[Alert]:
        if syn.src_mac in self.own_macs or syn.src_ip in self.allow_ips:
            return []

        recent = self._recent.pop(syn.src_ip, None) or deque()
        self._recent[syn.src_ip] = recent  # now the most recently seen source
        while len(self._recent) > self.settings.max_sources:
            self._recent.popitem(last=False)

        recent.append((syn.at, syn.dst_ip, syn.dst_port))
        while recent and syn.at - recent[0][0] > self.settings.window:
            recent.popleft()

        alerts = []
        ports = {port for _, ip, port in recent if ip == syn.dst_ip}
        if len(ports) >= self.settings.ports:
            self._raise(
                alerts,
                "port_scan",
                f"{syn.src_ip} ({syn.src_mac}) scanned {len(ports)} ports on {syn.dst_ip} "
                f"in {self._window_text()}: {_ports_text(ports)}",
                syn,
            )
        hosts = {ip for _, ip, port in recent if port == syn.dst_port}
        if len(hosts) >= self.settings.hosts:
            self._raise(
                alerts,
                "host_sweep",
                f"{syn.src_ip} ({syn.src_mac}) probed port {syn.dst_port} on {len(hosts)} hosts "
                f"in {self._window_text()}",
                syn,
            )
        return alerts

    def _window_text(self) -> str:
        return f"{self.settings.window.total_seconds():g}s"

    def _raise(self, alerts: list[Alert], kind: str, message: str, syn: TcpSyn) -> None:
        if (kind, syn.src_ip) in self._raised:
            return
        self._raised.add((kind, syn.src_ip))
        alerts.append(Alert(kind, "warning", message, syn.at, syn.src_mac, syn.src_ip))


def _ports_text(ports: set[int]) -> str:
    shown = sorted(ports)[:MAX_PORTS_IN_MESSAGE]
    more = len(ports) - len(shown)
    return ", ".join(map(str, shown)) + (f" and {more} more" if more else "")
