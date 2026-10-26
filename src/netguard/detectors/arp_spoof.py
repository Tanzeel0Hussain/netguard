"""ARP spoofing / man-in-the-middle detection from a stream of ARP packets.

ARP has no authentication: any host can answer "192.168.1.1 is at <my MAC>",
and the victims start sending their traffic to it. This detector looks for the
traces such an attack leaves:

- gateway_mac_changed: the gateway IP is claimed by a MAC we have not seen as
  the gateway on this Wi-Fi access point (BSSID) before.
- ip_mac_changed: an IP that belonged to one MAC is now claimed by another.
- mac_claims_many_ips: one MAC answers for several IPs in a short window.
- arp_reply_flood: a MAC keeps sending ARP replies nobody asked for, which is
  how tools like arpspoof keep a poisoned cache poisoned.

The detector is plain Python with no I/O: packets in, alerts and events out.
"""

from __future__ import annotations

from collections import defaultdict, deque
from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import datetime, timedelta

from netguard.models import Alert, Event

OP_REQUEST = 1  # "who-has"
OP_REPLY = 2  # "is-at"


@dataclass(frozen=True)
class ArpPacket:
    op: int
    sender_mac: str
    sender_ip: str
    target_mac: str
    target_ip: str
    at: datetime


@dataclass(frozen=True)
class ArpWatchSettings:
    window: timedelta = timedelta(seconds=60)
    many_ips: int = 3  # distinct IPs from one MAC within `window`
    flood_replies: int = 15  # unsolicited replies from one MAC within `window`
    request_timeout: timedelta = timedelta(seconds=5)  # a reply this soon after a request was asked for


@dataclass
class ArpFindings:
    alerts: list[Alert] = field(default_factory=list)
    events: list[Event] = field(default_factory=list)

    def extend(self, other: ArpFindings) -> None:
        self.alerts.extend(other.alerts)
        self.events.extend(other.events)


class ArpWatch:
    def __init__(
        self,
        bindings: dict[str, str] | None = None,
        gateway_ip: str | None = None,
        gateway_macs: Iterable[str] = (),
        own_macs: Iterable[str] = (),
        settings: ArpWatchSettings | None = None,
    ):
        """
        bindings:     known IP -> MAC pairs (from the inventory)
        gateway_macs: MACs already accepted as the gateway on this access point
        own_macs:     this machine's MACs; its own packets are not checked
        """
        self.bindings = dict(bindings or {})
        self.gateway_ip = gateway_ip
        self.gateway_macs = set(gateway_macs)
        self.own_macs = set(own_macs)
        self.settings = settings or ArpWatchSettings()

        self._requests: dict[str, datetime] = {}  # IP asked about -> when
        self._claims: dict[str, deque[tuple[datetime, str]]] = defaultdict(deque)
        self._unsolicited: dict[str, deque[datetime]] = defaultdict(deque)
        self._raised: set[tuple[str, str, str]] = set()  # alert once per (kind, ip, mac)

    def feed(self, pkt: ArpPacket) -> ArpFindings:
        findings = ArpFindings()
        if pkt.op == OP_REQUEST:
            self._requests[pkt.target_ip] = pkt.at
        if pkt.sender_mac in self.own_macs:
            return findings
        if pkt.sender_ip == "0.0.0.0":  # an ARP probe (RFC 5227): no claim made yet
            return findings

        findings.extend(self.check_binding(pkt.sender_ip, pkt.sender_mac, pkt.at))
        self._check_many_ips(pkt, findings)
        if pkt.op == OP_REPLY:
            self._check_flood(pkt, findings)
        return findings

    def check_binding(self, ip: str, mac: str, at: datetime, source: str = "ARP") -> ArpFindings:
        """Check one IP -> MAC claim. Also used for the kernel ARP cache at start-up."""
        findings = ArpFindings()
        if ip == self.gateway_ip:
            if not self.gateway_macs:
                self.gateway_macs.add(mac)
                findings.events.append(
                    Event("gateway_learned", f"Gateway {ip} is at {mac} on this network", at, mac, ip)
                )
            elif mac not in self.gateway_macs:
                expected = ", ".join(sorted(self.gateway_macs))
                self._raise(
                    findings,
                    "gateway_mac_changed",
                    "critical",
                    f"Gateway {ip} is claimed by {mac} (expected {expected}) in {source}: "
                    "possible ARP spoofing / man-in-the-middle",
                    at,
                    mac,
                    ip,
                )
            return findings

        old = self.bindings.get(ip)
        if old and old != mac:
            self._raise(
                findings,
                "ip_mac_changed",
                "warning",
                f"{ip} moved from {old} to {mac} in {source}: a new device got this IP, or ARP spoofing",
                at,
                mac,
                ip,
            )
        self.bindings[ip] = mac
        return findings

    def _check_many_ips(self, pkt: ArpPacket, findings: ArpFindings) -> None:
        claims = self._claims[pkt.sender_mac]
        claims.append((pkt.at, pkt.sender_ip))
        self._prune(claims, pkt.at, key=lambda item: item[0])
        ips = {ip for _, ip in claims}
        if len(ips) >= self.settings.many_ips:
            self._raise(
                findings,
                "mac_claims_many_ips",
                "warning",
                f"{pkt.sender_mac} claimed {len(ips)} IPs in {self._window_text()}: "
                f"{', '.join(sorted(ips))}",
                pkt.at,
                pkt.sender_mac,
                None,
            )

    def _check_flood(self, pkt: ArpPacket, findings: ArpFindings) -> None:
        asked = self._requests.get(pkt.sender_ip)
        if asked is not None and pkt.at - asked <= self.settings.request_timeout:
            return  # a normal answer to a question
        replies = self._unsolicited[pkt.sender_mac]
        replies.append(pkt.at)
        self._prune(replies, pkt.at)
        if len(replies) >= self.settings.flood_replies:
            self._raise(
                findings,
                "arp_reply_flood",
                "warning",
                f"{pkt.sender_mac} sent {len(replies)} unsolicited ARP replies in "
                f"{self._window_text()} (claiming {pkt.sender_ip})",
                pkt.at,
                pkt.sender_mac,
                pkt.sender_ip,
            )

    def _prune(self, items: deque, now: datetime, key=lambda item: item) -> None:
        while items and now - key(items[0]) > self.settings.window:
            items.popleft()

    def _window_text(self) -> str:
        return f"{self.settings.window.total_seconds():g}s"

    def _raise(self, findings, kind, severity, message, at, mac, ip) -> None:
        token = (kind, ip or "", mac or "")
        if token in self._raised:
            return
        self._raised.add(token)
        findings.alerts.append(Alert(kind, severity, message, at, mac, ip))
