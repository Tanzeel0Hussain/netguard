"""Turn captured frames into the plain packet objects the detectors use.

Two kinds of packet matter: ARP (for spoofing detection) and TCP SYN without
ACK, i.e. new connection attempts (for port-scan detection).
"""

from __future__ import annotations

import logging
import threading
from collections.abc import Callable, Iterator
from datetime import datetime, timezone
from pathlib import Path

from netguard.detectors.arp_spoof import OP_REPLY, OP_REQUEST, ArpPacket
from netguard.detectors.portscan import TcpSyn
from netguard.models import normalize_mac

log = logging.getLogger(__name__)

POLL_SECONDS = 1.0  # how often the capture loop checks whether it should stop

# Kernel (BPF) filter: ARP, plus IPv4 TCP segments with SYN set and ACK clear.
CAPTURE_FILTER = "arp or (tcp[tcpflags] & (tcp-syn|tcp-ack) == tcp-syn)"

TCP_SYN, TCP_ACK = 0x02, 0x10

Packet = ArpPacket | TcpSyn


class CapturePermissionError(PermissionError):
    pass


class CaptureStoppedError(RuntimeError):
    pass


def parse_packet(pkt) -> Packet | None:
    """ArpPacket or TcpSyn for frames we care about, None for everything else."""
    from scapy.layers.inet import IP, TCP
    from scapy.layers.l2 import ARP, Ether

    try:
        at = datetime.fromtimestamp(float(pkt.time), timezone.utc)
        if ARP in pkt:
            arp = pkt[ARP]
            if arp.op not in (OP_REQUEST, OP_REPLY):
                return None
            return ArpPacket(
                op=int(arp.op),
                sender_mac=normalize_mac(arp.hwsrc),
                sender_ip=arp.psrc,
                target_mac=normalize_mac(arp.hwdst),
                target_ip=arp.pdst,
                at=at,
            )
        if TCP in pkt and IP in pkt and Ether in pkt:
            flags = int(pkt[TCP].flags)
            if flags & (TCP_SYN | TCP_ACK) != TCP_SYN:
                return None  # not a new connection attempt
            return TcpSyn(
                src_mac=normalize_mac(pkt[Ether].src),
                src_ip=pkt[IP].src,
                dst_ip=pkt[IP].dst,
                dst_port=int(pkt[TCP].dport),
                at=at,
            )
    except (ValueError, TypeError, AttributeError):
        return None  # malformed packet: not ours to judge
    return None


def read_pcap(path: Path) -> Iterator[Packet]:
    """Replay a capture file, e.g. one recorded with `tcpdump -w`. Needs no root."""
    import scapy.layers.inet  # noqa: F401 - like open_capture(): the reader picks its
    import scapy.layers.l2  # noqa: F401 - decoder when the file is opened
    from scapy.error import Scapy_Exception
    from scapy.utils import PcapReader

    try:
        reader = PcapReader(str(path))
    except Scapy_Exception as exc:
        raise ValueError(f"{path} is not a pcap file: {exc}") from exc
    with reader:
        for pkt in reader:
            parsed = parse_packet(pkt)
            if parsed:
                yield parsed


def open_capture(iface: str | None):
    """Open a raw socket for ARP and TCP SYN frames. Fails at once without root."""
    import scapy.arch  # noqa: F401 - sets conf.L2listen for this operating system
    import scapy.layers.inet  # noqa: F401 - registers IP/TCP (see below)
    import scapy.layers.l2  # noqa: F401 - registers Ethernet as a link type (see below)
    from scapy.config import conf
    from scapy.error import Scapy_Exception

    # A socket picks how to decode frames when it is opened, from the link
    # types registered at that moment. Without the imports above it falls back
    # to raw bytes, `ARP in pkt` is never true and the capture sees nothing.

    try:
        try:
            return conf.L2listen(iface=iface, filter=CAPTURE_FILTER)
        except Scapy_Exception as exc:  # no libpcap/tcpdump to compile the filter
            log.info("no kernel capture filter (%s); filtering in Python", exc)
            return conf.L2listen(iface=iface)
    except PermissionError as exc:
        raise CapturePermissionError(
            "capturing packets needs root (or CAP_NET_RAW). Run it with sudo, "
            "or replay a capture file with --pcap."
        ) from exc


def capture(sock, on_packet: Callable[[Packet], None], stop: threading.Event) -> None:
    """Feed parsed packets from `sock` to `on_packet` until `stop` is set. Closes `sock`."""
    from scapy.sendrecv import sniff

    def handle(pkt) -> None:
        # Scapy closes the socket if this callback raises, which would end the
        # capture silently, so nothing may escape from here.
        try:
            parsed = parse_packet(pkt)
            if parsed:
                on_packet(parsed)
        except Exception:  # noqa: BLE001
            log.exception("error while handling a packet")

    try:
        while not stop.is_set():
            sniff(
                opened_socket=sock,
                prn=handle,
                store=False,
                timeout=POLL_SECONDS,
                chainCC=True,  # let Ctrl+C reach the caller instead of being swallowed
            )
            if getattr(sock, "closed", False) and not stop.is_set():
                # Scapy closes a socket that fails (e.g. the interface went
                # down). Without this check the loop would spin doing nothing.
                raise CaptureStoppedError("packet capture stopped: is the interface still up?")
    finally:
        sock.close()
