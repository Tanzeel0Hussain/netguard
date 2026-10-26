"""Turn captured ARP packets into ArpPacket objects for the detector."""

from __future__ import annotations

import logging
import threading
from collections.abc import Callable, Iterator
from datetime import datetime, timezone
from pathlib import Path

from netguard.detectors.arp_spoof import OP_REPLY, OP_REQUEST, ArpPacket
from netguard.models import normalize_mac

log = logging.getLogger(__name__)

POLL_SECONDS = 1.0  # how often the capture loop checks whether it should stop


class CapturePermissionError(PermissionError):
    pass


class CaptureStoppedError(RuntimeError):
    pass


def packet_from_scapy(pkt) -> ArpPacket | None:
    from scapy.layers.l2 import ARP

    if ARP not in pkt:
        return None
    arp = pkt[ARP]
    if arp.op not in (OP_REQUEST, OP_REPLY):
        return None
    try:
        return ArpPacket(
            op=int(arp.op),
            sender_mac=normalize_mac(arp.hwsrc),
            sender_ip=arp.psrc,
            target_mac=normalize_mac(arp.hwdst),
            target_ip=arp.pdst,
            at=datetime.fromtimestamp(float(pkt.time), timezone.utc),
        )
    except (ValueError, TypeError):
        return None  # malformed packet: not ours to judge


def read_pcap(path: Path) -> Iterator[ArpPacket]:
    """Replay a capture file, e.g. one recorded with `tcpdump -w`. Needs no root."""
    from scapy.error import Scapy_Exception
    from scapy.utils import PcapReader

    try:
        reader = PcapReader(str(path))
    except Scapy_Exception as exc:
        raise ValueError(f"{path} is not a pcap file: {exc}") from exc
    with reader:
        for pkt in reader:
            arp = packet_from_scapy(pkt)
            if arp:
                yield arp


def open_capture(iface: str | None):
    """Open a raw socket for ARP frames. Fails at once without root."""
    import scapy.arch  # noqa: F401 - sets conf.L2listen for this operating system
    from scapy.config import conf
    from scapy.error import Scapy_Exception

    try:
        try:
            # A kernel (BPF) filter, so only ARP frames reach Python.
            return conf.L2listen(iface=iface, filter="arp")
        except Scapy_Exception as exc:  # no libpcap/tcpdump to compile the filter
            log.info("no kernel ARP filter (%s); filtering in Python", exc)
            return conf.L2listen(iface=iface)
    except PermissionError as exc:
        raise CapturePermissionError(
            "capturing packets needs root (or CAP_NET_RAW). Run it with sudo, "
            "or replay a capture file with --pcap."
        ) from exc


def capture_arp(sock, on_packet: Callable[[ArpPacket], None], stop: threading.Event) -> None:
    """Feed ARP packets from `sock` to `on_packet` until `stop` is set. Closes `sock`."""
    from scapy.layers.l2 import ARP
    from scapy.sendrecv import sniff

    def handle(pkt) -> None:
        # Scapy closes the socket if this callback raises, which would end the
        # capture silently, so nothing may escape from here.
        try:
            arp = packet_from_scapy(pkt)
            if arp:
                on_packet(arp)
        except Exception:  # noqa: BLE001
            log.exception("error while handling a packet")

    try:
        while not stop.is_set():
            sniff(
                opened_socket=sock,
                prn=handle,
                lfilter=lambda p: ARP in p,
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
