"""Made-up data to try NetGuard without a network, e.g. to show it to someone.

`netguard demo DIR` writes a database with a week of history and two packet
captures of attacks. No real device is described: every MAC uses a real
vendor prefix with invented last three bytes.
"""

from __future__ import annotations

from datetime import datetime, timedelta
from pathlib import Path

from netguard.audit.report import AuditedHost, AuditResult
from netguard.audit.rules import assess
from netguard.audit.scanner import OpenPort
from netguard.engine import process_scan, record_findings
from netguard.models import Alert, Event, Observation, utcnow
from netguard.storage import Store

NETWORK = "192.168.1.0/24"
GATEWAY_IP = "192.168.1.1"

# (ip, mac, label, trusted)
DEVICES = [
    ("192.168.1.1", "8c:6d:77:10:20:01", "Router", True),
    ("192.168.1.10", "f0:18:98:10:20:10", "Laptop", True),
    ("192.168.1.21", "6e:11:22:33:44:21", "Phone", True),
    ("192.168.1.30", "b0:be:76:10:20:30", "Smart TV", True),
    ("192.168.1.40", "70:b3:d5:f2:f0:40", "IP camera", False),
    ("192.168.1.50", "3c:84:6a:10:20:50", "Printer", True),
]
VISITOR = ("192.168.1.66", "de:ad:be:ef:00:66")
VICTIM = ("192.168.1.10", "f0:18:98:10:20:10")


def build_demo(folder: Path) -> dict[str, Path]:
    """Create the demo files in `folder` and return their paths."""
    folder.mkdir(parents=True, exist_ok=True)
    paths = {
        "db": folder / "netguard.db",
        "arp_pcap": folder / "arp-spoof.pcap",
        "scan_pcap": folder / "port-scan.pcap",
    }
    paths["db"].unlink(missing_ok=True)
    _fill_database(paths["db"], utcnow())
    write_arp_spoof_pcap(paths["arp_pcap"])
    write_port_scan_pcap(paths["scan_pcap"])
    return paths


def _scan(store: Store, devices, at: datetime) -> None:
    observations = [Observation(ip, mac, "arp-scan", at) for ip, mac, *_ in devices]
    process_scan(store, observations, "arp-scan", NETWORK, at, away_after=timedelta(minutes=15))


def _fill_database(path: Path, now: datetime) -> None:
    start = now - timedelta(days=7)
    with Store(path) as store:
        _scan(store, DEVICES, start)  # the baseline
        for ip, mac, label, trusted in DEVICES:
            store.set_trusted(mac, trusted, label=label)
        store.add_gateway_mac("8c:6d:77:10:20:ec", GATEWAY_IP, DEVICES[0][1], start)

        # The phone leaves for the day and comes back in the evening.
        without_phone = [d for d in DEVICES if d[2] != "Phone"]
        _scan(store, without_phone, start + timedelta(days=1, hours=8))
        _scan(store, DEVICES, start + timedelta(days=1, hours=18))

        # Yesterday evening an unknown device joined.
        joined = now - timedelta(hours=20)
        _scan(store, [*DEVICES, (*VISITOR, "", False)], joined)

        # ...and this morning it tried to become the gateway, then scanned the laptop.
        attack = now - timedelta(hours=3)
        alerts = [
            Alert(
                "gateway_mac_changed", "critical",
                f"Gateway {GATEWAY_IP} is claimed by {VISITOR[1]} (expected {DEVICES[0][1]}) "
                "in ARP: possible ARP spoofing / man-in-the-middle",
                attack, VISITOR[1], GATEWAY_IP,
            ),
            Alert(
                "arp_reply_flood", "warning",
                f"{VISITOR[1]} sent 15 unsolicited ARP replies in 60s (claiming {GATEWAY_IP})",
                attack + timedelta(seconds=14), VISITOR[1], GATEWAY_IP,
            ),
            Alert(
                "port_scan", "warning",
                f"{VISITOR[0]} ({VISITOR[1]}) scanned 15 ports on {VICTIM[0]} in 60s: "
                "21, 22, 23, 25, 53, 80, 110, 135, 139, 143 and 5 more",
                attack + timedelta(minutes=6), VISITOR[1], VISITOR[0],
            ),
        ]
        record_findings(store, alerts, [], now, timedelta(hours=1))

        # Then an audit of the devices.
        ports = [
            OpenPort("192.168.1.1", 53),
            OpenPort("192.168.1.1", 80, "HTTP/1.1 404 Not Found"),
            OpenPort("192.168.1.10", 22, "SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13"),
            OpenPort("192.168.1.30", 8008, ""),
            OpenPort("192.168.1.40", 23, "login:"),
            OpenPort("192.168.1.40", 554, ""),
            OpenPort("192.168.1.40", 80, "GoAhead-Webs"),
            OpenPort("192.168.1.50", 631, ""),
            OpenPort("192.168.1.50", 9100, ""),
        ]
        audited = now - timedelta(hours=1)
        result = AuditResult(
            started_at=audited,
            hosts=[AuditedHost(ip, mac, label) for ip, mac, label, _ in DEVICES],
            ports_checked=30,
            open_ports=ports,
            findings=assess(ports, gateway_ip=GATEWAY_IP),
        )
        store.save_audit(result)
        counts = result.counts()
        summary = ", ".join(f"{counts[s]} {s}" for s in ("high", "medium", "low") if counts[s])
        store.add_events([Event("audit", f"Audited {len(DEVICES)} device(s): {summary}", audited)])


# --- packet captures ----------------------------------------------------------

PCAP_START = 1_790_000_000.0  # any fixed time works; the detectors only compare gaps


def _arp(op: int, hwsrc: str, psrc: str, hwdst: str, pdst: str, t: float):
    from scapy.layers.l2 import ARP, Ether

    pkt = Ether(src=hwsrc, dst=hwdst if op == 2 else "ff:ff:ff:ff:ff:ff") / ARP(
        op=op, hwsrc=hwsrc, psrc=psrc, hwdst=hwdst, pdst=pdst
    )
    pkt.time = t
    return pkt


def write_arp_spoof_pcap(path: Path) -> None:
    """Normal ARP, then what `arpspoof -t <victim> <gateway>` sends: one lie per second."""
    from scapy.utils import wrpcap

    router_mac = DEVICES[0][1]
    victim_ip, victim_mac = VICTIM
    t = PCAP_START
    packets = [
        _arp(1, victim_mac, victim_ip, "00:00:00:00:00:00", GATEWAY_IP, t),
        _arp(2, router_mac, GATEWAY_IP, victim_mac, victim_ip, t + 0.002),
    ]
    packets += [
        _arp(2, VISITOR[1], GATEWAY_IP, victim_mac, victim_ip, t + 10 + n) for n in range(20)
    ]
    wrpcap(str(path), packets)


def write_port_scan_pcap(path: Path, ports=range(1, 101)) -> None:
    """What `nmap -sS -p1-100 <victim>` looks like: SYNs a few milliseconds apart."""
    from scapy.layers.inet import IP, TCP
    from scapy.layers.l2 import Ether
    from scapy.utils import wrpcap

    packets = []
    for n, port in enumerate(ports):
        pkt = Ether(src=VISITOR[1], dst=VICTIM[1]) / IP(src=VISITOR[0], dst=VICTIM[0]) / TCP(
            sport=40000, dport=port, flags="S"
        )
        pkt.time = PCAP_START + n * 0.005
        packets.append(pkt)
    wrpcap(str(path), packets)
