import ipaddress

import pytest

from netguard import discovery
from netguard.discovery.arp_table import parse_arp_table
from tests.conftest import obs

ARP_TABLE = """\
IP address       HW type     Flags       HW address            Mask     Device
192.168.100.1    0x1         0x2         04:88:5F:12:34:56     *        wlp0s20f3
192.168.100.11   0x1         0x2         52:54:00:a1:b2:c3     *        wlp0s20f3
192.168.100.40   0x1         0x0         00:00:00:00:00:00     *        wlp0s20f3
172.16.159.2     0x1         0x2         00:50:56:f0:00:01     *        vmnet8
"""

NETWORK = ipaddress.IPv4Network("192.168.100.0/24")


def test_arp_table_skips_incomplete_entries():
    found = parse_arp_table(ARP_TABLE)
    assert [(o.ip, o.mac) for o in found] == [
        ("192.168.100.1", "04:88:5f:12:34:56"),
        ("192.168.100.11", "52:54:00:a1:b2:c3"),
        ("172.16.159.2", "00:50:56:f0:00:01"),
    ]
    assert {o.source for o in found} == {"arp-table"}


def test_arp_table_can_filter_by_interface():
    found = parse_arp_table(ARP_TABLE, iface="vmnet8")
    assert [o.ip for o in found] == ["172.16.159.2"]


def test_discover_keeps_only_the_target_network_and_dedupes(monkeypatch):
    fake = [
        obs("192.168.100.20", "aa:aa:aa:aa:aa:20"),
        obs("192.168.100.3", "aa:aa:aa:aa:aa:03"),
        obs("192.168.100.3", "aa:aa:aa:aa:aa:03"),
        obs("10.9.9.9", "aa:aa:aa:aa:aa:99"),
    ]
    monkeypatch.setattr(discovery, "arp_scan", lambda *a, **kw: fake)
    found = discovery.discover(NETWORK)
    # Sorted numerically: .3 comes before .20.
    assert [o.ip for o in found] == ["192.168.100.3", "192.168.100.20"]


# --- active scan, with Scapy's srp() replaced so no packets are sent --------

scapy = pytest.importorskip("scapy")


def test_arp_scan_turns_replies_into_observations(monkeypatch):
    from scapy.layers.l2 import ARP, Ether

    from netguard.discovery.arp_scan import arp_scan

    sent = {}

    def fake_srp(packet, **kwargs):
        sent["packet"], sent["kwargs"] = packet, kwargs
        reply = Ether(src="52:54:00:a1:b2:c3") / ARP(
            op=2, psrc="192.168.100.11", hwsrc="52:54:00:A1:B2:C3"
        )
        return [(packet, reply)], []

    monkeypatch.setattr("scapy.sendrecv.srp", fake_srp)
    found = arp_scan(NETWORK, iface="wlp0s20f3", timeout=1.5)

    assert [(o.ip, o.mac, o.source) for o in found] == [
        ("192.168.100.11", "52:54:00:a1:b2:c3", "arp-scan")
    ]
    assert sent["packet"][Ether].dst == "ff:ff:ff:ff:ff:ff"
    assert sent["packet"][ARP].pdst == "192.168.100.0/24"
    assert sent["kwargs"]["iface"] == "wlp0s20f3"
    assert sent["kwargs"]["timeout"] == 1.5


def test_arp_scan_without_root_gives_a_helpful_error(monkeypatch):
    from netguard.discovery.arp_scan import ScanPermissionError, arp_scan

    def no_root(*args, **kwargs):
        raise PermissionError(1, "Operation not permitted")

    monkeypatch.setattr("scapy.sendrecv.srp", no_root)
    with pytest.raises(ScanPermissionError, match="--passive"):
        arp_scan(NETWORK)
