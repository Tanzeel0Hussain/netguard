import subprocess

import pytest

from netguard import cli
from netguard.netinfo import current_bssid, own_macs, parse_iw_link, parse_nmcli_bssid

scapy = pytest.importorskip("scapy")
from scapy.layers.inet import IP, TCP  # noqa: E402
from scapy.layers.l2 import ARP, Ether  # noqa: E402
from scapy.utils import wrpcap  # noqa: E402

from netguard.sensor.arp_sniffer import packet_from_scapy, read_pcap  # noqa: E402

GATEWAY_IP = "192.168.1.1"
ROUTER = "8c:6d:77:00:00:01"
VICTIM = "aa:aa:aa:aa:aa:50"
ATTACKER = "de:ad:be:ef:00:01"


def arp(op, hwsrc, psrc, hwdst, pdst, t):
    pkt = Ether(src=hwsrc, dst=hwdst if op == 2 else "ff:ff:ff:ff:ff:ff") / ARP(
        op=op, hwsrc=hwsrc, psrc=psrc, hwdst=hwdst, pdst=pdst
    )
    pkt.time = t
    return pkt


def attack_capture(path):
    """A small recording: normal ARP, some unrelated TCP, then arpspoof-style poisoning."""
    t = 1_790_000_000.0
    packets = [
        arp(1, VICTIM, "192.168.1.50", "00:00:00:00:00:00", GATEWAY_IP, t),
        arp(2, ROUTER, GATEWAY_IP, VICTIM, "192.168.1.50", t + 0.002),
        Ether(src=VICTIM, dst=ROUTER) / IP(dst="192.168.1.1") / TCP(dport=443),
    ]
    packets += [
        arp(2, ATTACKER, GATEWAY_IP, VICTIM, "192.168.1.50", t + 10 + n) for n in range(20)
    ]
    wrpcap(str(path), packets)


def test_packet_from_scapy():
    pkt = arp(2, "8C:6D:77:00:00:01", GATEWAY_IP, VICTIM, "192.168.1.50", 1_790_000_000.5)
    parsed = packet_from_scapy(pkt)
    assert (parsed.op, parsed.sender_mac, parsed.sender_ip) == (2, ROUTER, GATEWAY_IP)
    assert parsed.at.timestamp() == 1_790_000_000.5
    assert packet_from_scapy(Ether() / IP()) is None


def test_read_pcap_keeps_only_arp(tmp_path):
    attack_capture(tmp_path / "attack.pcap")
    packets = list(read_pcap(tmp_path / "attack.pcap"))
    assert len(packets) == 22
    assert packets[0].sender_mac == VICTIM


def test_watch_finds_the_attack_in_a_capture(tmp_path, capsys, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    capture = tmp_path / "attack.pcap"
    attack_capture(capture)

    code = cli.main(["watch", "--pcap", str(capture), "--gateway", GATEWAY_IP])
    out = capsys.readouterr().out
    assert code == 0
    assert f"[i] Gateway {GATEWAY_IP} is at {ROUTER}" in out
    assert f"[!] Gateway {GATEWAY_IP} is claimed by {ATTACKER}" in out
    assert f"{ATTACKER} sent 15 unsolicited ARP replies" in out
    assert "Done. 22 ARP packet(s), 2 alert(s)." in out
    # Offline analysis writes nothing.
    assert not (tmp_path / ".local").exists()


def test_watch_rejects_a_file_that_is_not_a_capture(tmp_path, capsys):
    bad = tmp_path / "notes.txt"
    bad.write_text("hello")
    assert cli.main(["--db", str(tmp_path / "db"), "watch", "--pcap", str(bad)]) == 1
    assert "is not a pcap file" in capsys.readouterr().err


# --- network helpers --------------------------------------------------------


def test_parse_iw_link():
    text = "Connected to 8c:6d:77:aa:bb:cc (on wlan0)\n\tSSID: Home\n"
    assert parse_iw_link(text) == "8c:6d:77:aa:bb:cc"
    assert parse_iw_link("Not connected.\n") is None


def test_parse_nmcli_bssid():
    text = "no:11\\:22\\:33\\:44\\:55\\:66\nyes:8C\\:6D\\:77\\:AA\\:BB\\:CC\n"
    assert parse_nmcli_bssid(text) == "8c:6d:77:aa:bb:cc"


def test_current_bssid_falls_back_to_nmcli_and_then_none():
    def no_iw(argv, **kwargs):
        if argv[0] == "iw":
            raise FileNotFoundError("iw")
        return subprocess.CompletedProcess(argv, 0, stdout="yes:8C\\:6D\\:77\\:AA\\:BB\\:CC\n")

    assert current_bssid("wlan0", run=no_iw) == "8c:6d:77:aa:bb:cc"

    def wired(argv, **kwargs):
        return subprocess.CompletedProcess(argv, 1, stdout="")

    assert current_bssid("eth0", run=wired) is None


def test_own_macs(tmp_path):
    for name, mac in [("lo", "00:00:00:00:00:00"), ("wlan0", "E8:84:A5:00:00:01\n")]:
        (tmp_path / name).mkdir()
        (tmp_path / name / "address").write_text(mac)
    assert own_macs(tmp_path) == {"e8:84:a5:00:00:01"}


# --- the capture loop, fed from a file instead of a live socket ------------


def replay_socket(path):
    """A capture file that reports `closed` like a live Scapy socket does."""
    from scapy.utils import PcapReader

    reader = PcapReader(str(path))
    reader.closed = False
    original_close = reader.close

    def close():
        reader.closed = True
        original_close()

    reader.close = close
    return reader


def test_capture_survives_a_failing_handler(tmp_path):
    import threading

    from netguard.sensor.arp_sniffer import capture_arp

    attack_capture(tmp_path / "attack.pcap")
    stop, seen = threading.Event(), []

    def on_packet(pkt):
        seen.append(pkt)
        if len(seen) == 1:
            raise RuntimeError("bug in a detector")  # must not end the capture
        if len(seen) == 22:
            stop.set()

    capture_arp(replay_socket(tmp_path / "attack.pcap"), on_packet, stop)
    assert len(seen) == 22


def test_capture_reports_a_dead_socket(tmp_path):
    import threading

    from netguard.sensor.arp_sniffer import CaptureStoppedError, capture_arp

    attack_capture(tmp_path / "attack.pcap")
    with pytest.raises(CaptureStoppedError, match="interface still up"):
        # The file ends (like a socket dying) while nobody asked to stop.
        capture_arp(replay_socket(tmp_path / "attack.pcap"), lambda pkt: None, threading.Event())


def test_capture_socket_decodes_ethernet_in_a_fresh_process():
    # Found in a live run: the socket was opened before Scapy knew Ethernet,
    # so every frame was raw bytes and 0 ARP packets were seen. It only shows
    # in a fresh interpreter, because these tests import Scapy's layers early.
    import sys

    code = """
from scapy.config import conf
import netguard.sensor.arp_sniffer as sniffer
seen = {}
def fake_listen(**kwargs):
    seen["ether"] = conf.l2types.num2layer.get(1)
    return object()
import scapy.arch
conf.L2listen = fake_listen
sniffer.open_capture("wlan0")
print(seen["ether"].__name__)
"""
    done = subprocess.run(
        [sys.executable, "-c", code], capture_output=True, text=True, timeout=60,
        env={"PYTHONPATH": "src", "PATH": "/usr/bin:/bin"},
    )
    assert done.returncode == 0, done.stderr
    assert done.stdout.strip() == "Ether"
