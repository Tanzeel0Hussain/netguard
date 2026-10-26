import subprocess
import sys

import pytest

pytest.importorskip("scapy")


def netguard(*args, home):
    """Run the real command in a fresh interpreter, the way a user does.

    In-process tests cannot catch Scapy bugs that depend on import order: the
    test suite imports Scapy's layers early, which hides them.
    """
    return subprocess.run(
        [sys.executable, "-m", "netguard", *args],
        capture_output=True,
        text=True,
        timeout=120,
        env={"PYTHONPATH": "src", "HOME": str(home), "PATH": "/usr/bin:/bin"},
    )


@pytest.fixture(scope="module")
def demo(tmp_path_factory):
    home = tmp_path_factory.mktemp("home")
    folder = home / "demo"
    done = netguard("demo", str(folder), home=home)
    assert done.returncode == 0, done.stderr
    return home, folder


def test_demo_creates_its_files(demo):
    _, folder = demo
    assert {p.name for p in folder.iterdir()} == {"netguard.db", "arp-spoof.pcap", "port-scan.pcap"}


def test_pcap_replay_works_in_a_fresh_process(demo):
    # Found by the demo: PcapReader picked its decoder before Ethernet was
    # registered, so `watch --pcap` saw 0 packets outside the test suite.
    home, folder = demo
    arp = netguard("watch", "--pcap", str(folder / "arp-spoof.pcap"), "--gateway", "192.168.1.1", home=home)
    assert "unknown LL type" not in arp.stderr
    assert "Done. 22 ARP packet(s), 0 TCP SYN(s), 2 alert(s)." in arp.stdout
    assert "possible ARP spoofing" in arp.stdout

    scan = netguard("watch", "--pcap", str(folder / "port-scan.pcap"), home=home)
    assert "Done. 0 ARP packet(s), 100 TCP SYN(s), 1 alert(s)." in scan.stdout


def test_demo_database_tells_a_story(demo):
    home, folder = demo
    timeline = netguard("--db", str(folder / "netguard.db"), "timeline", "--limit", "100", home=home).stdout
    for text in ("Unknown device joined", "possible ARP spoofing", "scanned 15 ports", "left", "is back", "Audited 6 device(s)"):
        assert text in timeline

    devices = netguard("--db", str(folder / "netguard.db"), "devices", home=home).stdout
    assert "IP camera" in devices and "untrusted" in devices


def test_demo_database_renders_in_the_dashboard(demo):
    pytest.importorskip("flask")
    from netguard.web import create_app

    _, folder = demo
    client = create_app(folder / "netguard.db", folder / "no-manuf").test_client()
    page = client.get("/", headers={"Host": "127.0.0.1"}).get_data(as_text=True)
    assert "1 critical" in page
    audit = client.get("/audit", headers={"Host": "127.0.0.1"}).get_data(as_text=True)
    assert "Telnet is open" in audit
