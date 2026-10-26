from datetime import timedelta

from netguard.detectors.portscan import PortScanSettings, PortScanWatch, TcpSyn
from tests.conftest import T0

SCANNER = "de:ad:be:ef:00:01"
ME = "e8:84:a5:00:00:01"
LAPTOP = "192.168.1.50"


def syn(port, dst=LAPTOP, src_ip="192.168.1.66", src_mac=SCANNER, seconds=0.0):
    return TcpSyn(src_mac, src_ip, dst, port, T0 + timedelta(seconds=seconds))


def feed_all(watch, packets):
    return [alert for pkt in packets for alert in watch.feed(pkt)]


def test_vertical_scan_alerts_once_at_the_threshold():
    watch = PortScanWatch(settings=PortScanSettings(ports=15))
    alerts = feed_all(watch, [syn(port, seconds=port * 0.01) for port in range(1, 101)])
    [alert] = alerts
    assert (alert.kind, alert.severity, alert.ip, alert.mac) == (
        "port_scan",
        "warning",
        "192.168.1.66",
        SCANNER,
    )
    assert "scanned 15 ports on 192.168.1.50" in alert.message
    assert "1, 2, 3, 4, 5, 6, 7, 8, 9, 10 and 5 more" in alert.message


def test_normal_browsing_is_quiet():
    # A browser opens many connections, but to few ports (80, 443).
    watch = PortScanWatch()
    packets = [syn(443 if n % 2 else 80, seconds=n * 0.2) for n in range(200)]
    assert feed_all(watch, packets) == []


def test_ports_spread_over_more_than_the_window_are_not_a_scan():
    watch = PortScanWatch(settings=PortScanSettings(window=timedelta(seconds=60), ports=15))
    # One new port every 10 seconds: at most 7 inside any 60 s window.
    assert feed_all(watch, [syn(port, seconds=port * 10) for port in range(1, 40)]) == []


def test_horizontal_sweep():
    watch = PortScanWatch(settings=PortScanSettings(hosts=10))
    packets = [syn(22, dst=f"192.168.1.{n}", seconds=n * 0.01) for n in range(1, 30)]
    [alert] = feed_all(watch, packets)
    assert alert.kind == "host_sweep"
    assert "probed port 22 on 10 hosts" in alert.message


def test_two_scanners_are_reported_separately():
    watch = PortScanWatch(settings=PortScanSettings(ports=5))
    packets = [syn(p, src_ip="192.168.1.66") for p in range(1, 6)]
    packets += [syn(p, src_ip="192.168.1.77", src_mac="aa:aa:aa:aa:aa:77") for p in range(1, 6)]
    assert [a.ip for a in feed_all(watch, packets)] == ["192.168.1.66", "192.168.1.77"]


def test_own_machine_and_allowed_sources_are_ignored():
    watch = PortScanWatch(own_macs={ME}, allow_ips={"192.168.1.5"}, settings=PortScanSettings(ports=5))
    mine = [syn(p, src_mac=ME, src_ip="192.168.1.50", dst="192.168.1.1") for p in range(1, 50)]
    allowed = [syn(p, src_ip="192.168.1.5", src_mac="aa:aa:aa:aa:aa:05") for p in range(1, 50)]
    assert feed_all(watch, mine + allowed) == []


def test_tracked_sources_are_capped():
    # A scan with spoofed source IPs must not grow memory without limit.
    watch = PortScanWatch(settings=PortScanSettings(max_sources=100))
    for n in range(5000):
        watch.feed(syn(80, src_ip=f"10.{n // 65536}.{n // 256 % 256}.{n % 256}"))
    assert watch.tracked_sources == 100


def test_recently_active_source_survives_the_cap():
    watch = PortScanWatch(settings=PortScanSettings(max_sources=3, ports=5))
    for port in range(1, 5):  # four ports from the scanner...
        watch.feed(syn(port))
        watch.feed(syn(80, src_ip=f"10.0.0.{port}"))  # ...mixed with other sources
    # The scanner was active recently, so its history is still there.
    assert [a.kind for a in watch.feed(syn(5))] == ["port_scan"]
