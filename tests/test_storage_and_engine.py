from datetime import timedelta

from netguard.detectors.new_device import detect_new_devices
from netguard.engine import process_scan
from tests.conftest import T0, obs

PHONE = "aa:aa:aa:aa:aa:01"
LAPTOP = "aa:aa:aa:aa:aa:02"
STRANGER = "de:ad:be:ef:00:01"


def test_first_scan_is_a_baseline_without_alerts(store):
    result = process_scan(store, [obs("192.168.1.10", PHONE)], "arp-scan", "192.168.1.0/24", T0)
    assert result.baseline is True
    assert result.alerts == []
    assert store.known_macs() == {PHONE}


def test_unknown_device_on_a_later_scan_raises_one_alert(store):
    process_scan(store, [obs("192.168.1.10", PHONE)], "arp-scan", "192.168.1.0/24", T0)
    later = T0 + timedelta(minutes=5)
    seen = [obs("192.168.1.10", PHONE, later), obs("192.168.1.66", STRANGER, later)]

    result = process_scan(store, seen, "arp-scan", "192.168.1.0/24", later)

    assert result.baseline is False
    assert [(a.kind, a.mac, a.ip) for a in result.alerts] == [
        ("new_device", STRANGER, "192.168.1.66")
    ]
    assert store.alerts()[0].message == f"Unknown device joined: {STRANGER} at 192.168.1.66"

    # Seen again: it is in the inventory now, so no second alert.
    again = process_scan(store, seen, "arp-scan", "192.168.1.0/24", later)
    assert again.alerts == []


def test_rescan_updates_ip_and_last_seen_but_keeps_first_seen(store):
    store.record_scan([obs("192.168.1.10", PHONE)], "arp-scan", "net", T0)
    later = T0 + timedelta(hours=1)
    store.record_scan([obs("192.168.1.11", PHONE, later)], "arp-scan", "net", later)

    device = store.device(PHONE)
    assert device.ip == "192.168.1.11"
    assert device.first_seen == T0
    assert device.last_seen == later


def test_trust_and_label(store):
    store.record_scan([obs("192.168.1.10", PHONE), obs("192.168.1.12", LAPTOP)], "arp-scan", "net", T0)

    assert store.set_trusted(PHONE, True, label="My phone")
    assert store.set_trusted(STRANGER, True) is False  # not in the inventory
    assert [d.mac for d in store.devices(untrusted_only=True)] == [LAPTOP]

    # Untrusting keeps the label.
    store.set_trusted(PHONE, False)
    phone = store.device(PHONE)
    assert (phone.trusted, phone.label) == (False, "My phone")


def test_detector_alerts_once_per_mac_even_with_two_ips():
    seen = [obs("192.168.1.66", STRANGER), obs("192.168.1.67", STRANGER)]
    alerts = detect_new_devices(seen, known_macs=set(), baseline=False, now=T0)
    assert len(alerts) == 1


def test_gateway_macs_are_kept_per_access_point(store):
    store.add_gateway_mac("8c:6d:77:00:00:ec", "192.168.1.1", "8c:6d:77:00:00:01", T0)
    store.add_gateway_mac("8c:6d:77:00:00:ec", "192.168.1.1", "8c:6d:77:00:00:01", T0)  # no duplicate
    store.add_gateway_mac("04:88:5f:00:00:ec", "192.168.1.1", "04:88:5f:00:00:01", T0)

    assert store.gateway_macs("8c:6d:77:00:00:ec", "192.168.1.1") == {"8c:6d:77:00:00:01"}
    assert store.gateway_macs("wired", "192.168.1.1") == set()
    assert len(store.all_gateway_macs()) == 2
