from datetime import timedelta

from netguard.detectors.presence import detect_presence_changes
from netguard.engine import process_scan
from netguard.models import Device
from tests.conftest import T0, obs

PHONE = "aa:aa:aa:aa:aa:01"
TV = "aa:aa:aa:aa:aa:02"
AWAY = timedelta(minutes=15)


def device(mac, last_seen=T0, present=True, label=None, ip="192.168.1.10"):
    return Device(mac=mac, ip=ip, first_seen=T0, last_seen=last_seen, present=present, label=label)


def kinds(events):
    return [(e.kind, e.mac) for e in events]


def test_missing_device_only_leaves_after_the_away_time():
    devices = [device(PHONE)]
    soon = T0 + timedelta(minutes=5)
    assert detect_presence_changes(devices, [], soon, AWAY) == []

    later = T0 + timedelta(minutes=15)
    assert kinds(detect_presence_changes(devices, [], later, AWAY)) == [("left", PHONE)]


def test_device_that_already_left_does_not_leave_again():
    devices = [device(PHONE, present=False)]
    assert detect_presence_changes(devices, [], T0 + timedelta(hours=3), AWAY) == []


def test_device_coming_back_and_first_seen_devices():
    devices = [device(PHONE, present=False, label="My phone")]
    now = T0 + timedelta(hours=1)
    events = detect_presence_changes(
        devices, [obs("192.168.1.11", PHONE, now), obs("192.168.1.20", TV, now)], now, AWAY
    )
    assert kinds(events) == [("returned", PHONE), ("first_seen", TV)]
    assert events[0].message == f"My phone ({PHONE}) is back at 192.168.1.11"


def test_engine_tracks_a_device_leaving_and_returning(store):
    net = "192.168.1.0/24"
    process_scan(store, [obs("192.168.1.10", PHONE), obs("192.168.1.20", TV)], "arp-scan", net, T0)

    later = T0 + timedelta(minutes=20)
    result = process_scan(store, [obs("192.168.1.20", TV, later)], "arp-scan", net, later)
    assert kinds(result.events) == [("left", PHONE)]
    assert store.device(PHONE).present is False
    assert store.device(TV).present is True

    back = later + timedelta(minutes=5)
    result = process_scan(store, [obs("192.168.1.10", PHONE, back)], "arp-scan", net, back)
    assert kinds(result.events) == [("returned", PHONE)]
    assert store.device(PHONE).present is True

    timeline = [(e.kind, e.mac) for e in store.events()]
    assert timeline[:2] == [("returned", PHONE), ("left", PHONE)]
    assert {("first_seen", PHONE), ("first_seen", TV)} <= set(timeline)


def test_incomplete_scan_never_reports_left():
    # Found on a real network: the kernel ARP cache only held the router, and
    # both phones were wrongly reported as gone.
    devices = [device(PHONE)]
    later = T0 + timedelta(hours=1)
    assert detect_presence_changes(devices, [], later, AWAY, complete=False) == []


def test_passive_scan_can_still_see_a_device_return(store):
    net = "192.168.1.0/24"
    process_scan(store, [obs("192.168.1.10", PHONE)], "arp-scan", net, T0)
    later = T0 + timedelta(hours=1)
    assert process_scan(store, [], "arp-table", net, later).events == []
    assert store.device(PHONE).present is True

    process_scan(store, [], "arp-scan", net, later)  # active scan: really gone
    assert store.device(PHONE).present is False
    back = later + timedelta(minutes=1)
    passive = process_scan(store, [obs("192.168.1.10", PHONE, back)], "arp-table", net, back)
    assert kinds(passive.events) == [("returned", PHONE)]
