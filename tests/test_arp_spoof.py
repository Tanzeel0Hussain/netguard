from datetime import timedelta

from netguard.detectors.arp_spoof import (
    OP_REPLY,
    OP_REQUEST,
    ArpPacket,
    ArpWatch,
    ArpWatchSettings,
)
from tests.conftest import T0

GATEWAY_IP = "192.168.1.1"
ROUTER = "8c:6d:77:00:00:01"
ROUTER_2 = "8c:6d:77:00:00:02"  # a second access point's router
ME = "e8:84:a5:00:00:01"
PHONE = "aa:aa:aa:aa:aa:01"
ATTACKER = "de:ad:be:ef:00:01"
BROADCAST = "ff:ff:ff:ff:ff:ff"


def reply(sender_mac, sender_ip, at=T0, target_mac=ME, target_ip="192.168.1.50"):
    return ArpPacket(OP_REPLY, sender_mac, sender_ip, target_mac, target_ip, at)


def request(sender_mac, sender_ip, target_ip, at=T0):
    return ArpPacket(OP_REQUEST, sender_mac, sender_ip, "00:00:00:00:00:00", target_ip, at)


def watch(**kwargs):
    defaults = dict(gateway_ip=GATEWAY_IP, gateway_macs={ROUTER}, own_macs={ME})
    return ArpWatch(**{**defaults, **kwargs})


def kinds(findings):
    return [a.kind for a in findings.alerts]


def test_normal_gateway_traffic_is_quiet():
    w = watch()
    assert kinds(w.feed(request(ME, "192.168.1.50", GATEWAY_IP))) == []
    assert kinds(w.feed(reply(ROUTER, GATEWAY_IP, T0 + timedelta(milliseconds=3)))) == []


def test_gateway_claimed_by_another_mac_is_critical():
    findings = watch().feed(reply(ATTACKER, GATEWAY_IP))
    [alert] = findings.alerts
    assert (alert.kind, alert.severity, alert.mac, alert.ip) == (
        "gateway_mac_changed",
        "critical",
        ATTACKER,
        GATEWAY_IP,
    )
    assert "expected 8c:6d:77:00:00:01" in alert.message


def test_gateway_is_learned_once_on_a_new_access_point():
    w = watch(gateway_macs=set())
    findings = w.feed(reply(ROUTER_2, GATEWAY_IP))
    assert kinds(findings) == []
    assert [(e.kind, e.mac) for e in findings.events] == [("gateway_learned", ROUTER_2)]
    # From now on another MAC for the gateway is suspicious.
    assert kinds(w.feed(reply(ATTACKER, GATEWAY_IP))) == ["gateway_mac_changed"]


def test_roaming_to_another_access_point_is_not_an_attack():
    # The case found on a real network: two routers, one per floor, same
    # gateway IP. Each access point has its own accepted gateway MAC.
    first_floor = watch(gateway_macs={ROUTER})
    second_floor = watch(gateway_macs={ROUTER_2})
    assert kinds(first_floor.feed(reply(ROUTER, GATEWAY_IP))) == []
    assert kinds(second_floor.feed(reply(ROUTER_2, GATEWAY_IP))) == []


def test_ip_moving_to_another_mac_is_a_warning():
    w = watch(bindings={"192.168.1.10": PHONE})
    [alert] = w.feed(reply(ATTACKER, "192.168.1.10")).alerts
    assert (alert.kind, alert.severity) == ("ip_mac_changed", "warning")
    assert PHONE in alert.message and ATTACKER in alert.message


def test_one_mac_claiming_many_ips():
    w = watch()
    found = []
    for n, ip in enumerate(["192.168.1.10", "192.168.1.11", "192.168.1.12"]):
        found += kinds(w.feed(reply(ATTACKER, ip, T0 + timedelta(seconds=n))))
    assert found == ["mac_claims_many_ips"]


def test_claims_spread_over_a_long_time_are_fine():
    w = watch()
    found = []
    for n, ip in enumerate(["192.168.1.10", "192.168.1.11", "192.168.1.12"]):
        found += kinds(w.feed(reply(PHONE, ip, T0 + timedelta(minutes=5 * n))))
    assert "mac_claims_many_ips" not in found  # e.g. DHCP gave it new addresses


def test_unsolicited_reply_flood():
    w = watch(settings=ArpWatchSettings(flood_replies=5))
    found = []
    for n in range(6):
        found += kinds(w.feed(reply(PHONE, "192.168.1.10", T0 + timedelta(seconds=n))))
    assert found == ["arp_reply_flood"]


def test_answers_to_our_questions_are_not_a_flood():
    w = watch(settings=ArpWatchSettings(flood_replies=3))
    found = []
    for n in range(6):
        at = T0 + timedelta(seconds=n)
        w.feed(request(ME, "192.168.1.50", "192.168.1.10", at))
        found += kinds(w.feed(reply(PHONE, "192.168.1.10", at + timedelta(milliseconds=2))))
    assert found == []


def test_arpspoof_style_attack_raises_each_alert_once():
    # What `arpspoof -t victim gateway` does: tell the victim, every second,
    # that the gateway IP is at the attacker's MAC.
    w = watch(settings=ArpWatchSettings(flood_replies=10))
    found = []
    for n in range(30):
        found += kinds(w.feed(reply(ATTACKER, GATEWAY_IP, T0 + timedelta(seconds=n))))
    assert found == ["gateway_mac_changed", "arp_reply_flood"]


def test_own_packets_and_probes_are_ignored():
    w = watch(bindings={"192.168.1.50": PHONE})
    assert kinds(w.feed(reply(ME, "192.168.1.50"))) == []
    probe = ArpPacket(OP_REQUEST, ATTACKER, "0.0.0.0", "00:00:00:00:00:00", GATEWAY_IP, T0)
    assert kinds(w.feed(probe)) == []


def test_kernel_cache_check_names_its_source():
    findings = watch().check_binding(GATEWAY_IP, ATTACKER, T0, source="the kernel ARP cache")
    assert "in the kernel ARP cache" in findings.alerts[0].message
