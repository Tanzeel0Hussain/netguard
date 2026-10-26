import ipaddress

import pytest

from netguard.netinfo import UnsafeTargetError, detect_netinfo, validate_scan_target

# Captured from a laptop on Wi-Fi with two VMware host-only networks.
ROUTE_TABLE = """\
Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT
wlp0s20f3\t00000000\t0164A8C0\t0003\t0\t0\t600\t00000000\t0\t0\t0
vmnet1\t009E10AC\t00000000\t0001\t0\t0\t0\t00FFFFFF\t0\t0\t0
vmnet8\t009F10AC\t00000000\t0001\t0\t0\t0\t00FFFFFF\t0\t0\t0
wlp0s20f3\t0064A8C0\t00000000\t0001\t0\t0\t600\t00FFFFFF\t0\t0\t0
"""


def test_detects_default_interface_subnet_and_gateway():
    info = detect_netinfo(ROUTE_TABLE)
    assert info.iface == "wlp0s20f3"
    assert info.network == ipaddress.IPv4Network("192.168.100.0/24")
    assert info.gateway == ipaddress.IPv4Address("192.168.100.1")


def test_can_pick_another_interface():
    info = detect_netinfo(ROUTE_TABLE, iface="vmnet8")
    assert info.network == ipaddress.IPv4Network("172.16.159.0/24")
    assert info.gateway is None


def test_no_default_route_is_an_error():
    only_header = ROUTE_TABLE.splitlines()[0]
    with pytest.raises(RuntimeError, match="no default route"):
        detect_netinfo(only_header)


@pytest.mark.parametrize("cidr", ["192.168.1.0/24", "10.0.0.0/20", "172.16.5.0/24"])
def test_private_lan_targets_are_allowed(cidr):
    validate_scan_target(ipaddress.IPv4Network(cidr))


@pytest.mark.parametrize("cidr", ["8.8.8.0/24", "1.1.1.1/32"])
def test_public_targets_are_refused(cidr):
    with pytest.raises(UnsafeTargetError, match="not a private network"):
        validate_scan_target(ipaddress.IPv4Network(cidr))


def test_huge_targets_are_refused():
    with pytest.raises(UnsafeTargetError, match="the limit is"):
        validate_scan_target(ipaddress.IPv4Network("10.0.0.0/8"))
