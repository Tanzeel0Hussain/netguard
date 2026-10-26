import socket
import struct
import threading

import pytest

from netguard import cli
from netguard.names import (
    DeviceName,
    find_name,
    find_names,
    mdns_name,
    mdns_query,
    netbios_name,
    netbios_query,
    parse_mdns_answer,
    parse_netbios_answer,
    reverse_dns,
)
from tests.conftest import obs

LOCAL = "127.0.0.1"


def mdns_answer(query: bytes, name: str) -> bytes:
    """A DNS response that answers the query's PTR question, using a compression pointer."""
    question = query[12:]
    header = struct.pack("!HHHHHH", struct.unpack("!H", query[:2])[0], 0x8400, 1, 1, 0, 0)
    target = b"".join(bytes([len(p)]) + p.encode() for p in name.split(".")) + b"\0"
    answer = struct.pack("!H", 0xC00C) + struct.pack("!HHIH", 12, 1, 120, len(target)) + target
    return header + question + answer


def netbios_answer(query: bytes, names: list[tuple[str, int, int]]) -> bytes:
    """A node status response listing (name, suffix, flags)."""
    header = struct.pack("!HHHHHH", struct.unpack("!H", query[:2])[0], 0x8400, 0, 1, 0, 0)
    entries = b"".join(n.ljust(15).encode() + bytes([suffix]) + struct.pack("!H", flags) for n, suffix, flags in names)
    rdata = bytes([len(names)]) + entries + b"\0" * 46  # statistics block
    return header + query[12:12 + 34] + struct.pack("!HHIH", 0x21, 1, 0, len(rdata)) + rdata


@pytest.fixture
def udp_responder():
    """A UDP server on 127.0.0.1 that answers each packet with reply(packet)."""
    servers = []

    def start(reply):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind((LOCAL, 0))
        sock.settimeout(5)

        def serve():
            try:
                data, addr = sock.recvfrom(4096)
                sock.sendto(reply(data), addr)
            except OSError:
                pass

        threading.Thread(target=serve, daemon=True).start()
        servers.append(sock)
        return sock.getsockname()[1]

    yield start
    for sock in servers:
        sock.close()


def test_mdns_query_asks_for_the_reverse_name():
    query = mdns_query("192.168.1.30")
    assert b"\x0230\x011\x03168\x03192\x07in-addr\x04arpa\x00" in query
    assert query.endswith(struct.pack("!HH", 12, 1))


def test_mdns_name_from_a_device(udp_responder):
    port = udp_responder(lambda q: mdns_answer(q, "Living-Room-TV.local"))
    assert mdns_name(LOCAL, timeout=2, port=port) == "Living-Room-TV"


def test_netbios_name_skips_group_names(udp_responder):
    names = [("WORKGROUP", 0x00, 0x8400), ("DESKTOP-7Q2K", 0x00, 0x0400), ("DESKTOP-7Q2K", 0x20, 0x0400)]
    port = udp_responder(lambda q: netbios_answer(q, names))
    assert netbios_name(LOCAL, timeout=2, port=port) == "DESKTOP-7Q2K"


def test_netbios_query_is_a_node_status_request():
    query = netbios_query()
    assert query[12] == 32 and query[13:15] == b"CK"  # "*" encoded
    assert query.endswith(struct.pack("!HH", 0x21, 1))


def test_silent_devices_give_no_name():
    free = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    free.bind((LOCAL, 0))
    port = free.getsockname()[1]  # bound but never answers
    try:
        assert mdns_name(LOCAL, timeout=0.2, port=port) is None
        assert netbios_name(LOCAL, timeout=0.2, port=port) is None
    finally:
        free.close()


@pytest.mark.parametrize("data", [b"", b"\x00" * 12, b"\xff" * 40, b"\x00\x00\x00\x00\x00\x01\x00\x01" + b"\xc0" * 30])
def test_garbage_answers_are_ignored(data):
    assert parse_mdns_answer(data) is None
    assert parse_netbios_answer(data) is None


def test_reverse_dns_uses_the_resolver_and_times_out():
    assert reverse_dns("192.168.1.5", lookup=lambda ip: ("printer.home", [], [ip])) == "printer.home"

    def unknown(ip):
        raise socket.herror(1, "Unknown host")

    assert reverse_dns("192.168.1.5", lookup=unknown) is None

    slow = threading.Event()
    assert reverse_dns("192.168.1.5", timeout=0.1, lookup=lambda ip: slow.wait(2)) is None


def test_sources_are_tried_in_order_and_useless_names_skipped():
    resolvers = [("dns", lambda ip: "_gateway"), ("mdns", lambda ip: None), ("netbios", lambda ip: "ROUTER")]
    assert find_name("192.168.1.1", resolvers) == DeviceName("ROUTER", "netbios")
    assert find_name("192.168.1.2", [("dns", lambda ip: None)]) is None


def test_find_names_looks_up_each_ip_once():
    asked = []

    def dns(ip):
        asked.append(ip)
        return f"host-{ip.rsplit('.', 1)[1]}" if ip != "192.168.1.9" else None

    found = find_names(["192.168.1.5", "192.168.1.9", "192.168.1.5"], [("dns", dns)])
    assert found == {"192.168.1.5": DeviceName("host-5", "dns")}
    assert sorted(asked) == ["192.168.1.5", "192.168.1.9"]


def test_scan_saves_names_and_asks_only_for_unnamed_devices(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("HOME", str(tmp_path))
    found = [obs("192.168.1.30", "aa:aa:aa:aa:aa:30"), obs("192.168.1.40", "aa:aa:aa:aa:aa:40")]
    monkeypatch.setattr(cli, "discover", lambda *a, **kw: list(found))
    asked = []

    def fake_find_names(ips):
        asked.append(sorted(ips))
        return {ip: DeviceName("Living-Room-TV", "mdns") for ip in ips if ip == "192.168.1.30"}

    monkeypatch.setattr(cli, "find_names", fake_find_names)
    db = str(tmp_path / "netguard.db")
    for _ in range(2):
        assert cli.main(["--db", db, "scan", "--network", "192.168.1.0/24"]) == 0
    assert asked == [["192.168.1.30", "192.168.1.40"], ["192.168.1.40"]]

    capsys.readouterr()
    cli.main(["--db", db, "devices"])
    assert "Living-Room-TV" in capsys.readouterr().out

    asked.clear()
    cli.main(["--db", db, "scan", "--network", "192.168.1.0/24", "--no-names"])
    assert asked == []
