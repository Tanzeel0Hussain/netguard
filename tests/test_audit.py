import asyncio
import socket
import socketserver
import threading

import pytest

from netguard import cli
from netguard.audit.report import AuditedHost, AuditResult, to_html, to_markdown
from netguard.audit.rules import assess
from netguard.audit.scanner import OpenPort, probe, scan_hosts
from tests.conftest import T0, obs

LOCAL = "127.0.0.1"


def closed_port() -> int:
    """A local port with nothing listening on it."""
    with socket.socket() as s:
        s.bind((LOCAL, 0))
        return s.getsockname()[1]


async def serve(handler):
    server = await asyncio.start_server(handler, LOCAL, 0)
    return server, server.sockets[0].getsockname()[1]


async def ssh_like(reader, writer):
    writer.write(b"SSH-2.0-OpenSSH_7.4\r\n")
    await writer.drain()
    writer.close()


async def http_like(reader, writer):
    request = await reader.readuntil(b"\r\n\r\n")
    assert request.startswith(b"HEAD / HTTP/1.0")  # the only thing an audit sends
    writer.write(b"HTTP/1.0 200 OK\r\nServer: lighttpd/1.4.59\r\n\r\n")
    await writer.drain()
    writer.close()


# --- scanner ----------------------------------------------------------------


def test_probe_reads_banners_and_skips_closed_ports():
    async def run():
        ssh, ssh_port = await serve(ssh_like)
        web, web_port = await serve(http_like)
        async with ssh, web:
            return (
                await probe(LOCAL, ssh_port),
                await probe(LOCAL, web_port, http=True),
                await probe(LOCAL, closed_port(), timeout=0.5),
            )

    ssh, web, closed = asyncio.run(run())
    assert ssh.banner == "SSH-2.0-OpenSSH_7.4"
    assert web.banner == "lighttpd/1.4.59"
    assert closed is None


def test_silent_service_is_still_reported_open():
    async def silent(reader, writer):
        await asyncio.sleep(2)
        writer.close()

    async def run():
        server, port = await serve(silent)
        async with server:
            return await probe(LOCAL, port, timeout=0.2)

    result = asyncio.run(run())
    assert result is not None and result.banner == ""


def test_scan_respects_the_concurrency_limit():
    state = {"open": 0, "most": 0}

    async def slow(reader, writer):
        state["open"] += 1
        state["most"] = max(state["most"], state["open"])
        await asyncio.sleep(0.1)
        state["open"] -= 1
        writer.close()

    async def run():
        servers = [await serve(slow) for _ in range(12)]
        try:
            return await scan_hosts([LOCAL], [port for _, port in servers], timeout=1, concurrency=3)
        finally:
            for server, _ in servers:
                server.close()

    found = asyncio.run(run())
    assert len(found) == 12
    assert state["most"] <= 3


# --- rules ------------------------------------------------------------------


def test_assess_flags_risky_services_most_severe_first():
    ports = [
        OpenPort("192.168.1.20", 22, "SSH-2.0-OpenSSH_7.4"),
        OpenPort("192.168.1.10", 445),
        OpenPort("192.168.1.30", 23),
        OpenPort("192.168.1.9", 6379),
        OpenPort("192.168.1.20", 631),
    ]
    findings = assess(ports)
    assert [(f.severity, f.ip, f.port) for f in findings] == [
        ("high", "192.168.1.9", 6379),
        ("high", "192.168.1.30", 23),
        ("medium", "192.168.1.10", 445),
        ("low", "192.168.1.20", 22),
    ]
    assert findings[-1].title == "Old OpenSSH 7.4"


def test_current_openssh_is_fine():
    assert assess([OpenPort("192.168.1.20", 22, "SSH-2.0-OpenSSH_9.6p1 Ubuntu")]) == []


def test_router_admin_page_over_plain_http():
    plain = assess([OpenPort("192.168.1.1", 80), OpenPort("192.168.1.1", 53)], gateway_ip="192.168.1.1")
    assert [f.title for f in plain] == ["Router admin page only over plain HTTP"]
    # Same ports on a device that is not the router, or a router with HTTPS: no finding.
    assert assess([OpenPort("192.168.1.5", 80)], gateway_ip="192.168.1.1") == []
    https = [OpenPort("192.168.1.1", 80), OpenPort("192.168.1.1", 443, tls=True)]
    assert assess(https, gateway_ip="192.168.1.1") == []


# --- report and storage ------------------------------------------------------


def sample_result():
    ports = [
        OpenPort("192.168.1.30", 23, "<script>alert(1)</script>"),
        OpenPort("192.168.1.10", 443, "", tls=True),
    ]
    return AuditResult(
        started_at=T0,
        hosts=[AuditedHost("192.168.1.30", "aa:aa:aa:aa:aa:30", "Camera"),
               AuditedHost("192.168.1.10", "aa:aa:aa:aa:aa:10")],
        ports_checked=30,
        open_ports=ports,
        findings=assess(ports),
    )


def test_markdown_report():
    text = to_markdown(sample_result())
    assert "- **Findings:** 1 high" in text
    assert "| HIGH | 192.168.1.30 | 23 | Telnet is open |" in text
    assert "### 192.168.1.10 (aa:aa:aa:aa:aa:10)" in text
    assert "| 443 | HTTPS (TLS) |" in text


def test_html_report_escapes_banners():
    page = to_html(sample_result())
    assert page.startswith("<!doctype html>")
    assert "<script>alert(1)</script>" not in page  # a device must not inject into the report
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in page
    assert '<tr class="high">' in page


def test_audit_is_saved_and_loaded(store):
    result = sample_result()
    store.save_audit(result)
    loaded = store.latest_audit()
    assert loaded.started_at == T0
    assert sorted(loaded.open_ports, key=lambda p: p.port) == sorted(result.open_ports, key=lambda p: p.port)
    assert loaded.findings == result.findings
    assert {h.name for h in loaded.hosts} == {"Camera", ""}


# --- command line -------------------------------------------------------------


@pytest.mark.parametrize(
    ("spec", "expected"),
    [("22,80,443", [22, 80, 443]), ("20-23", [20, 21, 22, 23]), ("22, 8000-8002", [22, 8000, 8001, 8002])],
)
def test_parse_ports(spec, expected):
    assert cli.parse_ports(spec) == expected


@pytest.mark.parametrize(("spec", "message"), [("abc", "bad port list"), ("0-10", "1 to 65535"), ("1-5000", "too many")])
def test_parse_ports_rejects(spec, message):
    with pytest.raises(ValueError, match=message):
        cli.parse_ports(spec)


@pytest.fixture
def cli_env(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("HOME", str(tmp_path))
    db = tmp_path / "netguard.db"

    def run(*args):
        code = cli.main(["--db", str(db), *args])
        out, err = capsys.readouterr()
        return code, out, err

    return db, run


def test_audit_refuses_devices_outside_the_inventory(cli_env):
    db, run = cli_env
    code, _, err = run("audit", "--target", "192.168.1.99")
    assert code == 1
    assert "not in the inventory" in err


class TelnetLikeHandler(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.sendall(b"login: ")


def test_audit_end_to_end_on_a_local_service(cli_env, tmp_path, monkeypatch):
    from netguard.audit import rules
    from netguard.engine import process_scan
    from netguard.storage import Store

    db, run = cli_env
    with Store(db) as store:
        process_scan(store, [obs(LOCAL, "aa:aa:aa:aa:aa:01")], "arp-scan", "127.0.0.0/8", T0)

    with socketserver.TCPServer((LOCAL, 0), TelnetLikeHandler) as server:
        threading.Thread(target=server.serve_forever, daemon=True).start()
        port = server.server_address[1]
        # Pretend the free port is Telnet's, so the rules recognise it.
        monkeypatch.setitem(rules.RISKS, port, rules.RISKS[23])

        report = tmp_path / "audit.html"
        code, out, err = run("audit", "--target", LOCAL, "--ports", str(port), "--report", str(report))
        server.shutdown()

    assert code == 0, err
    assert f"{LOCAL}  {port}" in out and "login:" in out
    assert f"[HIGH] {LOCAL}:{port} Telnet is open" in out
    assert "1 open port(s), 1 high." in out
    assert "Telnet is open" in report.read_text()

    code, out, _ = run("timeline")
    assert "Audited 1 device(s): 1 high" in out
