from datetime import timedelta

import pytest

pytest.importorskip("flask")

from netguard import cli  # noqa: E402
from netguard.audit.report import AuditedHost, AuditResult  # noqa: E402
from netguard.audit.rules import assess  # noqa: E402
from netguard.audit.scanner import OpenPort  # noqa: E402
from netguard.engine import process_scan  # noqa: E402
from netguard.models import Alert, utcnow  # noqa: E402
from netguard.storage import Store  # noqa: E402
from netguard.web import create_app, hostname, is_loopback  # noqa: E402
from tests.conftest import obs  # noqa: E402

ROUTER = "8c:6d:77:00:00:01"
PHONE = "6e:11:22:33:44:73"
XSS = "<script>alert(1)</script>"


@pytest.fixture
def db(tmp_path):
    path = tmp_path / "netguard.db"
    now = utcnow()
    with Store(path) as store:
        process_scan(store, [obs("192.168.1.1", ROUTER, now)], "arp-scan", "192.168.1.0/24", now)
        process_scan(store, [obs("192.168.1.1", ROUTER, now), obs("192.168.1.73", PHONE, now)],
                     "arp-scan", "192.168.1.0/24", now)
        store.set_trusted(ROUTER, True, label="Router")
        store.add_alerts([Alert("gateway_mac_changed", "critical", f"Gateway claimed {XSS}", now, PHONE, "192.168.1.1")])
        ports = [OpenPort("192.168.1.1", 80, XSS), OpenPort("192.168.1.1", 53)]
        store.save_audit(
            AuditResult(now, [AuditedHost("192.168.1.1", ROUTER, "Router")], 30, ports,
                        assess(ports, gateway_ip="192.168.1.1"))
        )
    return path


@pytest.fixture
def client(db, tmp_path):
    app = create_app(db, tmp_path / "no-manuf")
    return app.test_client()


def get(client, path, host="127.0.0.1:8080"):
    return client.get(path, headers={"Host": host})


def test_overview_shows_the_counts(client):
    page = get(client, "/").get_data(as_text=True)
    assert "devices online" in page
    assert '<span class="value">2<small> / 2</small></span>' in page
    assert "1 critical" in page
    assert "audit findings" in page


def test_devices_page(client):
    page = get(client, "/devices").get_data(as_text=True)
    assert ROUTER in page and "Router" in page and "trusted" in page
    assert "(randomised MAC)" in page  # the phone


def test_timeline_and_audit_pages(client):
    timeline = get(client, "/timeline").get_data(as_text=True)
    assert "first_seen" in timeline and "critical" in timeline
    audit = get(client, "/audit").get_data(as_text=True)
    assert "Router admin page only over plain HTTP" in audit


@pytest.mark.parametrize("path", ["/", "/timeline", "/audit"])
def test_text_from_devices_is_escaped(client, path):
    # Banners and alert messages come from the network: they must never run as code.
    page = get(client, path).get_data(as_text=True)
    assert XSS not in page


def test_security_headers(client):
    headers = get(client, "/").headers
    assert headers["Content-Security-Policy"].startswith("default-src 'self'")
    assert headers["X-Frame-Options"] == "DENY"
    assert headers["X-Content-Type-Options"] == "nosniff"


@pytest.mark.parametrize("host", ["evil.example", "evil.example:8080", "192.168.1.50:8080"])
def test_foreign_host_header_is_refused(client, host):
    # DNS rebinding: a web page resolves its own name to 127.0.0.1 and reads the dashboard.
    assert get(client, "/api/devices", host=host).status_code == 403


@pytest.mark.parametrize("host", ["localhost:8080", "127.0.0.1", "[::1]:8080"])
def test_local_host_headers_are_accepted(client, host):
    assert get(client, "/", host=host).status_code == 200


def test_json_api(client):
    devices = get(client, "/api/devices").get_json()
    assert {d["mac"] for d in devices} == {ROUTER, PHONE}
    assert devices[0]["first_seen"].endswith("+00:00")  # ISO 8601, not an HTTP date
    alerts = get(client, "/api/alerts").get_json()
    assert alerts[0]["kind"] == "gateway_mac_changed"
    audit = get(client, "/api/audit").get_json()
    assert audit["findings"][0]["severity"] == "medium"
    timeline = get(client, "/api/timeline").get_json()
    assert timeline[0]["is_alert"] is True


def test_empty_database(tmp_path):
    client = create_app(tmp_path / "empty.db", tmp_path / "no-manuf").test_client()
    assert "No devices yet" in get(client, "/devices").get_data(as_text=True)
    assert "No audit yet" in get(client, "/audit").get_data(as_text=True)
    assert get(client, "/api/audit").get_json() is None


def test_alerts_today_ignores_old_alerts(db, tmp_path):
    with Store(db) as store:
        old = utcnow() - timedelta(days=3)
        store.add_alerts([Alert("new_device", "warning", "old one", old, "aa:aa:aa:aa:aa:99", "192.168.1.99")])
    page = get(create_app(db, tmp_path / "x").test_client(), "/").get_data(as_text=True)
    assert "alerts in the last 24 h, 1 critical" in page


def test_hostname_and_loopback_helpers():
    assert hostname("127.0.0.1:8080") == "127.0.0.1"
    assert hostname("[::1]:8080") == "[::1]"
    assert hostname("localhost") == "localhost"
    assert is_loopback("127.0.0.1") and is_loopback("::1") and is_loopback("localhost")
    assert not is_loopback("0.0.0.0") and not is_loopback("192.168.1.50")


def test_web_command_refuses_a_public_bind(tmp_path, capsys, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    assert cli.main(["web", "--host", "0.0.0.0"]) == 1
    assert "only runs on 127.0.0.1" in capsys.readouterr().err
