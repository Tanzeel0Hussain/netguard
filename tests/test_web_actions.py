import re

import pytest

pytest.importorskip("flask")

from netguard import actions  # noqa: E402
from netguard.audit.scanner import OpenPort  # noqa: E402
from netguard.config import Config  # noqa: E402
from netguard.discovery import ScanPermissionError  # noqa: E402
from netguard.engine import process_scan  # noqa: E402
from netguard.models import utcnow  # noqa: E402
from netguard.storage import Store  # noqa: E402
from netguard.web import create_app  # noqa: E402
from tests.conftest import obs  # noqa: E402

TV = "aa:aa:aa:aa:aa:30"
HOST = {"Host": "127.0.0.1:8080"}


@pytest.fixture
def config(tmp_path, monkeypatch):
    monkeypatch.setattr(actions, "find_names", lambda ips: {})
    cfg = Config(db_path=tmp_path / "netguard.db", oui_path=tmp_path / "no-manuf", network="192.168.1.0/24")
    with Store(cfg.db_path) as store:
        process_scan(store, [obs("192.168.1.30", TV, utcnow())], "arp-scan", "192.168.1.0/24", utcnow())
    return cfg


@pytest.fixture
def client(config):
    return create_app(config).test_client()


def token(client) -> str:
    page = client.get("/devices", headers=HOST).get_data(as_text=True)
    return re.search(r'name="csrf_token" value="([^"]+)"', page)[1]


def post(client, path, data=None, headers=None, with_token=True):
    form = dict(data or {})
    if with_token:
        form["csrf_token"] = token(client)
    return client.post(path, data=form, headers={**HOST, **(headers or {})})


def device(config, mac=TV):
    with Store(config.db_path) as store:
        return store.device(mac)


def test_trust_and_untrust_from_the_page(client, config):
    response = post(client, f"/devices/{TV}/trust", {"trusted": "1"})
    assert response.status_code == 302 and response.headers["Location"].endswith("/devices")
    assert device(config).trusted is True
    assert "marked as trusted" in client.get("/devices", headers=HOST).get_data(as_text=True)

    post(client, f"/devices/{TV}/trust", {"trusted": "0"})
    assert device(config).trusted is False


def test_name_a_device_and_clear_it(client, config):
    post(client, f"/devices/{TV}/label", {"label": "  Living room TV  "})
    assert device(config).label == "Living room TV"
    post(client, f"/devices/{TV}/label", {"label": "x" * 200})
    assert len(device(config).label) == 64
    post(client, f"/devices/{TV}/label", {"label": ""})
    assert device(config).label is None


def test_label_cannot_inject_html(client, config):
    post(client, f"/devices/{TV}/label", {"label": '"><script>alert(1)</script>'})
    page = client.get("/devices", headers=HOST).get_data(as_text=True)
    assert "<script>alert(1)</script>" not in page


def test_post_without_the_token_is_refused(client, config):
    # What a malicious page would send through your browser (CSRF).
    response = post(client, f"/devices/{TV}/trust", {"trusted": "1"}, with_token=False)
    assert response.status_code == 403
    response = post(client, f"/devices/{TV}/trust", {"trusted": "1", "csrf_token": "guess"}, with_token=False)
    assert response.status_code == 403
    assert device(config).trusted is False


def test_null_origin_is_refused_and_our_pages_do_not_cause_it(client, config):
    # Found in a real browser: "Referrer-Policy: no-referrer" made Chrome send
    # "Origin: null" on the dashboard's own forms, so every button gave 403.
    assert client.get("/", headers=HOST).headers["Referrer-Policy"] == "same-origin"
    # A sandboxed iframe on an attacker's page also sends "null": keep refusing it.
    assert post(client, f"/devices/{TV}/trust", {"trusted": "1"}, headers={"Origin": "null"}).status_code == 403


def test_post_from_another_origin_is_refused(client, config):
    response = post(client, f"/devices/{TV}/trust", {"trusted": "1"}, headers={"Origin": "https://evil.example"})
    assert response.status_code == 403
    ok = post(client, f"/devices/{TV}/trust", {"trusted": "1"}, headers={"Origin": "http://127.0.0.1:8080"})
    assert ok.status_code == 302


@pytest.mark.parametrize("mac", ["de:ad:be:ef:00:01", "not-a-mac"])
def test_unknown_or_bad_mac_is_404(client, mac):
    assert post(client, f"/devices/{mac}/trust", {"trusted": "1"}).status_code == 404


def test_scan_falls_back_to_the_arp_cache_without_root(client, config, monkeypatch):
    calls = []

    def fake_discover(network, iface=None, passive=False, timeout=2.0):
        calls.append(passive)
        if not passive:
            raise ScanPermissionError("needs root")
        return [obs("192.168.1.30", TV, utcnow()), obs("192.168.1.66", "de:ad:be:ef:00:66", utcnow())]

    monkeypatch.setattr(actions, "discover", fake_discover)
    response = post(client, "/scan")
    assert response.status_code == 302
    assert calls == [False, True]
    page = client.get("/", headers=HOST).get_data(as_text=True)
    assert "kernel ARP cache" in page and "1 new alert(s)" in page
    assert device(config, "de:ad:be:ef:00:66") is not None


def test_scan_error_is_shown_not_crashed(client, monkeypatch):
    def broken(*args, **kwargs):
        raise OSError("Network is down")

    monkeypatch.setattr(actions, "discover", broken)
    post(client, "/scan")
    assert "Scan failed: Network is down" in client.get("/", headers=HOST).get_data(as_text=True)


def test_run_audit_from_the_page(client, monkeypatch):
    async def fake_scan_hosts(ips, ports, timeout=1.0, concurrency=100):
        assert ips == ["192.168.1.30"]
        return [OpenPort("192.168.1.30", 23, "login:")]

    monkeypatch.setattr(actions, "scan_hosts", fake_scan_hosts)
    response = post(client, "/audit/run")
    assert response.headers["Location"].endswith("/audit")
    page = client.get("/audit", headers=HOST).get_data(as_text=True)
    assert "Audited 1 device(s): 1 high." in page
    assert "Telnet is open" in page


def test_read_only_mode_has_no_buttons_and_refuses_posts(config):
    client = create_app(config, read_only=True).test_client()
    page = client.get("/devices", headers=HOST).get_data(as_text=True)
    assert "<form" not in page and "read-only" in page
    response = client.post(f"/devices/{TV}/trust", data={"trusted": "1"}, headers=HOST)
    assert response.status_code == 403


def test_devices_page_does_not_auto_refresh(client):
    # It would wipe a name while you type it.
    assert 'http-equiv="refresh"' not in client.get("/devices", headers=HOST).get_data(as_text=True)
    assert 'http-equiv="refresh"' in client.get("/", headers=HOST).get_data(as_text=True)
