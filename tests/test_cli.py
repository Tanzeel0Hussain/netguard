import pytest

from netguard import cli
from tests.conftest import obs

PHONE = "aa:aa:aa:aa:aa:01"
STRANGER = "de:ad:be:ef:00:01"


@pytest.fixture
def run(tmp_path, monkeypatch, capsys):
    """Run `netguard` with a throwaway database and fake discovery results."""
    monkeypatch.setenv("HOME", str(tmp_path))  # never read the real config file
    db = tmp_path / "netguard.db"
    found = []
    monkeypatch.setattr(cli, "discover", lambda *a, **kw: list(found))
    monkeypatch.setattr(cli, "find_names", lambda ips: {})  # no real name lookups in tests

    def _run(*args):
        code = cli.main(["--db", str(db), *args])
        out, err = capsys.readouterr()
        return code, out, err

    _run.found = found
    return _run


def test_scan_then_list_trust_and_alerts(run):
    run.found[:] = [obs("192.168.1.10", PHONE)]
    code, out, _ = run("scan", "--network", "192.168.1.0/24")
    assert code == 0
    assert "Found 1 device(s)." in out
    assert "First scan" in out

    code, out, _ = run("trust", "AA-AA-AA-AA-AA-01", "--label", "My phone")
    assert code == 0
    assert f"{PHONE} marked as trusted." in out

    run.found[:] = [obs("192.168.1.10", PHONE), obs("192.168.1.66", STRANGER)]
    code, out, _ = run("scan", "--network", "192.168.1.0/24")
    assert f"[!] Unknown device joined: {STRANGER} at 192.168.1.66" in out
    assert "NEW" in out

    code, out, _ = run("devices", "--untrusted")
    assert STRANGER in out and PHONE not in out

    code, out, _ = run("alerts")
    assert "WARNING" in out and STRANGER in out


def test_label_and_vendor_column(run, tmp_path):
    manuf = tmp_path / ".local" / "share" / "netguard" / "manuf"
    manuf.parent.mkdir(parents=True)
    manuf.write_text("AA:AA:AA\tAcme\tAcme Devices Ltd\n")
    run.found[:] = [obs("192.168.1.10", PHONE), obs("192.168.1.73", "6e:11:22:33:44:73")]
    run("scan", "--network", "192.168.1.0/24")

    code, out, _ = run("label", PHONE, "Living room TV")
    assert code == 0

    code, out, _ = run("devices")
    phone_row = next(line for line in out.splitlines() if PHONE in line)
    assert "Acme Devices Ltd" in phone_row and "Living room TV" in phone_row
    assert "untrusted" in phone_row  # labelling does not trust a device
    assert "(randomised MAC)" in out
    assert "oui update" not in out

    code, out, _ = run("label", PHONE, "--clear")
    assert code == 0
    code, out, _ = run("oui", "lookup", "aa-aa-aa-00-00-01")
    assert out.startswith("aa:aa:aa:00:00:01  Acme Devices Ltd")


def test_label_needs_a_name_or_clear(run):
    code, _, err = run("label", PHONE)
    assert code == 1
    assert "NAME or --clear" in err


def test_vendor_hint_without_the_list(run):
    run.found[:] = [obs("192.168.1.10", PHONE)]
    _, out, _ = run("scan", "--network", "192.168.1.0/24")
    assert "netguard oui update" in out


def test_monitor_single_scan_and_timeline(run, tmp_path):
    run.found[:] = [obs("192.168.1.10", PHONE)]
    code, out, _ = run("monitor", "--network", "192.168.1.0/24", "--count", "1", "--interval", "60")
    assert code == 0
    assert "scan #1: 1 seen, 1 online, 0 new alert(s)" in out
    assert "Stopped after 1 scan(s), 0 failed." in out

    run.found[:] = [obs("192.168.1.10", PHONE), obs("192.168.1.66", STRANGER)]
    run("scan", "--network", "192.168.1.0/24")

    code, out, _ = run("timeline")
    assert code == 0
    lines = out.splitlines()
    assert "WARNING" in lines[2] and STRANGER in lines[2]  # newest first
    assert any("first_seen" in line and PHONE in line for line in lines)

    code, out, _ = run("timeline", "--mac", PHONE)
    assert STRANGER not in out

    log = tmp_path / ".local" / "share" / "netguard" / "events.jsonl"
    assert '"kind": "new_device"' in log.read_text()


def test_monitor_refuses_a_tiny_interval(run):
    code, _, err = run("monitor", "--network", "192.168.1.0/24", "--interval", "1")
    assert code == 1
    assert "at least 10 seconds" in err


def test_alert_command_must_be_a_list(run, tmp_path):
    config = tmp_path / "bad.toml"
    config.write_text('[alerts]\ncommand = "notify-send"\n')
    code, _, err = run("--config", str(config), "alerts")
    assert code == 1
    assert "must be a list of strings" in err


def test_scan_refuses_a_public_network(run):
    code, _, err = run("scan", "--network", "8.8.8.0/24")
    assert code == 1
    assert "not a private network" in err


def test_trust_unknown_mac_fails(run):
    code, _, err = run("trust", STRANGER)
    assert code == 1
    assert "not in the inventory" in err


def test_invalid_mac_is_reported(run):
    code, _, err = run("trust", "not-a-mac")
    assert code == 1
    assert "not a valid MAC" in err
